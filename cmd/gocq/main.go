// Package gocq 程序的主体部分
package gocq

import (
	"crypto/aes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/LagrangeDev/LagrangeGo/client"
	"github.com/LagrangeDev/LagrangeGo/client/auth"
	"github.com/LagrangeDev/LagrangeGo/client/packets/pb/action"
	"github.com/LagrangeDev/LagrangeGo/utils"
	"github.com/LagrangeDev/LagrangeGo/utils/crypto"
	para "github.com/fumiama/go-hide-param"
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"

	"github.com/Mrs4s/go-cqhttp/coolq"
	"github.com/Mrs4s/go-cqhttp/db"
	"github.com/Mrs4s/go-cqhttp/global"
	"github.com/Mrs4s/go-cqhttp/global/terminal"
	"github.com/Mrs4s/go-cqhttp/internal/base"
	"github.com/Mrs4s/go-cqhttp/internal/cache"
	"github.com/Mrs4s/go-cqhttp/internal/download"
	"github.com/Mrs4s/go-cqhttp/internal/selfdiagnosis"
	"github.com/Mrs4s/go-cqhttp/internal/selfupdate"
	"github.com/Mrs4s/go-cqhttp/modules/servers"
	"github.com/Mrs4s/go-cqhttp/server"
)

// InitBase 解析参数并检测
//
//	如果在 windows 下双击打开了程序，程序将在此函数释出脚本后终止；
//	如果传入 -h 参数，程序将打印帮助后终止；
//	如果传入 -d 参数，程序将在启动 daemon 后终止。
func InitBase() {
	base.Parse()
	if !base.FastStart && terminal.RunningByDoubleClick() {
		err := terminal.NoMoreDoubleClick()
		if err != nil {
			log.Errorf("遇到错误: %v", err)
			time.Sleep(time.Second * 5)
		}
		os.Exit(0)
	}
	switch {
	case base.LittleH:
		base.Help()
	case base.LittleD:
		server.Daemon()
	}
	if base.LittleWD != "" {
		err := os.Chdir(base.LittleWD)
		if err != nil {
			log.Fatalf("重置工作目录时出现错误: %v", err)
		}
	}
	base.Init()
}

// PrepareData 准备 log, 缓存, 数据库, 必须在 InitBase 之后执行
func PrepareData() {
	rotateOptions := []rotatelogs.Option{
		rotatelogs.WithRotationTime(time.Hour * 24),
	}
	rotateOptions = append(rotateOptions, rotatelogs.WithMaxAge(base.LogAging))
	if base.LogForceNew {
		rotateOptions = append(rotateOptions, rotatelogs.ForceNewFile())
	}
	w, err := rotatelogs.New(path.Join("logs", "%Y-%m-%d.log"), rotateOptions...)
	if err != nil {
		log.Errorf("rotatelogs init err: %v", err)
		panic(err)
	}

	consoleFormatter := global.LogFormat{EnableColor: base.LogColorful}
	fileFormatter := global.LogFormat{EnableColor: false}
	log.AddHook(global.NewLocalHook(w, consoleFormatter, fileFormatter, global.GetLogLevel(base.LogLevel)...))

	mkCacheDir := func(path string, _type string) {
		if !global.PathExists(path) {
			if err := os.MkdirAll(path, 0o755); err != nil {
				log.Fatalf("创建%s缓存文件夹失败: %v", _type, err)
			}
		}
	}
	mkCacheDir(global.ImagePath, "图片")
	mkCacheDir(global.VoicePath, "语音")
	mkCacheDir(global.VideoPath, "视频")
	mkCacheDir(global.CachePath, "发送图片")
	mkCacheDir(global.VersionsPath, "版本缓存")
	cache.Init()

	db.Init()
	if err := db.Open(); err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
}

// LoginInteract 登录交互, 可能需要键盘输入, 必须在 InitBase, PrepareData 之后执行
func LoginInteract() {
	var byteKey []byte
	arg := os.Args
	if len(arg) > 1 {
		for i := range arg {
			switch arg[i] {
			case "update":
				if len(arg) > i+1 {
					selfupdate.SelfUpdate(arg[i+1])
				} else {
					selfupdate.SelfUpdate("")
				}
			case "key":
				p := i + 1
				if len(arg) > p {
					byteKey = []byte(arg[p])
					para.Hide(p)
				}
			}
		}
	}

	if (base.Account.Uin == 0 || (base.Account.Password == "" && !base.Account.Encrypt)) && !global.PathExists("session.token") {
		log.Warn("账号密码未配置, 将使用二维码登录.")
		if !base.FastStart {
			log.Warn("将在 5秒 后继续.")
			time.Sleep(time.Second * 5)
		}
	}

	log.Info("当前版本:", base.Version)
	if base.Debug {
		log.SetLevel(log.DebugLevel)
		log.Warnf("已开启Debug模式.")
	}
	if !global.FileExists("device.json") {
		log.Warn("虚拟设备信息不存在, 将自动生成随机设备.")
		device = auth.NewDeviceInfo(int(crypto.RandU32()))
		_ = device.Save("device.json")
		log.Info("已生成设备信息并保存到 device.json 文件.")
	} else {
		log.Info("将使用 device.json 内的设备信息运行Bot.")
		var err error
		if device, err = auth.LoadOrSaveDevice("device.json"); err != nil {
			log.Fatalf("加载设备信息失败: %v", err)
		}
	}

	if base.Account.Encrypt {
		if !global.PathExists("password.encrypt") {
			if base.Account.Password == "" {
				log.Error("无法进行加密，请在配置文件中的添加密码后重新启动.")
			} else {
				log.Infof("密码加密已启用, 请输入Key对密码进行加密: (Enter 提交)")
				byteKey, _ = term.ReadPassword(int(os.Stdin.Fd()))
				base.PasswordHash = md5.Sum([]byte(base.Account.Password))
				_ = os.WriteFile("password.encrypt", []byte(PasswordHashEncrypt(base.PasswordHash[:], byteKey)), 0o644)
				log.Info("密码已加密，为了您的账号安全，请删除配置文件中的密码后重新启动.")
			}
			readLine()
			os.Exit(0)
		}
		if base.Account.Password != "" {
			log.Error("密码已加密，为了您的账号安全，请删除配置文件中的密码后重新启动.")
			readLine()
			os.Exit(0)
		}
		if len(byteKey) == 0 {
			log.Infof("密码加密已启用, 请输入Key对密码进行解密以继续: (Enter 提交)")
			cancel := make(chan struct{}, 1)
			state, _ := term.GetState(int(os.Stdin.Fd()))
			go func() {
				select {
				case <-cancel:
					return
				case <-time.After(time.Second * 45):
					log.Infof("解密key输入超时")
					time.Sleep(3 * time.Second)
					_ = term.Restore(int(os.Stdin.Fd()), state)
					os.Exit(0)
				}
			}()
			byteKey, _ = term.ReadPassword(int(os.Stdin.Fd()))
			cancel <- struct{}{}
		} else {
			log.Infof("密码加密已启用, 使用运行时传递的参数进行解密，按 Ctrl+C 取消.")
		}

		encrypt, _ := os.ReadFile("password.encrypt")
		ph, err := PasswordHashDecrypt(string(encrypt), byteKey)
		if err != nil {
			log.Fatalf("加密存储的密码损坏，请尝试重新配置密码")
		}
		copy(base.PasswordHash[:], ph)
	} else if len(base.Account.Password) > 0 {
		base.PasswordHash = md5.Sum([]byte(base.Account.Password))
	}

	if !base.FastStart {
		log.Info("Bot将在5秒后登录并开始信息处理, 按 Ctrl+C 取消.")
		time.Sleep(time.Second * 5)
	}
	log.Info("开始尝试登录并同步消息...")
	app := auth.AppList["linux"]["3.2.15-30366"]
	log.Infof("使用协议: %s", app.CurrentVersion)
	cli = newClient(app)
	cli.UseDevice(device)
	isQRCodeLogin := (base.Account.Uin == 0 || len(base.Account.Password) == 0) && !base.Account.Encrypt
	isTokenLogin := false

	// 加载本地版本信息, 一般是在上次登录时保存的
	versionFile := path.Join(global.VersionsPath, "7.json")
	if global.FileExists(versionFile) {
		b, err := os.ReadFile(versionFile)
		if err != nil {
			log.Warnf("从文件 %s 读取本地版本信息文件出错.", versionFile)
			os.Exit(0)
		}
		info, err := JsParse(b)
		if err != nil {
			log.Warnf("从文件 %s 解析本地版本信息出错: %v", versionFile, err)
			os.Exit(0)
		}
		cli.UseVersion(info)
		log.Infof("从文件 %s 读取协议版本 %s.", versionFile, cli.Version().CurrentVersion)
	}

	saveToken := func() {
		base.AccountToken, _ = cli.Sig().Marshal()
		_ = os.WriteFile("session.token", base.AccountToken, 0o644)
	}
	if global.FileExists("session.token") {
		token, _ := os.ReadFile("session.token")
		sig, err := auth.UnmarshalSigInfo(token, true)
		if err == nil {
			if base.Account.Uin != 0 && int64(sig.Uin) != base.Account.Uin {
				log.Warnf("警告: 配置文件内的QQ号 (%v) 与缓存内的QQ号 (%v) 不相同", base.Account.Uin, int64(sig.Uin))
				log.Warnf("1. 使用会话缓存继续.")
				log.Warnf("2. 删除会话缓存并重启.")
				log.Warnf("请选择:")
				text := readIfTTY("1")
				if text == "2" {
					_ = os.Remove("session.token")
					log.Infof("缓存已删除.")
					os.Exit(0)
				}
			}
			cli.UseSig(sig)
			if err = cli.FastLogin(); err != nil {
				_ = os.Remove("session.token")
				log.Warnf("恢复会话失败: %v , 尝试使用正常流程登录.", err)
				time.Sleep(time.Second)
				cli.Disconnect()
				cli.Release()
				cli = newClient(app)
				cli.UseDevice(device)
			} else {
				isTokenLogin = true
			}
		}
	}
	if base.Account.Uin != 0 && base.PasswordHash != [16]byte{} {
		cli.Uin = uint32(base.Account.Uin)
		cli.PasswordMD5 = base.PasswordHash
	}
	if !base.FastStart {
		log.Infof("正在检查协议更新...")
		currentVersionName := cli.Version().CurrentVersion
		remoteVersion, err := getRemoteLatestProtocolVersion(7)
		if err == nil {
			remoteVersionName := gjson.GetBytes(remoteVersion, "current_version").String()
			if remoteVersionName != currentVersionName {
				switch {
				case !base.UpdateProtocol:
					log.Infof("检测到协议更新: %s -> %s", currentVersionName, remoteVersionName)
					log.Infof("如果登录时出现版本过低错误, 可尝试使用 -update-protocol 参数启动")
				case !isTokenLogin:
					info, _ := auth.UnmarshalAppInfo(remoteVersion)
					cli.UseVersion(info)
					err := os.WriteFile(versionFile, remoteVersion, 0644)
					log.Infof("协议版本已更新: %s -> %s", currentVersionName, remoteVersionName)
					if err != nil {
						log.Warnln("更新协议版本缓存文件", versionFile, "失败:", err)
					}
				default:
					log.Infof("检测到协议更新: %s -> %s", currentVersionName, remoteVersionName)
					log.Infof("由于使用了会话缓存, 无法自动更新协议, 请删除缓存后重试")
				}
			}
		} else if err.Error() != "remote version unavailable" {
			log.Warnf("检查协议更新失败: %v", err)
		}
	}
	if !isTokenLogin {
		if !isQRCodeLogin {
			if err := commonLogin(); err != nil {
				log.Fatalf("登录时发生致命错误: %v", err)
			}
		} else {
			if err := qrcodeLogin(); err != nil {
				log.Fatalf("登录时发生致命错误: %v", err)
			}
		}
	}
	var times uint = 1 // 重试次数
	var reLoginLock sync.Mutex
	cli.DisconnectedEvent.Subscribe(func(_ *client.QQClient, e *client.DisconnectedEvent) {
		reLoginLock.Lock()
		defer reLoginLock.Unlock()
		times = 1
		if cli.Online.Load() {
			return
		}
		log.Warnf("Bot已离线: %v", e.Message)
		time.Sleep(time.Second * time.Duration(base.Reconnect.Delay))
		for {
			if base.Reconnect.Disabled {
				log.Warnf("未启用自动重连, 将退出.")
				os.Exit(1)
			}
			if times > base.Reconnect.MaxTimes && base.Reconnect.MaxTimes != 0 {
				log.Fatalf("Bot重连次数超过限制, 停止")
			}
			times++
			if base.Reconnect.Interval > 0 {
				log.Warnf("将在 %v 秒后尝试重连. 重连次数：%v/%v", base.Reconnect.Interval, times, base.Reconnect.MaxTimes)
				time.Sleep(time.Second * time.Duration(base.Reconnect.Interval))
			} else {
				time.Sleep(time.Second)
			}
			if cli.Online.Load() {
				log.Infof("登录已完成")
				break
			}
			log.Warnf("尝试重连...")
			err := cli.FastLogin()
			if err == nil {
				saveToken()
				return
			}
			log.Warnf("快速重连失败: %v", err)
			if isQRCodeLogin {
				log.Fatalf("快速重连失败, 扫码登录无法恢复会话.")
			}
			log.Warnf("快速重连失败, 尝试普通登录. 这可能是因为其他端强行T下线导致的.")
			time.Sleep(time.Second)
			if err := qrcodeLogin(); err != nil {
				log.Errorf("登录时发生致命错误: %v", err)
			} else {
				saveToken()
				break
			}
		}
	})
	saveToken()
	// cli.AllowSlider = true
	log.Infof("登录成功 欢迎使用: %v", cli.NickName())
	log.Info("开始加载好友列表...")
	global.Check(cli.RefreshFriendCache(), true)
	friendListLen := len(cli.GetCachedAllFriendsInfo())
	log.Infof("共加载 %v 个好友.", friendListLen)
	log.Infof("开始加载群列表...")
	global.Check(cli.RefreshAllGroupsInfo(), true)
	GroupListLen := len(cli.GetCachedAllGroupsInfo())
	log.Infof("共加载 %v 个群.", GroupListLen)
	if uint(base.Account.Status) >= 3000 {
		base.Account.Status = 10
	}
	_ = cli.SetOnlineStatus(utils.Ternary(base.Account.Status >= 1000, action.SetStatus{
		Status:    10,
		ExtStatus: uint32(base.Account.Status),
	}, action.SetStatus{Status: uint32(base.Account.Status)}))
	servers.Run(coolq.NewQQBot(cli))
	log.Info("资源初始化完成, 开始处理信息.")
	log.Info("アトリは、高性能ですから!")
}

// WaitSignal 在新线程检查更新和网络并等待信号, 必须在 InitBase, PrepareData, LoginInteract 之后执行
//
//   - 直接返回: os.Interrupt, syscall.SIGTERM
//   - dump stack: syscall.SIGQUIT, syscall.SIGUSR1
func WaitSignal() {
	go func() {
		selfupdate.CheckUpdate()
		selfdiagnosis.NetworkDiagnosis(cli)
	}()

	<-global.SetupMainSignalHandler()
}

// PasswordHashEncrypt 使用key加密给定passwordHash
func PasswordHashEncrypt(passwordHash []byte, key []byte) string {
	if len(passwordHash) != 16 {
		panic("密码加密参数错误")
	}

	key = pbkdf2.Key(key, key, 114514, 32, sha1.New)

	cipher, _ := aes.NewCipher(key)
	result := make([]byte, 16)
	cipher.Encrypt(result, passwordHash)

	return hex.EncodeToString(result)
}

// PasswordHashDecrypt 使用key解密给定passwordHash
func PasswordHashDecrypt(encryptedPasswordHash string, key []byte) ([]byte, error) {
	ciphertext, err := hex.DecodeString(encryptedPasswordHash)
	if err != nil {
		return nil, err
	}

	key = pbkdf2.Key(key, key, 114514, 32, sha1.New)

	cipher, _ := aes.NewCipher(key)
	result := make([]byte, 16)
	cipher.Decrypt(result, ciphertext)

	return result, nil
}

func newClient(app *auth.AppInfo) *client.QQClient {
	signUrls := make([]string, 0, len(base.SignServers))
	defaultSignURL := "https://lwxmagic.sealdice.com/api/sign"
	for _, s := range base.SignServers {
		if strings.Contains(s.URL, defaultSignURL) {
			s.URL = strings.ReplaceAll(s.URL, defaultSignURL, "$(SIGN_SERVER_DEFAULT)")
		}
		u, err := url.Parse(s.URL)
		if err != nil || u.Hostname() == "" {
			continue
		}
		signUrls = append(signUrls, u.String())
	}
	c := client.NewClientEmpty()
	c.UseVersion(app)
	signer := newSigner()
	c.UseSignProvider(signer)
	c.AddSignServer(signUrls...)
	signer.init()
	// TODO 服务器更新通知
	// c.OnServerUpdated(func(bot *client.QQClient, e *client.ServerUpdatedEvent) bool {
	//	if !base.UseSSOAddress {
	//		log.Infof("收到服务器地址更新通知, 根据配置文件已忽略.")
	//		return false
	//	}
	//	log.Infof("收到服务器地址更新通知, 将在下一次重连时应用. ")
	//	return true
	// })
	if global.FileExists("address.txt") {
		log.Infof("检测到 address.txt 文件. 将覆盖目标IP.")
		addr := global.ReadAddrFile("address.txt")
		if len(addr) > 0 {
			c.SetCustomServer(addr)
		}
		log.Infof("读取到 %v 个自定义地址.", len(addr))
	}
	c.SetLogger(protocolLogger{})
	return c
}

var remoteVersions = map[int]string{
	1: "https://raw.githubusercontent.com/RomiChan/protocol-versions/master/android_phone.json",
	6: "https://raw.githubusercontent.com/RomiChan/protocol-versions/master/android_pad.json",
	7: "https://raw.githubusercontent.com/LagrangeDev/protocol-versions/refs/heads/master/LagrangeGo/latest.json",
}

func getRemoteLatestProtocolVersion(protocolType int) ([]byte, error) {
	url, ok := remoteVersions[protocolType]
	if !ok {
		return nil, errors.New("remote version unavailable")
	}
	response, err := download.Request{URL: url}.Bytes()
	if err != nil {
		return download.Request{URL: "https://www.ghproxy.cn/" + url}.Bytes()
	}
	return response, nil
}

type protocolLogger struct{}

const fromProtocol = "Protocol -> "

func (p protocolLogger) Info(format string, arg ...any) {
	log.Infof(fromProtocol+format, arg...)
}

func (p protocolLogger) Warning(format string, arg ...any) {
	log.Warnf(fromProtocol+format, arg...)
}

func (p protocolLogger) Debug(format string, arg ...any) {
	log.Debugf(fromProtocol+format, arg...)
}

func (p protocolLogger) Error(format string, arg ...any) {
	log.Errorf(fromProtocol+format, arg...)
}

func (p protocolLogger) Dump(data []byte, format string, arg ...any) {
	if !global.PathExists(global.DumpsPath) {
		_ = os.MkdirAll(global.DumpsPath, 0o755)
	}
	dumpFile := path.Join(global.DumpsPath, fmt.Sprintf("%v.dump", time.Now().Unix()))
	message := fmt.Sprintf(format, arg...)
	log.Errorf("出现错误 %v. 详细信息已转储至文件 %v 请连同日志提交给开发者处理", message, dumpFile)
	_ = os.WriteFile(dumpFile, data, 0o644)
}

// JsParse 兼容lgrOnebot的转换函数
func JsParse(js []byte) (*auth.AppInfo, error) {
	trans := struct {
		OS       string `json:"Os"`
		Kernel   string `json:"Kernel"`
		VendorOS string `json:"VendorOs"`

		CurrentVersion   string `json:"CurrentVersion"`
		BuildVersion     int    `json:"BuildVersion"`
		MiscBitmap       int    `json:"MiscBitmap"`
		PTVersion        string `json:"PtVersion"`
		PTOSVersion      int    `json:"SsoVersion"`
		PackageName      string `json:"PackageName"`
		WTLoginSDK       string `json:"WtLoginSdk"`
		PackageSign      string `json:"PackageSign"`
		AppID            int    `json:"AppId"`
		SubAppID         int    `json:"SubAppId"`
		AppIDQrcode      int    `json:"AppIdQrCode"`
		AppClientVersion int    `json:"AppClientVersion"`
		MainSigmap       int    `json:"MainSigMap"`
		SubSigmap        int    `json:"SubSigMap"`
		NTLoginType      int    `json:"NTLoginType"`

		SignExtraHexLower string `json:"-"`
		SignExtraHexUpper string `json:"-"`
	}{}
	err := json.Unmarshal(js, &trans)
	if err != nil {
		return nil, err
	}
	return &auth.AppInfo{
		OS:                trans.OS,
		Kernel:            trans.Kernel,
		VendorOS:          trans.VendorOS,
		CurrentVersion:    trans.CurrentVersion,
		BuildVersion:      trans.BuildVersion,
		MiscBitmap:        trans.MiscBitmap,
		PTVersion:         trans.PTVersion,
		PTOSVersion:       trans.PTOSVersion,
		PackageName:       trans.PackageName,
		WTLoginSDK:        trans.WTLoginSDK,
		PackageSign:       trans.PackageSign,
		AppID:             trans.AppID,
		SubAppID:          trans.SubAppID,
		AppIDQrcode:       trans.AppIDQrcode,
		AppClientVersion:  trans.AppClientVersion,
		MainSigmap:        trans.MainSigmap,
		SubSigmap:         trans.SubSigmap,
		NTLoginType:       trans.NTLoginType,
		SignExtraHexLower: trans.SignExtraHexLower,
		SignExtraHexUpper: trans.SignExtraHexUpper,
	}, nil
}
