// Package main
package main

import (
	_ "github.com/Mrs4s/go-cqhttp/db/leveldb"   // leveldb 数据库支持
	_ "github.com/Mrs4s/go-cqhttp/modules/silk" // silk编码模块

	"github.com/Mrs4s/go-cqhttp/cmd/gocq"
	"github.com/Mrs4s/go-cqhttp/global/terminal"
)

func main() {
	terminal.SetTitle()
	gocq.InitBase()
	gocq.PrepareData()
	gocq.LoginInteract()
	_ = terminal.DisableQuickEdit()
	_ = terminal.EnableVT100()
	gocq.WaitSignal()
	_ = terminal.RestoreInputMode()
}
