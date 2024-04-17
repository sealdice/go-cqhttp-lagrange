package coolq

import (
	"github.com/LagrangeDev/LagrangeGo/message"
	"strconv"
	"strings"

	"github.com/LagrangeDev/LagrangeGo/client"
	log "github.com/sirupsen/logrus"

	"github.com/Mrs4s/go-cqhttp/global"
)

func convertGroupMemberInfo(groupID int64, m *client.GroupMemberInfo) global.MSG {
	sex := "unknown"
	if m.Gender == 1 { // unknown = 0xff
		sex = "female"
	} else if m.Gender == 0 {
		sex = "male"
	}
	role := "member"
	switch m.Permission { // nolint:exhaustive
	case client.Owner:
		role = "owner"
	case client.Administrator:
		role = "admin"
	}
	return global.MSG{
		"group_id":          groupID,
		"user_id":           m.Uin,
		"nickname":          m.Nickname,
		"card":              m.CardName,
		"sex":               sex,
		"age":               0,
		"area":              "",
		"join_time":         m.JoinTime,
		"last_sent_time":    m.LastSpeakTime,
		"shut_up_timestamp": m.ShutUpTimestamp,
		"level":             strconv.FormatInt(int64(m.Level), 10),
		"role":              role,
		"unfriendly":        false,
		"title":             m.SpecialTitle,
		"title_expire_time": 0,
		"card_changeable":   false,
	}
}

func (bot *CQBot) formatGroupMessage(m *message.GroupMessage) *event {
	source := message.Source{
		SourceType: message.SourceGroup,
		PrimaryID:  m.GroupCode,
	}
	cqm := toStringMessage(m.Elements, source)
	typ := "message/group/normal"
	if m.Sender.Uin == bot.Client.Uin {
		typ = "message_sent/group/normal"
	}
	gm := global.MSG{
		"anonymous":   nil,
		"font":        0,
		"group_id":    m.GroupCode,
		"message":     ToFormattedMessage(m.Elements, source),
		"message_seq": m.Id,
		"raw_message": cqm,
		"sender": global.MSG{
			"age":     0,
			"area":    "",
			"level":   "",
			"sex":     "unknown",
			"user_id": m.Sender.Uin,
		},
		"user_id": m.Sender.Uin,
	}
	if m.Sender.IsAnonymous() {
		gm["anonymous"] = global.MSG{
			"flag": m.Sender.AnonymousInfo.AnonymousId + "|" + m.Sender.AnonymousInfo.AnonymousNick,
			"id":   m.Sender.Uin,
			"name": m.Sender.AnonymousInfo.AnonymousNick,
		}
		gm["sender"].(global.MSG)["nickname"] = "匿名消息"
		typ = "message/group/anonymous"
	} else {
		group := bot.Client.FindGroup(m.GroupCode)
		mem := group.FindMember(m.Sender.Uin)
		if mem == nil {
			log.Warnf("获取 %v 成员信息失败，尝试刷新成员列表", m.Sender.Uin)
			t, err := bot.Client.GetGroupMembers(group)
			if err != nil {
				log.Warnf("刷新群 %v 成员列表失败: %v", group.Uin, err)
				return nil
			}
			group.Members = t
			mem = group.FindMember(m.Sender.Uin)
			if mem == nil {
				return nil
			}
		}
		ms := gm["sender"].(global.MSG)
		role := "member"
		switch mem.Permission { // nolint:exhaustive
		case client.Owner:
			role = "owner"
		case client.Administrator:
			role = "admin"
		}
		ms["role"] = role
		ms["nickname"] = mem.Nickname
		ms["card"] = mem.CardName
		ms["title"] = mem.SpecialTitle
	}
	ev := bot.event(typ, gm)
	ev.Time = int64(m.Time)
	return ev
}

func toStringMessage(m []message.IMessageElement, source message.Source) string {
	elems := toElements(m, source)
	var sb strings.Builder
	for _, elem := range elems {
		elem.WriteCQCodeTo(&sb)
	}
	return sb.String()
}

func fU64(v uint64) string {
	return strconv.FormatUint(v, 10)
}
