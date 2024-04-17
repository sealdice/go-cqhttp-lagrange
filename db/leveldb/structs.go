package leveldb

import "github.com/Mrs4s/go-cqhttp/db"

func (w *writer) writeStoredGroupMessage(x *db.StoredGroupMessage) {
	if x == nil {
		w.nil()
		return
	}
	w.coder(coderStruct)
	w.string(x.ID)
	w.int32(x.GlobalID)
	w.writeStoredMessageAttribute(x.Attribute)
	w.string(x.SubType)
	w.writeQuotedInfo(x.QuotedInfo)
	w.int64(x.GroupCode)
	w.string(x.AnonymousID)
	w.arrayMsg(x.Content)
}

func (r *reader) readStoredGroupMessage() *db.StoredGroupMessage {
	coder := r.coder()
	if coder == coderNil {
		return nil
	}
	x := &db.StoredGroupMessage{}
	x.ID = r.string()
	x.GlobalID = r.int32()
	x.Attribute = r.readStoredMessageAttribute()
	x.SubType = r.string()
	x.QuotedInfo = r.readQuotedInfo()
	x.GroupCode = r.int64()
	x.AnonymousID = r.string()
	x.Content = r.arrayMsg()
	return x
}

func (w *writer) writeStoredPrivateMessage(x *db.StoredPrivateMessage) {
	if x == nil {
		w.nil()
		return
	}
	w.coder(coderStruct)
	w.string(x.ID)
	w.int32(x.GlobalID)
	w.writeStoredMessageAttribute(x.Attribute)
	w.string(x.SubType)
	w.writeQuotedInfo(x.QuotedInfo)
	w.int64(x.SessionUin)
	w.int64(x.TargetUin)
	w.arrayMsg(x.Content)
}

func (r *reader) readStoredPrivateMessage() *db.StoredPrivateMessage {
	coder := r.coder()
	if coder == coderNil {
		return nil
	}
	x := &db.StoredPrivateMessage{}
	x.ID = r.string()
	x.GlobalID = r.int32()
	x.Attribute = r.readStoredMessageAttribute()
	x.SubType = r.string()
	x.QuotedInfo = r.readQuotedInfo()
	x.SessionUin = r.int64()
	x.TargetUin = r.int64()
	x.Content = r.arrayMsg()
	return x
}

func (w *writer) writeStoredMessageAttribute(x *db.StoredMessageAttribute) {
	if x == nil {
		w.nil()
		return
	}
	w.coder(coderStruct)
	w.int32(x.MessageSeq)
	w.int32(x.InternalID)
	w.int64(x.SenderUin)
	w.string(x.SenderName)
	w.int64(x.Timestamp)
}

func (r *reader) readStoredMessageAttribute() *db.StoredMessageAttribute {
	coder := r.coder()
	if coder == coderNil {
		return nil
	}
	x := &db.StoredMessageAttribute{}
	x.MessageSeq = r.int32()
	x.InternalID = r.int32()
	x.SenderUin = r.int64()
	x.SenderName = r.string()
	x.Timestamp = r.int64()
	return x
}

func (w *writer) writeQuotedInfo(x *db.QuotedInfo) {
	if x == nil {
		w.nil()
		return
	}
	w.coder(coderStruct)
	w.string(x.PrevID)
	w.int32(x.PrevGlobalID)
	w.arrayMsg(x.QuotedContent)
}

func (r *reader) readQuotedInfo() *db.QuotedInfo {
	coder := r.coder()
	if coder == coderNil {
		return nil
	}
	x := &db.QuotedInfo{}
	x.PrevID = r.string()
	x.PrevGlobalID = r.int32()
	x.QuotedContent = r.arrayMsg()
	return x
}
