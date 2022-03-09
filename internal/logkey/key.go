package logkey

const (
	// MsgField and the following fields are names for structured log in gensign.
	MsgField        = "msg"
	ErrField        = "err"
	TransIDField    = "id"
	HandlerField    = "handler"
	TimeElapseField = "elapsed"

	// PrinsField and the following fields are names for structured log in handlers.
	PrinsField = "prins"
	KeyidField = "keyid"
)
