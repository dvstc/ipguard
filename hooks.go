package ipguard

// BlockEvent is emitted when a connection or request is blocked.
type BlockEvent struct {
	IP        string
	Reason    string // one of the Reason* constants
	Transport string
	Country   string // from current geo data, "" if unavailable
}

// BanEvent is emitted when an IP is auto-banned after exceeding the failure threshold.
type BanEvent struct {
	IP        string
	Transport string
	Failures  int
	BanCount  int    // total times this IP has been banned (including this one)
	Country   string // from current geo data, "" if unavailable
}

// UnbanEvent is emitted when a ban is removed, either by expiry or manual action.
type UnbanEvent struct {
	IP     string
	Reason string // "expired" or "manual"
}

// PermaBanEvent is emitted when an IP is promoted to a permanent ban,
// either by recidivist auto-escalation or manual PermaBan() call.
type PermaBanEvent struct {
	IP        string
	Transport string // empty for manual PermaBan()
	BanCount  int
	Country   string
}

// Hooks provides optional callbacks for guard events. Set any function
// field to receive notifications; nil fields are silently skipped.
type Hooks struct {
	OnBlocked     func(BlockEvent)
	OnBanned      func(BanEvent)
	OnUnbanned    func(UnbanEvent)
	OnPermaBanned func(PermaBanEvent)
	OnWarning     func(message string, data map[string]string)
}
