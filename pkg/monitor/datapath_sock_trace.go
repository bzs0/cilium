package monitor

import "github.com/cilium/cilium/pkg/types"

// Socket trace event point with respect to service translation
const (
	XlatePointPreDirectionFwd = iota
	XlatePointPostDirectionFwd
	XlatePointPreDirectionRev
	XlatePointPostDirectionRev
)

// L4 protocol for socket trace event
const (
	L4ProtocolUnknown = iota
	L4ProtocolTCP
	L4ProtocolUDP
)

// SockTraceNotify is message format for socket trace notifications from datapath.
type SockTraceNotify struct {
	Type       uint8
	XlatePoint uint8
	L4Proto    uint8
	DstIP      types.IPv6
	DstPort    uint16
	CgroupId   uint64
	SockCookie uint64
	Flags      uint8
}
