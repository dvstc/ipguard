package tgeo

import (
	"encoding/binary"
	"net/netip"
)

// IPRange represents a contiguous IPv4 address range mapped to a country.
type IPRange struct {
	Start   netip.Addr
	End     netip.Addr
	Country string // ISO 3166-1 alpha-2, or "ZZ" for unknown/unallocated
}

// AddrInc increments an IPv4 address by 1. Returns the incremented address and
// true if successful, or a zero address and false on overflow (255.255.255.255 + 1).
func AddrInc(addr netip.Addr) (netip.Addr, bool) {
	b := addr.As4()
	v := binary.BigEndian.Uint32(b[:])
	if v == ^uint32(0) {
		return netip.Addr{}, false
	}
	v++
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b), true
}

// AddrToUint32 converts an IPv4 netip.Addr to a uint32 in network byte order.
func AddrToUint32(addr netip.Addr) uint32 {
	b := addr.As4()
	return binary.BigEndian.Uint32(b[:])
}

// Uint32ToAddr converts a uint32 in network byte order to an IPv4 netip.Addr.
func Uint32ToAddr(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}
