package traceroute

import (
	"bytes"
	"encoding/binary"
	"math"
	"net"
	"syscall"

	"golang.org/x/net/ipv4"
)

type udpHeader struct {
	SourcePort uint16
	DestPort   uint16
	Length     uint16
	Checksum   uint16
}

func newUDPPacket(dst net.IP, srcPort, dstPort int, ttl, id int, payload []byte) []byte {
	ipHeader := ipv4.Header{
		Version:  ipv4.Version,          // protocol version
		Len:      ipv4.HeaderLen,        // header length
		TotalLen: 20 + 8 + len(payload), // packet total length: 20 IP, 8 UDP
		ID:       id % math.MaxUint16,   // identification
		TTL:      ttl,                   // time-to-live
		Protocol: syscall.IPPROTO_UDP,   // next protocol
		Dst:      dst,                   // destination address
		// the other fields, including Src, will be filled in by the kernel
	}
	udp := udpHeader{
		SourcePort: uint16(srcPort % math.MaxUint16),
		DestPort:   uint16(dstPort % math.MaxUint16),
		Length:     uint16(8 + len(payload)),
		// We'll leave checksum empty. It's optional in ipv4, and maybe the kernel will calculate it for us
	}
	b, _ := ipHeader.Marshal()
	data := bytes.NewBuffer(b)
	binary.Write(data, binary.BigEndian, udp)
	data.Write(payload)
	return data.Bytes()
}

/*
func pkt() []byte {
	h := Header{
		Version:  4,
		Len:      20,
		TotalLen: 20 + 10, // 20 bytes for IP, 10 for ICMP
		TTL:      64,
		Protocol: 1, // ICMP
		Dst:      net.IPv4(127, 0, 0, 1),
		// ID, Src and Checksum will be set for us by the kernel
	}

	icmp := []byte{
		8, // type: echo request
		0, // code: not used by echo request
		0, // checksum (16 bit), we fill in below
		0,
		0, // identifier (16 bit). zero allowed.
		0,
		0, // sequence number (16 bit). zero allowed.
		0,
		0xC0, // Optional data. ping puts time packet sent here
		0xDE,
	}
	cs := csum(icmp)
	icmp[2] = byte(cs)
	icmp[3] = byte(cs >> 8)

	out, err := h.Marshal()
	if err != nil {
		log.Fatal(err)
	}
	return append(out, icmp...)
}

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i < len(b); i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	// add back the carry
	s = s>>16 + s&0xffff
	s = s + s>>16
	return uint16(^s)
}
*/
