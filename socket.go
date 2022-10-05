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
