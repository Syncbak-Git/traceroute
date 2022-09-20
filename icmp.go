package traceroute

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
)

// Return the first non-loopback address as a 4 byte IP address. This address
// is used for sending packets out.
func localAddress() (addr [4]byte, err error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if len(ipnet.IP.To4()) == net.IPv4len {
				copy(addr[:], ipnet.IP.To4())
				return
			}
		}
	}
	err = errors.New("You do not appear to be connected to the Internet")
	return
}

// Given a host name convert it to a 4 byte IP address.
func ipAddress(dest string) (net.IP, error) {
	addrs, err := net.LookupHost(dest)
	if err != nil {
		return nil, err
	}
	addr := addrs[0]
	ipAddr, err := net.ResolveIPAddr("ip", addr)
	if err != nil {
		return nil, err
	}
	return ipAddr.IP, nil
}

type icmpReply struct {
	src      net.IP
	dst      net.IP
	node     net.IP
	hops     int
	dstPort  int
	dstAddr  string
	sent     time.Time
	received time.Time
	elapsed  time.Duration
}

func (r *icmpReply) String() string {
	return fmt.Sprintf("src: %s, dst: %s, node: %s, hops: %d, elapsed: %s, port: %d", r.src.String(), r.dst.String(), r.node.String(), r.hops, r.elapsed.String(), r.dstPort)
}

func extractMessage(p []byte, now time.Time) (*icmpReply, error) {
	// get the reply IPv4 header. That will have the node address
	replyHeader, err := icmp.ParseIPv4Header(p)
	if err != nil {
		return nil, err
	}
	// now, extract the ICMP message
	msg, err := icmp.ParseMessage(syscall.IPPROTO_ICMP, p[replyHeader.Len:])
	if err != nil {
		return nil, err
	}
	var data []byte
	if te, ok := msg.Body.(*icmp.TimeExceeded); ok {
		data = te.Data
	} else if du, ok := msg.Body.(*icmp.DstUnreach); ok {
		data = du.Data
	} else {
		return nil, fmt.Errorf("Unknown message type: %v", msg.Type)
	}
	// data should now have the IP header of the original message plus at least
	// 8 bytes of the original message (which is, at least, the UDP header)
	srcHeader, err := icmp.ParseIPv4Header(data)
	if err != nil {
		return nil, err
	}
	udpHeader := data[srcHeader.Len:]
	if len(udpHeader) < 8 {
		return nil, fmt.Errorf("source udp header too short: %d", len(udpHeader))
	}
	dstPort := binary.BigEndian.Uint16(udpHeader[2:4])
	return &icmpReply{
		src:      srcHeader.Src,
		dst:      srcHeader.Dst,
		node:     replyHeader.Src,
		dstPort:  int(dstPort),
		received: now,
	}, nil
}

type options struct {
	timeout   time.Duration
	maxTTL    int
	firstPort int
}

func continuousTraceroute(destinations []string, opt options) error {
	localAddr, err := localAddress()
	if err != nil {
		return err
	}
	// Set up the socket to receive inbound packets
	recvSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		// this is fatal, because we need to be able to read the responses
		return err
	}
	defer syscall.Close(recvSocket)
	// Bind to the local socket to listen for ICMP packets
	err = syscall.Bind(recvSocket, &syscall.SockaddrInet4{Port: opt.firstPort, Addr: localAddr})
	if err != nil {
		// again, this is fatal
		return err
	}
	// This sets the timeout to wait for a response from the remote host
	tv := syscall.NsecToTimeval(int64(opt.timeout))
	err = syscall.SetsockoptTimeval(recvSocket, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	if err != nil {
		// this one isn't really fatal, but we'll treat it as so, because it's a really bad sign
		return err
	}
	messages := make(chan *icmpReply, 1)
	go func() {
		var p = make([]byte, 100)
		for {
			n, _, err := syscall.Recvfrom(recvSocket, p, 0)
			now := time.Now().UTC()
			if err != nil {
				// TODO: log the error
				time.Sleep(10 * time.Millisecond)
				continue
			}
			msg, err := extractMessage(p[:n], now)
			if err != nil {
				// TODO: log the error
				time.Sleep(10 * time.Millisecond)
				continue
			}
			messages <- msg
		}
	}()
	// we'll use one send socket per TTL value, reusing it across destinations
	sockets := make(map[int]int)
	for ttl := 1; ttl <= opt.maxTTL; ttl++ {
		socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
		if err != nil {
			return err
		}
		defer syscall.Close(socket)
		err = syscall.SetsockoptInt(socket, 0x0, syscall.IP_TTL, ttl)
		if err != nil {
			return err
		}
		sockets[ttl] = socket
	}
	type packet struct {
		start time.Time
		ttl   int
		dest  string
		port  int
	}
	inProgress := map[string][]packet{}
	payload := []byte{0x00}
	var generation int
	for {
		generation++
		port := opt.firstPort - 1
		for _, dest := range destinations {
			delete(inProgress, dest)
			port++
			addr, err := ipAddress(dest)
			if err != nil {
				// TODO: log the error
				continue
			}
			for ttl, socket := range sockets {
				p := packet{
					start: time.Now().UTC(),
					ttl:   ttl,
					dest:  dest,
					port:  port,
				}
				var b [4]byte
				copy(b[:], addr.To4())
				inProgress[addr.String()] = append(inProgress[addr.String()], p)
				err := syscall.Sendto(socket, payload, 0, &syscall.SockaddrInet4{Port: port, Addr: b})
				if err != nil {
					// TODO: log the error
					continue
				}
			}
		}
		// TODO: we could keep more than one generation in inProgress, and we could distinguish
		// the responses using the source port
		for begin := time.Now().UTC(); time.Since(begin) < opt.timeout; {
			var err error
			msg := <-messages
			packets, ok := inProgress[msg.dst.String()]
			if !ok {
				err = fmt.Errorf("no matching in progress address")
			}
			var found bool
			for _, p := range packets {
				if p.port == msg.dstPort {
					found = true
					msg.sent = p.start
					msg.hops = p.ttl
					msg.dstAddr = p.dest
					msg.elapsed = msg.received.Sub(msg.sent)
					break
				}
			}
			if !found && err == nil {
				err = fmt.Errorf("no matching in progress record")
			}
			// TODO: log msg, with the generation and the error status
		}
	}

}
