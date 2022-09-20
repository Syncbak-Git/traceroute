package traceroute

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	log "github.com/Syncbak-Git/go-loggy"
	"github.com/Syncbak-Git/go-loggy/handlers/discard"
	"github.com/jackpal/gateway"
	"golang.org/x/net/icmp"
)

func findAddress() (addr [4]byte, err error) {
	ip, err := gateway.DiscoverInterface()
	if err != nil {
		return localAddress()
	}
	copy(addr[:], ip)
	return
}

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

// Hop is a step in the network route between a source and destination address.
type Hop struct {
	// Src is the source (ie, local) address.
	Src net.IP
	// Dst is the destination (ie, remote) address.
	Dst net.IP
	// Node is the node at this step of the route.
	Node net.IP
	// Step is the location of this node in the route, ie the TTL value used.
	Step int
	// DstPort is the destination port targeted.
	DstPort int
	// DstAddr` is the destination address targeted.
	DstAddr string
	// Sent is the time the query began.
	Sent time.Time
	// Received is the time the query completed.
	Received time.Time
	// Elapsed is the duration of the query.
	Elapsed time.Duration
}

func (r *Hop) String() string {
	return fmt.Sprintf("Src: %s, Dst: %s, Node: %s, Step: %d, Elapsed: %s, Port: %d", r.Src.String(), r.Dst.String(), r.Node.String(), r.Step, r.Elapsed.String(), r.DstPort)
}

func (r *Hop) Fields() log.Fields {
	return map[string]interface{}{
		"src":      r.Src.String(),
		"dst":      r.Dst.String(),
		"node":     r.Node.String(),
		"step":     r.Step,
		"dstport":  r.DstPort,
		"dstaddr":  r.DstAddr,
		"sent":     r.Sent.Format(time.RFC3339Nano),
		"received": r.Received.Format(time.RFC3339Nano),
		"elapsed":  r.Elapsed.Seconds(),
	}
}

func extractMessage(p []byte, now time.Time) (*Hop, error) {
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
	return &Hop{
		Src:      srcHeader.Src,
		Dst:      srcHeader.Dst,
		Node:     replyHeader.Src,
		DstPort:  int(dstPort),
		Received: now,
	}, nil
}

// Continuous does a continous traceroute for a set of destinations.
type Continuous struct {
	Timeout      time.Duration
	MaxTTL       int
	FirstPort    int
	Destinations []string
	logger       *log.Logger
}

// NewContinuous returns a new Continuous for monitoring the
// supplied destinations using the default options. The supplied Logger, if non-nil,
// will be used for logging.
func NewContinuous(destinations []string, logger *log.Logger) *Continuous {
	if logger == nil {
		d := discard.New()
		logger = &log.Logger{
			Handler:       d,
			ActionHandler: d,
			Level:         0,
		}
	}
	return &Continuous{
		Timeout: 5 * time.Second,
		// TODO: revert this
		// MaxTTL:       64,
		MaxTTL:       15,
		FirstPort:    33434,
		Destinations: destinations,
		logger:       logger,
	}
}

// Run runs a continous traceroute to the Continuous.Destinations. Except for
// initialization errors, Run will not return until the supplied context is Done.
func (c *Continuous) Run(ctx context.Context) error {
	localAddr, err := findAddress()
	if err != nil {
		return err
	}
	// set up the listening socket for incoming ICMP packets
	recvSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		// this is fatal, because we need to be able to read the responses
		return err
	}
	defer syscall.Close(recvSocket)
	err = syscall.Bind(recvSocket, &syscall.SockaddrInet4{Port: c.FirstPort, Addr: localAddr})
	if err != nil {
		// again, this is fatal
		return err
	}
	// TODO: do we need a receive timeout if we're running continuously?
	// we do, if we want ctx.Done() to exit the recvfrom loop, otherwise it blocks forever
	// once we stop sending requests
	// tv := syscall.NsecToTimeval(int64(c.Timeout))
	// err = syscall.SetsockoptTimeval(recvSocket, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	// if err != nil {
	// 	// this one isn't really fatal, but we'll treat it as so, because it's a really bad sign
	// 	return err
	// }
	// set up the sending sockets
	// we'll use one send socket per TTL value, reusing it across destinations
	sockets := make(map[int]int)
	for ttl := 1; ttl <= c.MaxTTL; ttl++ {
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
	// launch the listener
	messages := make(chan *Hop, 1)
	go func() {
		for ctx.Err() == nil {
			var p = make([]byte, 100)
			n, _, err := syscall.Recvfrom(recvSocket, p, 0)
			now := time.Now().UTC()
			if err != nil {
				c.logger.WithError(err).Error("Recvfrom error")
				time.Sleep(10 * time.Millisecond)
				continue
			}
			msg, err := extractMessage(p[:n], now)
			if err != nil {
				c.logger.WithError(err).Error("extractMessage error")
				time.Sleep(10 * time.Millisecond)
				continue
			}
			messages <- msg
		}
	}()
	type packet struct {
		start time.Time
		ttl   int
		dest  string
		port  int
	}
	inProgress := map[string][]packet{}
	payload := []byte{0x00}
	var generation int
	for ctx.Err() == nil {
		generation++
		for _, dest := range c.Destinations {
			port := c.FirstPort - 1
			delete(inProgress, dest)
			addr, err := ipAddress(dest)
			if err != nil {
				c.logger.WithError(err).WithField("address", dest).Error("could not resolve address")
				continue
			}
			for ttl, socket := range sockets {
				port++
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
					c.logger.WithError(err).WithField("address", dest).Error("Sendto error")
					continue
				}
			}
		}
		// TODO: we could keep more than one generation in inProgress, and we could distinguish
		// the responses using the source port
		for begin := time.Now().UTC(); time.Since(begin) < c.Timeout; {
			var err error
			msg := <-messages
			packets, ok := inProgress[msg.Dst.String()]
			if !ok {
				err = fmt.Errorf("no matching in progress address")
			}
			var found bool
			for _, p := range packets {
				if p.port == msg.DstPort {
					found = true
					msg.Sent = p.start
					msg.Step = p.ttl
					msg.DstAddr = p.dest
					msg.Elapsed = msg.Received.Sub(msg.Sent)
					break
				}
			}
			if !found && err == nil {
				err = fmt.Errorf("no matching in progress record")
			}
			fmt.Println(msg.String())
			c.logger.WithError(err).WithField("generation", generation).WithFields(msg).Action("traceroute")
		}
	}
	return ctx.Err()
}
