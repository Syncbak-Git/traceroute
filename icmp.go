package traceroute

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"syscall"
	"time"

	log "github.com/Syncbak-Git/go-loggy"
	"github.com/Syncbak-Git/go-loggy/handlers/discard"
	"github.com/jackpal/gateway"
	"golang.org/x/net/icmp"
)

type Addr struct {
	// Host is the host (ie, DNS) name of the node.
	Host string
	// IP is the IP address of the node.
	IP net.IP
}

// Continuous does a continous traceroute for a set of destinations.
type Continuous struct {
	Timeout       time.Duration
	MaxTTL        int
	FirstPort     int
	PortRange     int
	Destinations  []Addr
	Generations   int
	PayloadLength int
	logger        *log.Logger
}

// NewContinuous returns a new Continuous for monitoring the
// supplied destinations using the default options. The supplied Logger, if non-nil,
// will be used for logging.
func NewContinuous(destinations []string, logger *log.Logger) (*Continuous, error) {
	if logger == nil {
		d := discard.New()
		logger = &log.Logger{
			Handler:       d,
			ActionHandler: d,
			Level:         0,
		}
	}
	dest := make([]Addr, len(destinations))
	for i, host := range destinations {
		ip, err := ipAddress(host)
		if err != nil {
			return nil, fmt.Errorf("could not resolve %s: %s", host, err)
		}
		dest[i] = Addr{Host: host, IP: ip}
	}
	return &Continuous{
		Timeout:       5 * time.Second,
		MaxTTL:        30,
		FirstPort:     33434,
		PortRange:     1024,
		Destinations:  dest,
		Generations:   3,
		PayloadLength: 1,
		logger:        logger,
	}, nil
}

// Hop is a step in the network route between a source and destination address.
type Hop struct {
	// Src is the source (ie, local) address.
	Src Addr
	// Dst is the destination (ie, remote) address.
	Dst Addr
	// Node is the node at this step of the route.
	Node Addr
	// Step is the location of this node in the route, ie the TTL value used.
	Step int
	// ID is a unique ID that is used to match the original request with the ICMP response.
	// It can be derived from either the request or the response.
	ID string
	// DstPort is the destination port targeted.
	DstPort int
	// Sent is the time the query began.
	Sent time.Time
	// Received is the time the query completed.
	Received time.Time
	// Elapsed is the duration of the query.
	Elapsed time.Duration
	// Generation is the cycle counter.
	Generation int
	// icmpType is the ICMP Type value.
	icmpType int
}

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

func (r *Hop) String() string {
	return fmt.Sprintf("Src: %s, Dst: %s (%s), Node: %s (%s), Step: %d, Elapsed: %s, ID: %s, Generation: %d, Type: %d",
		r.Src.IP.String(), r.Dst.Host, r.Dst.IP.String(), r.Node.Host, r.Node.IP.String(), r.Step, r.Elapsed.String(), r.ID, r.Generation, r.icmpType)
}

func (r *Hop) Fields() log.Fields {
	return map[string]interface{}{
		"srchost":    r.Src.Host,
		"srcip":      r.Src.IP.String(),
		"dsthost":    r.Dst.Host,
		"dstip":      r.Dst.IP.String(),
		"nodehost":   r.Node.Host,
		"nodeip":     r.Node.IP.String(),
		"step":       r.Step,
		"id":         r.ID,
		"sent":       r.Sent.Format(time.RFC3339Nano),
		"received":   r.Received.Format(time.RFC3339Nano),
		"elapsed":    r.Elapsed.Seconds(),
		"ms":         r.Elapsed.Milliseconds(),
		"generation": r.Generation,
	}
}

func (c *Continuous) extractMessage(p []byte, now time.Time) (*Hop, error) {
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
	icmpType := int(p[replyHeader.Len])
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
	srcPort := binary.BigEndian.Uint16(udpHeader[0:2])
	dstPort := binary.BigEndian.Uint16(udpHeader[2:4])
	var name string
	names, _ := net.LookupAddr(replyHeader.Src.String())
	if len(names) > 0 {
		name = names[0]
	} else {
		name = replyHeader.Src.String()
	}
	id := c.packetID(srcHeader.ID, srcHeader.Dst, int(srcPort), int(dstPort))
	return &Hop{
		Src: Addr{
			IP: srcHeader.Src,
		},
		Dst: Addr{
			IP: srcHeader.Dst,
		},
		Node: Addr{
			Host: name,
			IP:   replyHeader.Src,
		},
		Received: now,
		ID:       id,
		icmpType: icmpType,
	}, nil
}

func (c *Continuous) readICMP(ctx context.Context, hops chan *Hop) error {
	defer close(hops)
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
	/////////////////////////////////////////
	// TODO: do we need a receive timeout if we're running continuously?
	// we do, if we want ctx.Done() to exit the recvfrom loop, otherwise it blocks forever
	// once we stop sending requests
	// tv := syscall.NsecToTimeval(int64(c.Timeout))
	// err = syscall.SetsockoptTimeval(recvSocket, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	// if err != nil {
	// 	// this one isn't really fatal, but we'll treat it as so, because it's a really bad sign
	// 	return err
	// }
	//////////////////////////////////////////
	err = syscall.Bind(recvSocket, &syscall.SockaddrInet4{Port: c.FirstPort, Addr: localAddr})
	if err != nil {
		// again, this is fatal
		return err
	}
	for ctx.Err() == nil {
		var p = make([]byte, 100)
		n, _, err := syscall.Recvfrom(recvSocket, p, 0)
		now := time.Now().UTC()
		if err != nil {
			c.logger.WithError(err).Error("Recvfrom error")
			time.Sleep(10 * time.Millisecond)
		} else {
			// extractMessage has to do reverse DNS lookups, which (at least on my machine) seem to get throttled,
			// and this messes up the elapsed time calculation (by backing up the Recvfrom loop). So, we do it
			// in its own goroutine.
			go func(now time.Time, p []byte, n int, err error) {
				if err != nil {
					return
				}
				msg, err := c.extractMessage(p[:n], now)
				if err != nil {
					c.logger.WithError(err).Error("extractMessage error")
					return
				}
				hops <- msg
			}(now, p, n, err)
		}
	}
	return ctx.Err()
}

type packet struct {
	start      time.Time
	ttl        int
	dest       Addr
	port       int
	generation int
	id         string
}

func (c *Continuous) nextPort(prev int) int {
	var p int
	if prev == 0 {
		p = c.FirstPort
	} else {
		p = prev + 1
	}
	if p > c.FirstPort+c.PortRange {
		p = c.FirstPort
	}
	return p
}

func (c *Continuous) packetID(ipHeaderID int, destIP net.IP, srcPort, destPort int) string {
	return fmt.Sprintf("%d|%s|%d|%d", ipHeaderID, destIP.String(), srcPort, destPort)
}

func (c *Continuous) generatePackets(ctx context.Context, jobs chan packet) error {
	defer close(jobs)
	// set up the sending socket
	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer syscall.Close(socket)
	newGeneration := time.NewTicker(c.Timeout)
	defer newGeneration.Stop()
	var generation int
	payload := bytes.Repeat([]byte{0x00}, c.PayloadLength)
	var srcPort, dstPort int
	var packetID int
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-newGeneration.C:
			generation++
			c.logger.Debugf("NewGeneration: %d", generation)
			for i, dest := range c.Destinations {
				if generation > 0 && generation%c.Generations == 0 {
					// update the destination IP address every few generations
					addr, err := ipAddress(dest.Host)
					if err != nil {
						c.logger.WithError(err).WithField("address", dest.Host).Error("could not resolve address")
					} else {
						c.Destinations[i].IP = addr
					}
				}
				for ttl := 1; ttl <= c.MaxTTL; ttl++ {
					srcPort = c.nextPort(srcPort)
					dstPort = c.nextPort(srcPort) // this looks wrong, but isn't.
					// We want to ensure that src and dst port pairings vary, so
					// we base the dstPort on the srcPort.
					packetID = (packetID + 1) % math.MaxUint16
					pkt := newUDPPacket(dest.IP, srcPort, dstPort, ttl, packetID, payload)
					p := packet{
						start:      time.Now().UTC(),
						ttl:        ttl,
						dest:       dest,
						generation: generation,
						id:         c.packetID(packetID, dest.IP, srcPort, dstPort),
					}
					var b [4]byte
					copy(b[:], dest.IP.To4())
					err := syscall.Sendto(socket, pkt, 0, &syscall.SockaddrInet4{Port: dstPort, Addr: b})
					if err != nil {
						c.logger.WithError(err).WithField("address", dest.Host).Error("Sendto error")
						continue
					}
					jobs <- p
				}
			}
		}
	}
}

// ErrMissingHost occurs when we try to process a response for a destination
// that's not in the list of destinations.
var ErrMissingHost error = errors.New("missing host")

func (c *Continuous) makeReports(data map[string]map[int][]*Hop) []Report {
	var all []Report
	for host, generations := range data {
		var ip net.IP
		for _, dest := range c.Destinations {
			if dest.Host == host {
				ip = dest.IP
				break
			}
		}
		if ip == nil {
			// this should never happen, so log it
			c.logger.WithError(ErrMissingHost).WithField("host", host).Error("missinghost")
			ip, _ = ipAddress(host)
		}
		addr := Addr{
			Host: host,
			IP:   ip,
		}
		r := c.newReport(addr, generations)
		all = append(all, r)
	}
	return all
}

func (c *Continuous) findGenerationWindow(generations map[int][]*Hop) (first int, last int) {
	for gen := range generations {
		if first == 0 || gen < first {
			first = gen
		}
		if gen > last {
			last = gen
		}
	}
	// we're going to treat the last generation as open-ended, because it's
	// almost certainly still in progress. So, last-first gives us the count
	// of _available_ generations (rather than being off by one).
	for last-first > c.Generations {
		first++
	}
	return
}

func (c *Continuous) newReport(destination Addr, generations map[int][]*Hop) Report {
	first, last := c.findGenerationWindow(generations)
	var hops []*Hop
	for gen := first; gen < last; gen++ {
		hops = append(hops, generations[gen]...)
	}
	sort.Slice(hops, func(a, b int) bool {
		aa := hops[a]
		bb := hops[b]
		if aa.Generation == bb.Generation {
			return aa.Step < bb.Step
		}
		return aa.Generation < bb.Generation
	})
	return Report{
		Destination:  destination,
		Hops:         hops,
		MaxHops:      c.MaxTTL,
		PacketLength: c.PayloadLength + 20 + 8, // 20 for IP header, 8 for UDP header
		Generations:  c.Generations,
	}
}

// Run runs a continous traceroute to the Continuous.Destinations. Except for
// initialization errors, Run will not return until the supplied context is Done.
func (c *Continuous) Run(ctx context.Context, reports <-chan func([]Report)) error {
	// launch the listener
	messages := make(chan *Hop, 1)
	go c.readICMP(ctx, messages)
	jobs := make(chan packet, 1)
	go c.generatePackets(ctx, jobs)
	inProgress := map[string]packet{}
	hops := map[string]map[int][]*Hop{} // hops by generation by destination
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-messages:
			if !ok {
				return errors.New("message channel closed")
			}
			var err error
			p, ok := inProgress[msg.ID]
			if !ok {
				err = fmt.Errorf("no matching in progress address")
			} else {
				msg.Sent = p.start
				msg.Step = p.ttl
				msg.Dst.Host = p.dest.Host
				msg.Elapsed = msg.Received.Sub(msg.Sent)
				msg.Generation = p.generation
				delete(inProgress, msg.ID)
			}
			c.logger.WithError(err).WithFields(msg).Action("traceroute")
			if ok {
				key := msg.Dst.Host
				_, ok := hops[key]
				if !ok {
					hops[key] = map[int][]*Hop{}
				}
				messages := hops[key][msg.Generation]
				messages = append(messages, msg)
				hops[key][msg.Generation] = messages
				// purge the old ones
				first, _ := c.findGenerationWindow(hops[key])
				for gen := range hops[key] {
					if gen < first {
						delete(hops[key], gen)
					}
				}
			}
		case p, ok := <-jobs:
			if !ok {
				return errors.New("jobs channel closed")
			}
			inProgress[p.id] = p
			// the ones that don't respond will accumulate unless we purge them periodically.
			oldest := time.Duration(c.Generations) * c.Timeout
			for id, p := range inProgress {
				age := time.Since(p.start)
				if age > oldest {
					delete(inProgress, id)
				}
			}
		case fn := <-reports:
			r := c.makeReports(hops)
			fn(r)
		}
	}
}
