package traceroute

import (
	"fmt"
	"strings"
	"time"
)

type Report struct {
	Destination  Addr
	MaxHops      int
	PacketLength int
	Hops         []*Hop
	Generations  int
}

func (r Report) String() string {
	type entry struct {
		step          int
		name          string
		address       string
		durations     []time.Duration
		atDestination bool
	}
	// we want to coalesce the hops, so that ones with the same IP address show multiple durations
	all := make(map[int][]entry)
	for _, hop := range r.Hops {
		var found bool
		for i, e := range all[hop.Step] {
			if e.name == hop.Node.Host {
				all[hop.Step][i].durations = append(all[hop.Step][i].durations, hop.Elapsed)
				found = true
				break
			}
		}
		if !found {
			e := entry{
				step:          hop.Step,
				name:          hop.Node.Host,
				address:       hop.Node.IP.String(),
				durations:     []time.Duration{hop.Elapsed},
				atDestination: hop.icmpType == 3,
			}
			all[hop.Step] = append(all[hop.Step], e)
		}
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("traceroute to %s (%s), %d hops max, %d byte packets\n",
		r.Destination.Host, r.Destination.IP.String(), r.MaxHops, r.PacketLength))
	if len(all) == 0 {
		sb.WriteString(fmt.Sprintf("No data\n"))
	} else {
		for i := 1; i < r.MaxHops; i++ {
			sb.WriteString(fmt.Sprintf("%d\t", i))
			var count int
			var done bool
			for _, e := range all[i] {
				done = done || e.atDestination
				sb.WriteString(fmt.Sprintf("%s\t(%s)\t", e.name, e.address))
				for _, d := range e.durations {
					sb.WriteString(fmt.Sprintf("%.3f ms\t", 1000*d.Seconds()))
					count++
				}
			}
			for count < r.Generations {
				sb.WriteString(fmt.Sprintf("*\t"))
				count++
			}
			sb.WriteString(fmt.Sprintf("\n"))
			if done {
				break
			}
		}
	}
	// 1  router.home (192.168.1.1)  0.372 ms  0.403 ms  0.453 ms
	// 14  * * *
	// 19  52.93.28.192 (52.93.28.192)  33.899 ms 52.93.28.188 (52.93.28.188)  32.730 ms 52.93.28.176 (52.93.28.176)  31.235 ms
	return sb.String()
}
