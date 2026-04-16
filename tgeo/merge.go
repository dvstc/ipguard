package tgeo

import (
	"sort"
)

// SourceData holds IP ranges from a single data source along with its priority.
// Higher priority values win when ranges from multiple sources overlap.
type SourceData struct {
	Ranges   []IPRange
	Priority int
}

// MergeStats records information about the merge operation.
type MergeStats struct {
	RangesPerSource map[string]int `json:"ranges_per_source"`
	ConflictCount   int            `json:"conflict_count"`
	OutputRanges    int            `json:"output_ranges"`
	GapsFilled      int            `json:"gaps_filled"`
}

type sweepEvent struct {
	ip       uint32
	isStart  bool
	priority int
	country  string
}

type activeEntry struct {
	priority int
	country  string
}

// Merge combines IP ranges from multiple sources using an event-based sweep-line.
// Higher-priority sources win on conflict. Gaps are filled with "ZZ".
func Merge(sourcesData map[string]SourceData) ([]IPRange, MergeStats) {
	stats := MergeStats{
		RangesPerSource: make(map[string]int),
	}

	total := 0
	for name, sd := range sourcesData {
		stats.RangesPerSource[name] = len(sd.Ranges)
		total += len(sd.Ranges)
	}

	if total == 0 {
		stats.GapsFilled = 1
		stats.OutputRanges = 1
		return []IPRange{{
			Start:   Uint32ToAddr(0),
			End:     Uint32ToAddr(^uint32(0)),
			Country: "ZZ",
		}}, stats
	}

	events := make([]sweepEvent, 0, total*2)
	for _, sd := range sourcesData {
		for _, r := range sd.Ranges {
			startU := AddrToUint32(r.Start)
			endU := AddrToUint32(r.End)
			events = append(events, sweepEvent{
				ip:       startU,
				isStart:  true,
				priority: sd.Priority,
				country:  r.Country,
			})
			if endU < ^uint32(0) {
				events = append(events, sweepEvent{
					ip:       endU + 1,
					isStart:  false,
					priority: sd.Priority,
					country:  r.Country,
				})
			}
		}
	}

	sort.Slice(events, func(i, j int) bool {
		if events[i].ip != events[j].ip {
			return events[i].ip < events[j].ip
		}
		if events[i].isStart != events[j].isStart {
			return !events[i].isStart
		}
		return false
	})

	var active []activeEntry
	var merged []IPRange
	prevIP := uint32(0)
	prevCountry := ""
	firstEvent := true

	bestFromActive := func() string {
		best := -1
		country := ""
		countries := make(map[string]struct{})
		for _, a := range active {
			countries[a.country] = struct{}{}
			if a.priority > best {
				best = a.priority
				country = a.country
			}
		}
		if len(countries) > 1 {
			stats.ConflictCount++
		}
		return country
	}

	emitInterval := func(start, end uint32, country string) {
		if start > end {
			return
		}
		if country == "" {
			country = "ZZ"
			stats.GapsFilled++
		}
		merged = append(merged, IPRange{
			Start:   Uint32ToAddr(start),
			End:     Uint32ToAddr(end),
			Country: country,
		})
	}

	for i := 0; i < len(events); {
		curIP := events[i].ip

		if firstEvent {
			if curIP > 0 {
				emitInterval(0, curIP-1, "")
			}
			firstEvent = false
		} else if curIP > prevIP {
			emitInterval(prevIP, curIP-1, prevCountry)
		}

		for i < len(events) && events[i].ip == curIP {
			e := events[i]
			if e.isStart {
				active = append(active, activeEntry{priority: e.priority, country: e.country})
			} else {
				for j := len(active) - 1; j >= 0; j-- {
					if active[j].priority == e.priority && active[j].country == e.country {
						active[j] = active[len(active)-1]
						active = active[:len(active)-1]
						break
					}
				}
			}
			i++
		}

		prevIP = curIP
		prevCountry = bestFromActive()
	}

	emitInterval(prevIP, ^uint32(0), prevCountry)

	merged = coalesceRanges(merged)

	stats.OutputRanges = len(merged)
	return merged, stats
}

func coalesceRanges(ranges []IPRange) []IPRange {
	if len(ranges) == 0 {
		return nil
	}

	result := []IPRange{ranges[0]}
	for i := 1; i < len(ranges); i++ {
		last := &result[len(result)-1]
		if ranges[i].Country == last.Country {
			lastEnd := AddrToUint32(last.End)
			curStart := AddrToUint32(ranges[i].Start)
			if curStart == lastEnd+1 {
				last.End = ranges[i].End
				continue
			}
		}
		result = append(result, ranges[i])
	}
	return result
}
