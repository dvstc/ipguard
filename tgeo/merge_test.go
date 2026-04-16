package tgeo

import (
	"testing"
)

func makeSourcesData(sources ...struct {
	name     string
	priority int
	ranges   []IPRange
}) map[string]SourceData {
	m := make(map[string]SourceData)
	for _, s := range sources {
		m[s.name] = SourceData{Ranges: s.ranges, Priority: s.priority}
	}
	return m
}

type srcInput struct {
	name     string
	priority int
	ranges   []IPRange
}

func TestMergeThreeSourcesAgree(t *testing.T) {
	r := IPRange{Start: ip("1.0.0.0"), End: ip("1.0.0.255"), Country: "US"}
	data := makeSourcesData(
		srcInput{"rir", 1, []IPRange{r}},
		srcInput{"bgp", 2, []IPRange{r}},
		srcInput{"dbip", 3, []IPRange{r}},
	)

	merged, stats := Merge(data)
	if stats.ConflictCount > 0 {
		t.Errorf("expected no conflicts, got %d", stats.ConflictCount)
	}

	foundUS := false
	for _, m := range merged {
		if m.Country == "US" && m.Start == ip("1.0.0.0") && m.End == ip("1.0.0.255") {
			foundUS = true
		}
	}
	if !foundUS {
		t.Error("US range not found in merged output")
	}
}

func TestMergeHighestPriorityWins(t *testing.T) {
	data := makeSourcesData(
		srcInput{"rir", 1, []IPRange{{Start: ip("1.0.0.0"), End: ip("1.0.0.255"), Country: "US"}}},
		srcInput{"dbip", 3, []IPRange{{Start: ip("1.0.0.0"), End: ip("1.0.0.255"), Country: "AU"}}},
	)

	merged, stats := Merge(data)
	if stats.ConflictCount == 0 {
		t.Error("expected at least one conflict")
	}

	for _, m := range merged {
		if m.Start == ip("1.0.0.0") && m.End == ip("1.0.0.255") {
			if m.Country != "AU" {
				t.Errorf("expected AU (priority 3), got %s", m.Country)
			}
			return
		}
	}
	t.Error("range 1.0.0.0 - 1.0.0.255 not found")
}

func TestMergeGapFilledWithZZ(t *testing.T) {
	data := makeSourcesData(
		srcInput{"rir", 1, []IPRange{{Start: ip("10.0.0.0"), End: ip("10.0.0.255"), Country: "US"}}},
	)

	merged, stats := Merge(data)
	if stats.GapsFilled == 0 {
		t.Error("expected gaps to be filled")
	}

	if merged[0].Country != "ZZ" {
		t.Errorf("first range: got %s, want ZZ", merged[0].Country)
	}
	if merged[0].Start != ip("0.0.0.0") {
		t.Errorf("first range start: got %s, want 0.0.0.0", merged[0].Start)
	}
}

func TestMergeAdjacentSameCountryCoalesced(t *testing.T) {
	data := makeSourcesData(
		srcInput{"rir", 1, []IPRange{
			{Start: ip("1.0.0.0"), End: ip("1.0.0.255"), Country: "US"},
			{Start: ip("1.0.1.0"), End: ip("1.0.1.255"), Country: "US"},
		}},
	)

	merged, _ := Merge(data)
	for _, m := range merged {
		if m.Start == ip("1.0.0.0") {
			if m.End != ip("1.0.1.255") {
				t.Errorf("expected coalesced range to end at 1.0.1.255, got %s", m.End)
			}
			return
		}
	}
	t.Error("coalesced range starting at 1.0.0.0 not found")
}

func TestMergeEmptyInput(t *testing.T) {
	data := makeSourcesData()
	merged, stats := Merge(data)
	if stats.OutputRanges != 1 {
		t.Errorf("expected 1 output range (full ZZ), got %d", stats.OutputRanges)
	}
	if merged[0].Country != "ZZ" {
		t.Errorf("expected ZZ, got %s", merged[0].Country)
	}
	if merged[0].Start != ip("0.0.0.0") || merged[0].End != ip("255.255.255.255") {
		t.Errorf("expected full range, got %s - %s", merged[0].Start, merged[0].End)
	}
}

func TestMergeBoundaryOverflow(t *testing.T) {
	data := makeSourcesData(
		srcInput{"rir", 1, []IPRange{
			{Start: ip("255.255.255.0"), End: ip("255.255.255.255"), Country: "US"},
		}},
	)

	merged, _ := Merge(data)
	last := merged[len(merged)-1]
	if last.End != ip("255.255.255.255") {
		t.Errorf("last range end: got %s, want 255.255.255.255", last.End)
	}
}

func TestMergeLargeInput(t *testing.T) {
	var rirRanges, bgpRanges, dbipRanges []IPRange
	for i := uint32(0); i < 200_000; i++ {
		base := i * 256
		rirRanges = append(rirRanges, IPRange{
			Start: Uint32ToAddr(base), End: Uint32ToAddr(base + 255), Country: "US",
		})
	}
	for i := uint32(0); i < 250_000; i++ {
		base := i * 256
		bgpRanges = append(bgpRanges, IPRange{
			Start: Uint32ToAddr(base), End: Uint32ToAddr(base + 255), Country: "US",
		})
	}
	for i := uint32(0); i < 100_000; i++ {
		base := i * 256
		dbipRanges = append(dbipRanges, IPRange{
			Start: Uint32ToAddr(base), End: Uint32ToAddr(base + 255), Country: "US",
		})
	}

	data := makeSourcesData(
		srcInput{"rir", 1, rirRanges},
		srcInput{"bgp", 2, bgpRanges},
		srcInput{"dbip", 3, dbipRanges},
	)

	merged, stats := Merge(data)
	if stats.OutputRanges == 0 {
		t.Fatal("no output ranges")
	}
	if len(merged) > 10 {
		t.Errorf("expected heavy coalescing, got %d ranges", len(merged))
	}
}

func TestMergeSingleSource(t *testing.T) {
	data := makeSourcesData(
		srcInput{"rir", 1, []IPRange{
			{Start: ip("0.0.0.0"), End: ip("255.255.255.255"), Country: "US"},
		}},
	)

	merged, stats := Merge(data)
	if stats.OutputRanges != 1 {
		t.Errorf("expected 1 range, got %d", stats.OutputRanges)
	}
	if merged[0].Country != "US" {
		t.Errorf("expected US, got %s", merged[0].Country)
	}
}
