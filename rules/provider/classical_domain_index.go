package provider

import (
	"hash/maphash"
	"math/bits"
	"slices"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules/common"
)

const minClassicalDomainRun = 16

type classicalNameTable struct {
	names  []string
	slots  []uint32
	maxLen int
}

func newClassicalNameTable(names []string, seed maphash.Seed) classicalNameTable {
	slices.Sort(names)
	names = slices.Compact(names)
	if len(names) < cap(names)/2 {
		names = slices.Clone(names)
	}
	table := classicalNameTable{names: names}
	for _, name := range names {
		table.maxLen = max(table.maxLen, len(name))
	}
	if len(names) < minClassicalDomainRun {
		return table
	}
	shift := bits.Len(uint(len(names)) + uint(len(names))/4 - 1)
	if shift >= 32 || shift >= bits.UintSize-1 {
		return table
	}
	table.slots = make([]uint32, 1<<shift)
	mask := uint64(len(table.slots) - 1)
	for i, name := range names {
		for pos := maphash.String(seed, name) & mask; ; pos = (pos + 1) & mask {
			if table.slots[pos] == 0 {
				table.slots[pos] = uint32(i + 1)
				break
			}
		}
	}
	return table
}

func (t *classicalNameTable) has(name string, seed maphash.Seed) bool {
	if len(name) > t.maxLen {
		return false
	}
	if len(t.slots) == 0 {
		_, found := slices.BinarySearch(t.names, name)
		return found
	}
	mask := uint64(len(t.slots) - 1)
	for pos := maphash.String(seed, name) & mask; ; pos = (pos + 1) & mask {
		index := t.slots[pos]
		if index == 0 {
			return false
		}
		if t.names[index-1] == name {
			return true
		}
	}
}

type classicalDomainRun struct {
	seed              maphash.Seed
	domains, suffixes classicalNameTable
}

func isClassicalDomain(rule classicalMatcher) bool {
	switch rule.(type) {
	case *common.Domain, *common.DomainSuffix:
		return true
	default:
		return false
	}
}

// Only adjacent standard domain rules can share an index: other rules may
// resolve DNS, look up a process or change the metadata used by later rules.
func newClassicalDomainRun(rules []classicalMatcher) *classicalDomainRun {
	var exact int
	for _, rule := range rules {
		if _, ok := rule.(*common.Domain); ok {
			exact++
		}
	}
	domains := make([]string, 0, exact)
	suffixes := make([]string, 0, len(rules)-exact)
	for _, rule := range rules {
		switch r := rule.(type) {
		case *common.Domain:
			domains = append(domains, r.Payload())
		case *common.DomainSuffix:
			suffixes = append(suffixes, r.Payload())
		}
	}
	seed := maphash.MakeSeed()
	return &classicalDomainRun{
		seed: seed, domains: newClassicalNameTable(domains, seed), suffixes: newClassicalNameTable(suffixes, seed),
	}
}

func (r *classicalDomainRun) Match(metadata *C.Metadata, _ C.RuleMatchHelper) (bool, string) {
	host := metadata.RuleHost()
	if r.domains.has(host, r.seed) || r.suffixes.has(host, r.seed) {
		return true, ""
	}
	if len(r.suffixes.names) > 0 {
		for i := max(0, len(host)-r.suffixes.maxLen-1); i < len(host); i++ {
			if host[i] == '.' && r.suffixes.has(host[i+1:], r.seed) {
				return true, ""
			}
		}
	}
	return false, ""
}
