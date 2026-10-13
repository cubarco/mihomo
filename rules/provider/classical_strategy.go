package provider

import (
	"fmt"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/rules/common"
)

type classicalStrategy struct {
	rules []classicalMatcher
	count int
	parse common.ParseRuleFunc
}

type classicalMatcher interface {
	Match(*C.Metadata, C.RuleMatchHelper) (bool, string)
}

func (c *classicalStrategy) Behavior() P.RuleBehavior {
	return P.Classical
}

func (c *classicalStrategy) Match(metadata *C.Metadata, helper C.RuleMatchHelper) bool {
	for _, rule := range c.rules {
		if m, _ := rule.Match(metadata, helper); m {
			return true
		}
	}

	return false
}

func (c *classicalStrategy) Count() int {
	return c.count
}

func (c *classicalStrategy) Reset() {
	c.rules = nil
	c.count = 0
}

func (c *classicalStrategy) Insert(rule string) {
	r, err := c.payloadToRule(rule)
	if err != nil {
		log.Warnln("parse classical rule [%s] error: %s", rule, err.Error())
	} else {
		c.rules = append(c.rules, r)
		c.count++
	}
}

func (c *classicalStrategy) payloadToRule(rule string) (C.Rule, error) {
	tp, payload, target, params := common.ParseRulePayload(rule, false)
	switch tp {
	case "MATCH", "RULE-SET", "SUB-RULE":
		return nil, fmt.Errorf("unsupported rule type on classical rule-set: %s", tp)
	}
	return c.parse(tp, payload, target, params, nil)
}

func (c *classicalStrategy) FinishInsert() {
	kept := 0
	for start := 0; start < len(c.rules); {
		end := start
		for end < len(c.rules) && isClassicalDomain(c.rules[end]) {
			end++
		}
		if end-start >= minClassicalDomainRun {
			c.rules[kept] = newClassicalDomainRun(c.rules[start:end])
			kept++
			start = end
			continue
		}
		if end == start {
			end++
		}
		kept += copy(c.rules[kept:], c.rules[start:end])
		start = end
	}
	if kept == len(c.rules) {
		return
	}
	clear(c.rules[kept:])
	if kept < cap(c.rules)/2 {
		c.rules = append([]classicalMatcher(nil), c.rules[:kept]...)
	} else {
		c.rules = c.rules[:kept]
	}
}

func NewClassicalStrategy(parse common.ParseRuleFunc) *classicalStrategy {
	return &classicalStrategy{parse: parse}
}
