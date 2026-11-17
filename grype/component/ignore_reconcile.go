package component

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/anchore/grype/grype/match"
)

// IgnoreAction is the disposition for a historical ignore rule after replaying
// scans through the current component-identity rules.
type IgnoreAction string

const (
	// IgnoreActionRetire means the rule no longer suppresses any raw match and
	// can be removed automatically.
	IgnoreActionRetire IgnoreAction = "retire"

	// IgnoreActionRetain means the rule still suppresses at least one raw match
	// and must remain until the underlying finding is fixed or re-triaged.
	IgnoreActionRetain IgnoreAction = "retain"

	// IgnoreActionReview means the rule cannot be evaluated automatically
	// (VEX rules or rules with no criteria) and needs an explicit owner review.
	IgnoreActionReview IgnoreAction = "review"
)

// SuppressedMatch is the evidence for one raw match a historical rule would
// still suppress.
type SuppressedMatch struct {
	VulnerabilityID string `json:"vulnerabilityId"`
	Namespace       string `json:"namespace,omitempty"`
	PackageName     string `json:"packageName"`
	PackageVersion  string `json:"packageVersion"`
	PackageType     string `json:"packageType,omitempty"`
	PackageLanguage string `json:"packageLanguage,omitempty"`
	MatchType       string `json:"matchType,omitempty"`
}

// IgnoreDisposition explains what should happen to one historical ignore rule.
type IgnoreDisposition struct {
	Index       int               `json:"index"`
	Action      IgnoreAction      `json:"action"`
	Rule        match.IgnoreRule  `json:"rule"`
	Reason      string            `json:"reason"`
	NeedsReason bool              `json:"needsReason,omitempty"`
	Suppressed  []SuppressedMatch `json:"suppressed,omitempty"`
}

// ReconcileIgnoreRules replays raw matches (before ignore rules are applied)
// against each historical ignore rule. Rules that match nothing are safe to
// retire automatically; rules that still match keep their original reason or
// are flagged as needing one; VEX and empty rules are sent to review.
func ReconcileIgnoreRules(rules []match.IgnoreRule, rawMatches []match.Match) []IgnoreDisposition {
	out := make([]IgnoreDisposition, 0, len(rules))

	for idx, rule := range rules {
		disposition := IgnoreDisposition{
			Index: idx,
			Rule:  rule,
		}

		switch {
		case rule.VexStatus != "":
			disposition.Action = IgnoreActionReview
			disposition.Reason = "VEX rule is evaluated by the VEX processor and cannot be retired by component-identity replay"
		case !hasIgnoreCriteria(rule):
			disposition.Action = IgnoreActionReview
			disposition.Reason = "rule has no match conditions and cannot be retired automatically"
		default:
			suppressed := suppressibleMatches(rule, rawMatches)
			if len(suppressed) == 0 {
				disposition.Action = IgnoreActionRetire
				disposition.Reason = "no raw match remains for this rule after component-identity replay"
				break
			}

			disposition.Action = IgnoreActionRetain
			disposition.Suppressed = suppressed
			if rule.Reason != "" {
				disposition.Reason = rule.Reason
			} else {
				disposition.NeedsReason = true
				disposition.Reason = fmt.Sprintf("rule still suppresses %d raw match(es); add a reason for audit", len(suppressed))
			}
		}

		out = append(out, disposition)
	}

	return out
}

func suppressibleMatches(rule match.IgnoreRule, matches []match.Match) []SuppressedMatch {
	var out []SuppressedMatch
	for _, m := range matches {
		if len(rule.IgnoreMatch(m)) == 0 {
			continue
		}
		mt := ""
		if len(m.Details) > 0 {
			mt = string(m.Details[0].Type)
		}
		out = append(out, SuppressedMatch{
			VulnerabilityID: m.Vulnerability.ID,
			Namespace:       m.Vulnerability.Namespace,
			PackageName:     m.Package.Name,
			PackageVersion:  m.Package.Version,
			PackageType:     string(m.Package.Type),
			PackageLanguage: string(m.Package.Language),
			MatchType:       mt,
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].VulnerabilityID != out[j].VulnerabilityID {
			return out[i].VulnerabilityID < out[j].VulnerabilityID
		}
		if out[i].PackageName != out[j].PackageName {
			return out[i].PackageName < out[j].PackageName
		}
		return out[i].Namespace < out[j].Namespace
	})

	return out
}

func hasIgnoreCriteria(rule match.IgnoreRule) bool {
	return rule.Vulnerability != "" ||
		rule.Namespace != "" ||
		rule.FixState != "" ||
		rule.MatchType != "" ||
		rule.Package.Name != "" ||
		rule.Package.Version != "" ||
		rule.Package.Language != "" ||
		rule.Package.Type != "" ||
		rule.Package.Location != "" ||
		rule.Package.UpstreamName != ""
}

// WriteIgnoreDispositions exports a whitelist-migration report as deterministic
// JSON for review and CI artifacts.
func WriteIgnoreDispositions(w io.Writer, dispositions []IgnoreDisposition) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		SchemaVersion int                 `json:"schemaVersion"`
		Dispositions  []IgnoreDisposition `json:"dispositions"`
	}{
		SchemaVersion: 1,
		Dispositions:  dispositions,
	})
}
