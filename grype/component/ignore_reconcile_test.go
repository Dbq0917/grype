package component

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/match"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestReconcileIgnoreRules(t *testing.T) {
	rawMatches := []match.Match{
		{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{ID: "CVE-2023-0002", Namespace: "nvd:cpe"},
			},
			Package: grypePkg.Package{Name: "tar", Version: "1.35", Type: syftPkg.BinaryPkg},
			Details: match.Details{{Type: match.CPEMatch, Matcher: match.StockMatcher}},
		},
	}

	rules := []match.IgnoreRule{
		{
			Vulnerability: "CVE-2023-0001",
			Reason:        "historical npm/GNU tar false positive",
			Package:       match.IgnoreRulePackage{Name: "tar"},
		},
		{
			Vulnerability: "CVE-2023-0002",
			Reason:        "accepted risk until GNU tar upgrade",
			Package:       match.IgnoreRulePackage{Name: "tar", Version: "1.35"},
		},
		{
			Vulnerability: "CVE-2023-0002",
			Package:       match.IgnoreRulePackage{Name: "tar"},
		},
		{
			VexStatus: "not_affected",
		},
		{},
	}

	got := ReconcileIgnoreRules(rules, rawMatches)
	assert.Len(t, got, len(rules))

	assert.Equal(t, IgnoreActionRetire, got[0].Action)
	assert.Contains(t, got[0].Reason, "no raw match")

	assert.Equal(t, IgnoreActionRetain, got[1].Action)
	assert.Equal(t, "accepted risk until GNU tar upgrade", got[1].Reason)
	assert.False(t, got[1].NeedsReason)
	assert.Len(t, got[1].Suppressed, 1)
	assert.Equal(t, "CVE-2023-0002", got[1].Suppressed[0].VulnerabilityID)
	assert.Equal(t, "nvd:cpe", got[1].Suppressed[0].Namespace)

	assert.Equal(t, IgnoreActionRetain, got[2].Action)
	assert.True(t, got[2].NeedsReason)
	assert.Contains(t, got[2].Reason, "add a reason")

	assert.Equal(t, IgnoreActionReview, got[3].Action)
	assert.Contains(t, got[3].Reason, "VEX")
	assert.Equal(t, IgnoreActionReview, got[4].Action)

	var out bytes.Buffer
	assert.NoError(t, WriteIgnoreDispositions(&out, got))
	assert.Contains(t, out.String(), `"schemaVersion": 1`)
	assert.Contains(t, out.String(), `"action": "retire"`)
	assert.Contains(t, out.String(), `"needsReason": true`)
}
