package internal

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

const (
	gnuTarName = "tar"
	gnuTarGHSA = "GHSA-3jfq-g458-7qm9"
	gnuTarCVE  = "CVE-2023-39804"
)

// nameOrCPEProvider returns language-ecosystem records when the search is by
// name/ecosystem, and NVD records when the search is by CPE. This models the
// split the stock matcher must keep for a component with no ecosystem evidence.
type nameOrCPEProvider struct {
	byName []vulnerability.Vulnerability
	byCPE  []vulnerability.Vulnerability
}

func (s nameOrCPEProvider) Close() error { return nil }

func (s nameOrCPEProvider) PackageSearchNames(p pkg.Package) []string {
	return []string{p.Name}
}

func (s nameOrCPEProvider) VulnerabilityMetadata(vulnerability.Reference) (*vulnerability.Metadata, error) {
	return nil, nil
}

func (s nameOrCPEProvider) FindVulnerabilities(criteria ...vulnerability.Criteria) ([]vulnerability.Vulnerability, error) {
	for _, row := range search.CriteriaIterator(criteria) {
		for _, c := range row {
			if _, ok := c.(*search.UnaffectedCriteria); ok {
				return nil, nil
			}
		}
	}
	for _, row := range search.CriteriaIterator(criteria) {
		for _, c := range row {
			if _, ok := c.(*search.CPECriteria); ok {
				return s.byCPE, nil
			}
			if _, ok := c.(*search.EcosystemCriteria); ok {
				return s.byName, nil
			}
		}
	}
	return nil, nil
}

func TestMatchPackageByEcosystemAndCPEs_CPEOnlySkipsLanguageNameLookup(t *testing.T) {
	gnuTarCPE := cpe.Must("cpe:2.3:a:gnu:tar:1.35:*:*:*:*:*:*:*", cpe.DeclaredSource)
	store := nameOrCPEProvider{
		byName: []vulnerability.Vulnerability{
			{
				Reference: vulnerability.Reference{
					ID:        gnuTarGHSA,
					Namespace: "github:language:javascript",
				},
				PackageName: gnuTarName,
				Constraint:  version.MustGetConstraint("< 7.5.3", version.UnknownFormat),
			},
		},
		byCPE: []vulnerability.Vulnerability{
			{
				Reference: vulnerability.Reference{
					ID:        gnuTarCVE,
					Namespace: "nvd:cpe",
				},
				PackageName: gnuTarName,
				Constraint:  version.MustGetConstraint("< 1.36", version.UnknownFormat),
				CPEs:        []cpe.CPE{gnuTarCPE},
			},
		},
	}

	p := pkg.Package{
		Name:     gnuTarName,
		Version:  "1.35",
		Language: "",
		Type:     "",
		CPEs:     []cpe.CPE{gnuTarCPE},
	}

	matches, _, err := MatchPackageByEcosystemAndCPEs(store, p, match.StockMatcher, true)
	require.NoError(t, err)

	var ids []string
	for _, m := range matches {
		ids = append(ids, m.Vulnerability.ID)
	}
	assert.NotContains(t, ids, gnuTarGHSA, "npm tar advisories must not be exact-direct matches for a GNU tar CPE")
	assert.Contains(t, ids, gnuTarCVE, "CPE matching against GNU tar records must still run")
	assert.Len(t, matches, 1)
	assert.Equal(t, match.CPEMatch, matches[0].Details[0].Type)
	assert.Equal(t, "nvd:cpe", matches[0].Details[0].SearchedBy.(match.CPEParameters).Namespace)
}

func TestHasLanguageEcosystem(t *testing.T) {
	assert.False(t, hasLanguageEcosystem(pkg.Package{}))
	assert.False(t, hasLanguageEcosystem(pkg.Package{Language: syftPkg.UnknownLanguage}))
	assert.True(t, hasLanguageEcosystem(pkg.Package{Language: syftPkg.JavaScript}))
}

func TestMatchPackageByEcosystemAndCPEs_BinaryCPEOnlySkipsLanguageNameLookup(t *testing.T) {
	gnuTarCPE := cpe.Must("cpe:2.3:a:gnu:tar:1.35:*:*:*:*:*:*:*", cpe.DeclaredSource)
	store := nameOrCPEProvider{
		byName: []vulnerability.Vulnerability{{
			Reference:   vulnerability.Reference{ID: gnuTarGHSA, Namespace: "github:language:javascript"},
			PackageName: gnuTarName,
			Constraint:  version.MustGetConstraint("< 7.5.3", version.UnknownFormat),
		}},
		byCPE: []vulnerability.Vulnerability{{
			Reference:   vulnerability.Reference{ID: gnuTarCVE, Namespace: "nvd:cpe"},
			PackageName: gnuTarName,
			Constraint:  version.MustGetConstraint("< 1.36", version.UnknownFormat),
			CPEs:        []cpe.CPE{gnuTarCPE},
		}},
	}

	matches, _, err := MatchPackageByEcosystemAndCPEs(store, pkg.Package{
		Name: gnuTarName, Version: "1.35", Type: syftPkg.BinaryPkg, CPEs: []cpe.CPE{gnuTarCPE},
	}, match.StockMatcher, true)
	require.NoError(t, err)
	require.Len(t, matches, 1)
	assert.Equal(t, gnuTarCVE, matches[0].Vulnerability.ID)
}

func TestSameNameDifferentEcosystemsStaySeparate(t *testing.T) {
	store := mock.VulnerabilityProvider(
		vulnerability.Vulnerability{
			Reference:   vulnerability.Reference{ID: "PYTHON-SENTRY-1", Namespace: "github:language:python"},
			PackageName: "sentry",
			Constraint:  version.MustGetConstraint("< 2.0.0", version.UnknownFormat),
		},
		vulnerability.Vulnerability{
			Reference:   vulnerability.Reference{ID: "NPM-SENTRY-1", Namespace: "github:language:javascript"},
			PackageName: "sentry",
			Constraint:  version.MustGetConstraint("< 2.0.0", version.UnknownFormat),
		},
	)

	p := pkg.Package{Name: "sentry", Version: "1.0.0", Language: syftPkg.JavaScript, Type: syftPkg.NpmPkg}
	matches, _, err := MatchPackageByEcosystemAndCPEs(store, p, match.JavascriptMatcher, false)
	require.NoError(t, err)
	require.Len(t, matches, 1)
	assert.Equal(t, "NPM-SENTRY-1", matches[0].Vulnerability.ID)
	assert.Equal(t, "github:language:javascript", matches[0].Vulnerability.Namespace)
}

// TestComponentIdentityBeforeAfter is the acceptance fixture for the false
// positive regression. The same 20 candidate records are replayed through the
// legacy and component-identity paths.
func TestComponentIdentityBeforeAfter(t *testing.T) {
	gnuTarCPE := cpe.Must("cpe:2.3:a:gnu:tar:1.35:*:*:*:*:*:*:*", cpe.DeclaredSource)

	var falsePositives []vulnerability.Vulnerability
	for i := 0; i < 17; i++ {
		falsePositives = append(falsePositives, vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        fmt.Sprintf("GHSA-npm-tar-%02d", i),
				Namespace: "github:language:javascript",
			},
			PackageName: gnuTarName,
			Constraint:  version.MustGetConstraint("< 7.5.3", version.UnknownFormat),
		})
	}

	var truePositives []vulnerability.Vulnerability
	for i := 0; i < 3; i++ {
		truePositives = append(truePositives, vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        fmt.Sprintf("CVE-2023-398%02d", i),
				Namespace: "nvd:cpe",
			},
			PackageName: gnuTarName,
			Constraint:  version.MustGetConstraint("< 1.36", version.UnknownFormat),
			CPEs:        []cpe.CPE{gnuTarCPE},
		})
	}

	store := nameOrCPEProvider{byName: falsePositives, byCPE: truePositives}
	cpeOnly := pkg.Package{Name: gnuTarName, Version: "1.35", CPEs: []cpe.CPE{gnuTarCPE}}

	legacy, _, err := MatchPackageByEcosystemAndCPEsLegacy(store, cpeOnly, match.StockMatcher, true)
	require.NoError(t, err)
	strict, _, err := MatchPackageByEcosystemAndCPEs(store, cpeOnly, match.StockMatcher, true)
	require.NoError(t, err)

	assert.Len(t, legacy, 20, "legacy path should reproduce 17 npm FP + 3 GNU CPE findings")
	assert.Len(t, strict, 3, "component-identity path should retain only the 3 GNU CPE findings")
	assert.Equal(t, len(legacy)-len(strict), 17, "17 cross-ecosystem false positives should be removed")

	npmControl := pkg.Package{
		Name:     gnuTarName,
		Version:  "1.35.0",
		Language: syftPkg.JavaScript,
		Type:     syftPkg.NpmPkg,
		PURL:     "pkg:npm/tar@1.35.0",
	}
	npmMatches, _, err := MatchPackageByEcosystemAndCPEs(store, npmControl, match.JavascriptMatcher, false)
	require.NoError(t, err)
	assert.Len(t, npmMatches, 17, "the explicitly npm-typed positive control must retain all 17 npm findings")
}
