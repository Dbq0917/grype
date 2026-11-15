package dpkg

import (
	"testing"

	"github.com/anchore/grype/grype/internal/ignorereasons"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	"github.com/anchore/syft/syft/artifact"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcherDpkg_DirectMatch(t *testing.T) {
	dbtest.SharedDBs(t, "all").
		SelectOnly("debian:11/CVE-2024-0727").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}

			p := dbtest.NewPackage("openssl", "1.1.1k-1", syftPkg.DebPkg). // vulnerable (< 1.1.1w-0+deb11u2)
											WithDistro(dbtest.Debian11).
											Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2024-0727").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

func TestMatcherDpkg_IndirectMatch(t *testing.T) {
	dbtest.SharedDBs(t, "all").
		SelectOnly("debian:11/CVE-2024-0727").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}

			// binary package libssl3 with upstream openssl
			p := dbtest.NewPackage("libssl3", "1.1.1k-1", syftPkg.DebPkg). // vulnerable
											WithDistro(dbtest.Debian11).
											WithUpstream("openssl", "").
											Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2024-0727").
				SelectDetailByType(match.ExactIndirectMatch).
				AsDistroSearch()
		})
}

func TestMatcherDpkg_CPEFallbackWhenEOL(t *testing.T) {
	p := dbtest.NewPackage("openssl", "1.1.1k", syftPkg.DebPkg). // vulnerable
									WithDistro(dbtest.Debian8).
									WithCPE("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*").
									Build()

	tests := []struct {
		name             string
		useCPEsForEOL    bool
		expectCPEMatches bool
	}{
		{
			name:             "CPE fallback enabled and distro is EOL",
			useCPEsForEOL:    true,
			expectCPEMatches: true,
		},
		{
			name:             "CPE fallback disabled and distro is EOL",
			useCPEsForEOL:    false,
			expectCPEMatches: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// use the local EOL fixture that has Debian 8 EOL date set
			dbtest.DBs(t, "eol-debian8").Run(func(t *testing.T, db *dbtest.DB) {
				matcher := NewDpkgMatcher(MatcherConfig{
					UseCPEsForEOL: tt.useCPEsForEOL,
				})

				findings := db.Match(t, matcher, p)

				if tt.expectCPEMatches {
					findings.
						ContainsVulnerabilities("CVE-2024-0727").
						SelectMatch("CVE-2024-0727").
						SelectDetailByType(match.CPEMatch).
						AsCPESearch().
						FoundCPEs("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*")
				} else {
					findings.IsEmpty()
				}
			})
		})
	}
}

func TestMatcherDpkg_CPEMatchingWhenEnabled(t *testing.T) {
	// a package from a third-party apt repository: the distro feed has no record for it, only NVD does
	p := dbtest.NewPackage("vendor-openssl", "1.1.1k", syftPkg.DebPkg). // vulnerable
										WithDistro(dbtest.Debian12).
										WithCPE("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*").
										Build()

	tests := []struct {
		name             string
		useCPEs          bool
		expectCPEMatches bool
	}{
		{
			name:             "CPE matching enabled and distro is not EOL",
			useCPEs:          true,
			expectCPEMatches: true,
		},
		{
			name:             "CPE matching disabled and distro is not EOL",
			useCPEs:          false,
			expectCPEMatches: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbtest.SharedDBs(t, "all").
				SelectOnly("CVE-2024-0727").
				Run(func(t *testing.T, db *dbtest.DB) {
					matcher := NewDpkgMatcher(MatcherConfig{
						UseCPEs: tt.useCPEs,
					})

					findings := db.Match(t, matcher, p)

					if tt.expectCPEMatches {
						findings.
							ContainsVulnerabilities("CVE-2024-0727").
							SelectMatch("CVE-2024-0727").
							SelectDetailByType(match.CPEMatch).
							AsCPESearch().
							FoundCPEs("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*")
					} else {
						findings.IsEmpty()
					}
				})
		})
	}
}

// TestMatcherDpkg_NvdDroppedWhenDistroHasBackportFix covers the backport false-positive the distro
// feed exists to settle. Debian 11 ships the CVE-2024-0727 fix on the frozen 1.1.1w line as
// 1.1.1w-0+deb11u2, but NVD only knows upstream version numbers and still considers every 1.1.1
// release below 1.1.1x vulnerable. With CPE matching on, the NVD CPE finding must be reconciled away
// against the distro "fixed" verdict instead of being reported as a second, false finding. The only
// trace is a distro-fixed ignore, so nothing is silently dropped.
func TestMatcherDpkg_NvdDroppedWhenDistroHasBackportFix(t *testing.T) {
	dbtest.SharedDBs(t, "all").
		SelectOnly("debian:11/CVE-2024-0727", "CVE-2024-0727").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := NewDpkgMatcher(MatcherConfig{UseCPEs: true})

			pkgID := pkg.ID("openssl-backport-fixed")
			p := dbtest.NewPackage("openssl", "1.1.1w-0+deb11u2", syftPkg.DebPkg). // at the Debian backport fix
												WithID(pkgID).
												WithDistro(dbtest.Debian11).
												WithCPE("cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*").
												Build()

			// no distro match (the package is at/above the fix) and no NVD CPE match (reconciled away).
			// The suppressed finding is still surfaced as a distro-fixed ignore rather than dropped
			// silently; asserting the ignore also enforces that zero matches were produced.
			findings := db.Match(t, matcher, p)
			findings.Ignores().
				SelectRelatedPackageIgnore(ignorereasons.DistroFixed, "CVE-2024-0727").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

// TestMatcherDpkg_NvdKeptWhenDistroFeedIsSilent verifies the reconciliation does not over-suppress:
// a third-party package the distro feed has no record for is still matched purely from NVD via CPE,
// because there is no distro verdict to defer to.
func TestMatcherDpkg_NvdKeptWhenDistroFeedIsSilent(t *testing.T) {
	p := dbtest.NewPackage("vendor-openssl", "1.1.1k", syftPkg.DebPkg).
		WithDistro(dbtest.Debian11).
		WithCPE("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*").
		Build()

	dbtest.SharedDBs(t, "all").
		SelectOnly("CVE-2024-0727").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := NewDpkgMatcher(MatcherConfig{UseCPEs: true})

			db.Match(t, matcher, p).
				SelectMatch("CVE-2024-0727").
				SelectDetailByType(match.CPEMatch).
				AsCPESearch()
		})
}
