package dpkg

import (
	"errors"
	"fmt"

	"github.com/anchore/grype/grype/internal/ignorereasons"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
	cfg MatcherConfig
}

type MatcherConfig struct {
	MissingEpochStrategy version.MissingEpochStrategy
	UseCPEsForEOL        bool
	UseCPEs              bool
}

func NewDpkgMatcher(cfg MatcherConfig) *Matcher {
	return &Matcher{
		cfg: cfg,
	}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.DebPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.DpkgMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	var matches []match.Match
	var ignores []match.IgnoreFilter
	// distroVulnerable and distroFixed are the authoritative distro feed's verdict for this package
	// (and its upstreams). They reconcile the NVD/CPE results so that backported fixes are not
	// re-reported as vulnerable based on upstream version numbers.
	var distroVulnerable, distroFixed result.Set

	// Ubuntu ESM (Pro) distros need a two-pass disclosure/resolution match to resolve base disclosures against
	// ESM-channel fixes, covering both the binary and its source packages. Non-ESM dpkg scans keep the standard path.
	if shouldUseUbuntuESMMatching(p.Distro) {
		esmVulnerable, esmFixed, esmIgnores, err := m.matchUbuntuESM(store, p)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to match Ubuntu ESM: %w", err)
		}
		ignores = append(ignores, esmIgnores...)
		distroVulnerable, distroFixed = esmVulnerable, esmFixed
	} else {
		upstreamVulnerable, upstreamFixed, upstreamIgnores, err := m.matchUpstreamPackages(store, p)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to match by source indirection: %w", err)
		}
		distroVulnerable = distroVulnerable.Merge(upstreamVulnerable)
		distroFixed = distroFixed.Merge(upstreamFixed)
		ignores = append(ignores, upstreamIgnores...)

		versionConfig := version.ComparisonConfig{
			MissingEpochStrategy: m.cfg.MissingEpochStrategy,
		}
		exactVulnerable, exactFixed, err := internal.FindResultsByDistro(store, p, nil, m.Type(), &versionConfig)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to match by exact package name: %w", err)
		}
		distroVulnerable = distroVulnerable.Merge(exactVulnerable)
		distroFixed = distroFixed.Merge(exactFixed)
		ignores = append(ignores, internal.OwnershipIgnores(p, ignorereasons.DistroFixed, exactFixed.Vulnerabilities()...)...)
	}

	matches = append(matches, distroVulnerable.ToMatches()...)

	// if configured, also search by CPEs, either for every package or only for packages from EOL distros
	searchByCPE := m.cfg.UseCPEs
	if !searchByCPE && m.cfg.UseCPEsForEOL && internal.IsDistroEOL(store, p.Distro) {
		log.WithFields("package", p.Name, "distro", p.Distro).Debug("distro is EOL, searching by CPEs")
		searchByCPE = true
	}

	if searchByCPE {
		cpeVulnerable, cpeIgnores, err := internal.FindResultsByCPEs(store, p, m.Type())
		switch {
		case errors.Is(err, internal.ErrEmptyCPEMatch):
			log.WithFields("package", p.Name).Debug("package has no CPEs to match by")
		case err != nil:
			log.WithFields("package", p.Name, "error", err).Debug("failed to match by CPEs")
		default:
			reconciledMatches, reconciledIgnores := internal.ReconcileCPEResults(cpeVulnerable, distroVulnerable, distroFixed, cpeIgnores)
			matches = append(matches, reconciledMatches...)
			ignores = append(ignores, reconciledIgnores...)
		}
	}

	return matches, ignores, nil
}

// matchUbuntuESM matches an Ubuntu Pro/ESM package using the two-pass disclosure/resolution search, covering both
// the binary package and each of its source (upstream) packages. Ubuntu vulnerability data is source-keyed, so the
// upstream pass is what actually resolves most fixes. The shared result provider is built from the binary package p,
// so upstream matches are automatically recorded as indirect (and keyed to p) by the result detail logic.
func (m *Matcher) matchUbuntuESM(store vulnerability.Provider, p pkg.Package) (result.Set, result.Set, []match.IgnoreFilter, error) {
	provider := result.NewProvider(store, p, m.Type())

	vulnerable, fixed, ignores, err := ubuntuESMMatches(provider, p, m.cfg.MissingEpochStrategy)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to match by exact package name: %w", err)
	}

	for _, indirectPackage := range pkg.UpstreamPackages(p) {
		indirectVulnerable, indirectFixed, indirectIgnores, err := ubuntuESMMatches(provider, indirectPackage, m.cfg.MissingEpochStrategy)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to find vulnerabilities for dpkg upstream source package: %w", err)
		}
		vulnerable = vulnerable.Merge(markIndirect(indirectVulnerable, p))
		fixed = fixed.Merge(indirectFixed)
		ignores = append(ignores, indirectIgnores...)
	}

	return vulnerable, fixed, ignores, nil
}

func (m *Matcher) matchUpstreamPackages(store vulnerability.Provider, p pkg.Package) (result.Set, result.Set, []match.IgnoreFilter, error) {
	vulnerable := result.Set{}
	fixed := result.Set{}
	var ignores []match.IgnoreFilter

	versionConfig := version.ComparisonConfig{
		MissingEpochStrategy: m.cfg.MissingEpochStrategy,
	}
	for _, indirectPackage := range pkg.UpstreamPackages(p) {
		indirectVulnerable, indirectFixed, err := internal.FindResultsByDistro(store, indirectPackage, &p, m.Type(), &versionConfig)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to find vulnerabilities for dpkg upstream source package: %w", err)
		}
		vulnerable = vulnerable.Merge(markIndirect(indirectVulnerable, p))
		fixed = fixed.Merge(indirectFixed)
		// ownership ignores still point at the SBOM package p, matching the previous MatchPackageByDistro behavior
		ignores = append(ignores, internal.OwnershipIgnores(p, ignorereasons.DistroFixed, indirectFixed.Vulnerabilities()...)...)
	}

	return vulnerable, fixed, ignores, nil
}

// markIndirect records upstream/source results against the SBOM (catalog) package and marks their
// evidence indirect, the result.Set equivalent of match.ConvertToIndirectMatches.
func markIndirect(s result.Set, catalogPkg pkg.Package) result.Set {
	return s.Map(func(r *result.Result) {
		r.Package = &catalogPkg
		details := make([]match.Detail, len(r.Details))
		for i, d := range r.Details {
			if d.Type == match.ExactDirectMatch {
				d.Type = match.ExactIndirectMatch
			}
			details[i] = d
		}
		r.Details = details
	})
}
