package internal

import (
	"errors"

	"github.com/anchore/grype/grype/component"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// MatchPackageByEcosystemAndCPEs runs the ecosystem-by-name search (via
// MatchPackageByLanguage, which handles the multi-name fanout and cross-name
// NAK Remove internally) and, if enabled, the CPE search, then combines the
// results.
func MatchPackageByEcosystemAndCPEs(store vulnerability.Provider, p pkg.Package, matcher match.MatcherType, includeCPEs bool) ([]match.Match, []match.IgnoreFilter, error) {
	return matchPackageByEcosystemAndCPEs(store, p, matcher, includeCPEs, true)
}

// MatchPackageByEcosystemAndCPEsLegacy preserves the pre-component-identity
// behavior, where a package with no language/type still searched every language
// namespace by name. It exists only as an operator-controlled rollback path.
func MatchPackageByEcosystemAndCPEsLegacy(store vulnerability.Provider, p pkg.Package, matcher match.MatcherType, includeCPEs bool) ([]match.Match, []match.IgnoreFilter, error) {
	return matchPackageByEcosystemAndCPEs(store, p, matcher, includeCPEs, false)
}

func matchPackageByEcosystemAndCPEs(store vulnerability.Provider, p pkg.Package, matcher match.MatcherType, includeCPEs, requireEcosystem bool) ([]match.Match, []match.IgnoreFilter, error) {
	var matches []match.Match
	var ignored []match.IgnoreFilter

	identity := component.Resolve(p)
	if !requireEcosystem || identity.HasEcosystemIdentity() {
		var err error
		matches, ignored, err = MatchPackageByLanguage(store, identity.ApplyTo(p), matcher)
		if err != nil {
			log.Debugf("could not match by package ecosystem (package=%+v): %v", p, err)
		}
	} else {
		// A CPE-only component has no language or package-type evidence. A
		// name-only lookup would search every language namespace and can bind
		// unrelated advisories (for example npm `tar`) to a GNU tar CPE.
		log.WithFields("package", p.Name, "lookup", identity.LookupMode).
			Debug("skipping ecosystem name lookup for component without ecosystem evidence")
	}

	if includeCPEs {
		cpeMatches, cpeIgnores, cpeErr := MatchPackageByCPEs(store, p, matcher)
		switch {
		case errors.Is(cpeErr, ErrEmptyCPEMatch):
			log.Debugf("attempted CPE search on %s, which has no CPEs. Consider re-running with --add-cpes-if-none", p.Name)
		case cpeErr != nil:
			log.Debugf("could not match by package CPE (package=%+v): %v", p, cpeErr)
		}
		matches = append(matches, cpeMatches...)
		ignored = append(ignored, cpeIgnores...)
	}

	return matches, ignored, nil
}

// hasLanguageEcosystem reports whether the package declares a language
// ecosystem. CPE-only inputs have an empty or unknown language.
func hasLanguageEcosystem(p pkg.Package) bool {
	return p.Language != "" && p.Language != syftPkg.UnknownLanguage
}
