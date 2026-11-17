// Package component resolves the identity evidence Grype uses to decide which
// vulnerability namespaces are applicable to a cataloged package.
//
// The important distinction is between a package that carries an explicit
// ecosystem identity (a language, a package type, or a PURL that implies one)
// and a package that is only a CPE. The latter is common for `cpes:` inputs and
// hand-authored SBOMs. Without an ecosystem, a name-only database lookup would
// search every language namespace and can attach, for example, npm `tar`
// advisories to a GNU tar CPE. Identity resolution keeps that decision at the
// matcher boundary instead of filtering the report after the fact.
package component

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	grypePkg "github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// LookupMode describes the component evidence available for matching.
type LookupMode string

const (
	// LookupEcosystem means the package has language/type/PURL evidence and a
	// name lookup is restricted to that ecosystem.
	LookupEcosystem LookupMode = "ecosystem-name"

	// LookupCPEOnly means the package has CPE evidence but no ecosystem
	// evidence. Only the CPE search is applicable.
	LookupCPEOnly LookupMode = "cpe-only"

	// LookupNone means the package has neither ecosystem nor CPE evidence.
	LookupNone LookupMode = "none"
)

// Evidence records one input that contributed to the resolved identity.
type Evidence struct {
	Field  string `json:"field"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

// Identity is the audit-friendly result of component resolution.
type Identity struct {
	PackageName string     `json:"packageName"`
	Version     string     `json:"version"`
	PackageType string     `json:"packageType,omitempty"`
	Language    string     `json:"language,omitempty"`
	PURL        string     `json:"purl,omitempty"`
	LookupMode  LookupMode `json:"lookupMode"`
	Evidence    []Evidence `json:"evidence"`
}

// HasEcosystemIdentity reports whether there is explicit evidence that the
// package belongs to a language/package ecosystem.
func (i Identity) HasEcosystemIdentity() bool {
	return i.PackageType != "" || i.Language != ""
}

// Identify resolves the ecosystem identity for p. Missing type/language fields
// are backfilled from the PURL when possible, so typed SBOM inputs retain their
// ecosystem-specific matches while CPE-only inputs do not inherit one.
func Identify(p grypePkg.Package) Identity {
	return resolve(p, true)
}

// Resolve is the matcher hot-path variant of Identify. It resolves the same
// type/language/lookup mode but does not collect per-CPE audit evidence.
func Resolve(p grypePkg.Package) Identity {
	return resolve(p, false)
}

func resolve(p grypePkg.Package, includeEvidence bool) Identity {
	pkgType := knownPackageType(p.Type)
	language := knownLanguage(p.Language)

	id := Identity{
		PackageName: p.Name,
		Version:     p.Version,
		PURL:        p.PURL,
	}
	if includeEvidence {
		id.Evidence = []Evidence{}
	}

	if includeEvidence && pkgType != "" {
		id.Evidence = append(id.Evidence, Evidence{Field: "type", Value: pkgType, Source: "package"})
	}
	if includeEvidence && language != "" {
		id.Evidence = append(id.Evidence, Evidence{Field: "language", Value: language, Source: "package"})
	}

	if p.PURL != "" {
		if includeEvidence {
			id.Evidence = append(id.Evidence, Evidence{Field: "purl", Value: p.PURL, Source: "package"})
		}
		if pkgType == "" && language == "" {
			purlType := knownPackageType(syftPkg.TypeFromPURL(p.PURL))
			purlLanguage := knownLanguage(syftPkg.LanguageFromPURL(p.PURL))
			if purlType != "" {
				pkgType = purlType
				if includeEvidence {
					id.Evidence = append(id.Evidence, Evidence{Field: "type", Value: purlType, Source: "purl"})
				}
			}
			if purlLanguage != "" {
				language = purlLanguage
				if includeEvidence {
					id.Evidence = append(id.Evidence, Evidence{Field: "language", Value: purlLanguage, Source: "purl"})
				}
			}
		}
	}

	if includeEvidence {
		for _, c := range p.CPEs {
			if s := c.Attributes.BindToFmtString(); s != "" {
				id.Evidence = append(id.Evidence, Evidence{Field: "cpe", Value: s, Source: "package"})
			}
		}
	}

	id.PackageType = pkgType
	id.Language = language
	switch {
	case id.HasEcosystemIdentity():
		id.LookupMode = LookupEcosystem
	case len(p.CPEs) > 0:
		id.LookupMode = LookupCPEOnly
	default:
		id.LookupMode = LookupNone
	}

	return id
}

// ApplyTo returns a copy of p with the resolved ecosystem fields filled in.
// It never overwrites identity fields already set by the cataloger.
func (i Identity) ApplyTo(p grypePkg.Package) grypePkg.Package {
	if p.Type == "" || p.Type == syftPkg.UnknownPkg {
		if i.PackageType != "" {
			p.Type = syftPkg.Type(i.PackageType)
		}
	}
	if p.Language == "" || p.Language == syftPkg.UnknownLanguage {
		if i.Language != "" {
			p.Language = syftPkg.Language(i.Language)
		}
	}
	return p
}

// Explain renders a compact human-readable identity reason for logs and
// operator-facing audit output.
func (i Identity) Explain() string {
	var parts []string
	if i.PackageType != "" {
		parts = append(parts, "type="+i.PackageType)
	}
	if i.Language != "" {
		parts = append(parts, "language="+i.Language)
	}
	if i.PURL != "" {
		parts = append(parts, "purl="+i.PURL)
	}
	if len(parts) == 0 {
		parts = append(parts, "no ecosystem evidence")
	}
	return fmt.Sprintf("%s@%s lookup=%s (%s)", i.PackageName, i.Version, i.LookupMode, strings.Join(parts, ", "))
}

// AuditDocument is the stable JSON shape exported for audit.
type AuditDocument struct {
	SchemaVersion int        `json:"schemaVersion"`
	Components    []Identity `json:"components"`
}

// WriteAudit exports component identity evidence as deterministic JSON.
func WriteAudit(w io.Writer, identities []Identity) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(AuditDocument{
		SchemaVersion: 1,
		Components:    identities,
	})
}

func knownPackageType(t syftPkg.Type) string {
	// `binary` describes how the component was cataloged, not an ecosystem.
	// Treating it as one would still allow a name-only lookup to run for a
	// package whose only real identity evidence is a CPE.
	if t == "" || t == syftPkg.UnknownPkg || t == syftPkg.BinaryPkg {
		return ""
	}
	return string(t)
}

func knownLanguage(l syftPkg.Language) string {
	if l == "" || l == syftPkg.UnknownLanguage {
		return ""
	}
	return string(l)
}
