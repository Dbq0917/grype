package component

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestIdentify(t *testing.T) {
	gnuTarCPE := cpe.Must("cpe:2.3:a:gnu:tar:1.35:*:*:*:*:*:*:*", cpe.DeclaredSource)

	tests := []struct {
		name       string
		pkg        grypePkg.Package
		mode       LookupMode
		pkgType    string
		language   string
		hasEcosys  bool
		evidenceOf string
	}{
		{
			name: "typed package keeps cataloger identity",
			pkg: grypePkg.Package{
				Name: "tar", Version: "1.35.0",
				Type: syftPkg.NpmPkg, Language: syftPkg.JavaScript,
			},
			mode:      LookupEcosystem,
			pkgType:   string(syftPkg.NpmPkg),
			language:  string(syftPkg.JavaScript),
			hasEcosys: true, evidenceOf: "package",
		},
		{
			name: "purl backfills missing ecosystem fields",
			pkg: grypePkg.Package{
				Name: "tar", Version: "1.35.0",
				PURL: "pkg:npm/tar@1.35.0",
			},
			mode:      LookupEcosystem,
			pkgType:   string(syftPkg.NpmPkg),
			language:  string(syftPkg.JavaScript),
			hasEcosys: true, evidenceOf: "purl",
		},
		{
			name: "cpe-only has no ecosystem identity",
			pkg: grypePkg.Package{
				Name: "tar", Version: "1.35",
				CPEs: []cpe.CPE{gnuTarCPE},
			},
			mode:      LookupCPEOnly,
			hasEcosys: false, evidenceOf: "cpe",
		},
		{
			name: "binary type is not an ecosystem",
			pkg: grypePkg.Package{
				Name: "tar", Version: "1.35", Type: syftPkg.BinaryPkg,
				CPEs: []cpe.CPE{gnuTarCPE},
			},
			mode:      LookupCPEOnly,
			hasEcosys: false, evidenceOf: "cpe",
		},
		{
			name:      "blank package has no identity evidence",
			pkg:       grypePkg.Package{Name: "tar", Version: "1.35"},
			mode:      LookupNone,
			hasEcosys: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := Identify(tt.pkg)
			assert.Equal(t, tt.mode, id.LookupMode)
			assert.Equal(t, tt.pkgType, id.PackageType)
			assert.Equal(t, tt.language, id.Language)
			assert.Equal(t, tt.hasEcosys, id.HasEcosystemIdentity())
			if tt.evidenceOf != "" {
				found := false
				for _, e := range id.Evidence {
					if e.Source == tt.evidenceOf || e.Field == tt.evidenceOf {
						found = true
					}
				}
				assert.True(t, found, "expected evidence from %q: %+v", tt.evidenceOf, id.Evidence)
			}

			applied := id.ApplyTo(tt.pkg)
			if tt.pkgType != "" && tt.pkg.Type == "" {
				assert.Equal(t, syftPkg.Type(tt.pkgType), applied.Type)
			}
			if tt.language != "" && tt.pkg.Language == "" {
				assert.Equal(t, syftPkg.Language(tt.language), applied.Language)
			}
		})
	}
}

func TestWriteAudit(t *testing.T) {
	id := Identify(grypePkg.Package{
		Name: "tar", Version: "1.35",
		CPEs: []cpe.CPE{cpe.Must("cpe:2.3:a:gnu:tar:1.35:*:*:*:*:*:*:*", cpe.DeclaredSource)},
	})

	var out bytes.Buffer
	require.NoError(t, WriteAudit(&out, []Identity{id}))

	audit := out.String()
	assert.Contains(t, audit, `"schemaVersion": 1`)
	assert.Contains(t, audit, `"lookupMode": "cpe-only"`)
	assert.Contains(t, audit, `"field": "cpe"`)
	assert.True(t, strings.Contains(audit, "cpe:2.3:a:gnu:tar:1.35"))
}

func BenchmarkResolveTyped(b *testing.B) {
	p := grypePkg.Package{
		Name: "tar", Version: "1.35.0",
		Type: syftPkg.NpmPkg, Language: syftPkg.JavaScript,
		PURL: "pkg:npm/tar@1.35.0",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Resolve(p)
	}
}

func BenchmarkResolveCPEOnly(b *testing.B) {
	p := grypePkg.Package{
		Name: "tar", Version: "1.35",
		CPEs: []cpe.CPE{cpe.Must("cpe:2.3:a:gnu:tar:1.35:*:*:*:*:*:*:*", cpe.DeclaredSource)},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Resolve(p)
	}
}
