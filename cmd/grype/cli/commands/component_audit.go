package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/component"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type componentAuditOptions struct {
	ReportPath string `yaml:"report" json:"report" mapstructure:"report"`
	IgnorePath string `yaml:"ignore-file" json:"ignore-file" mapstructure:"ignore-file"`
	OutputPath string `yaml:"output" json:"output" mapstructure:"output"`
}

// ComponentAudit exposes operator tooling for component-identity evidence and
// historical ignore-rule migration.
func ComponentAudit(app clio.Application) *cobra.Command {
	opts := &componentAuditOptions{}

	cmd := &cobra.Command{
		Use:   "component-audit",
		Short: "Inspect component identity evidence and migrate historical ignore rules",
	}
	cmd.PersistentFlags().StringVar(&opts.ReportPath, "report", "", "grype JSON report produced with --show-suppressed")
	cmd.PersistentFlags().StringVar(&opts.IgnorePath, "ignore-file", "", "YAML file containing historical ignore rules")
	cmd.PersistentFlags().StringVar(&opts.OutputPath, "output", "", "write the migration report to this file instead of stdout")

	reconcile := &cobra.Command{
		Use:   "reconcile-ignores",
		Short: "Replay historical ignore rules against a raw scan report",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if opts.ReportPath == "" {
				return fmt.Errorf("--report is required")
			}
			if opts.IgnorePath == "" {
				return fmt.Errorf("--ignore-file is required")
			}
			return runReconcileIgnores(opts)
		},
	}

	cmd.AddCommand(reconcile)
	return app.SetupCommand(cmd)
}

func runReconcileIgnores(opts *componentAuditOptions) error {
	reportBytes, err := os.ReadFile(opts.ReportPath)
	if err != nil {
		return fmt.Errorf("unable to read report: %w", err)
	}

	rawMatches, err := rawMatchesFromReport(reportBytes)
	if err != nil {
		return err
	}

	ignoreBytes, err := os.ReadFile(opts.IgnorePath)
	if err != nil {
		return fmt.Errorf("unable to read ignore file: %w", err)
	}
	var ignoreDoc struct {
		Ignore []match.IgnoreRule `yaml:"ignore"`
	}
	if err := yaml.Unmarshal(ignoreBytes, &ignoreDoc); err != nil {
		return fmt.Errorf("unable to parse ignore file: %w", err)
	}

	dispositions := component.ReconcileIgnoreRules(ignoreDoc.Ignore, rawMatches)

	var out io.Writer = os.Stdout
	if opts.OutputPath != "" {
		f, err := os.Create(opts.OutputPath)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}
	return component.WriteIgnoreDispositions(out, dispositions)
}

type auditReport struct {
	Matches        []auditMatch `json:"matches"`
	IgnoredMatches []auditMatch `json:"ignoredMatches"`
}

type auditMatch struct {
	Vulnerability struct {
		ID        string `json:"id"`
		Namespace string `json:"namespace"`
		Fix       struct {
			State string `json:"state"`
		} `json:"fix"`
	} `json:"vulnerability"`
	RelatedVulnerabilities []struct {
		ID string `json:"id"`
	} `json:"relatedVulnerabilities"`
	Artifact struct {
		Name      string                `json:"name"`
		Version   string                `json:"version"`
		Type      syftPkg.Type          `json:"type"`
		Language  syftPkg.Language      `json:"language"`
		PURL      string                `json:"purl"`
		Upstreams []pkg.UpstreamPackage `json:"upstreams"`
	} `json:"artifact"`
	MatchDetails []struct {
		Type string `json:"type"`
	} `json:"matchDetails"`
}

func rawMatchesFromReport(reportBytes []byte) ([]match.Match, error) {
	var report auditReport
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		return nil, fmt.Errorf("unable to parse report: %w", err)
	}

	all := make([]auditMatch, 0, len(report.Matches)+len(report.IgnoredMatches))
	all = append(all, report.Matches...)
	all = append(all, report.IgnoredMatches...)

	out := make([]match.Match, 0, len(all))
	for _, m := range all {
		vuln := vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        m.Vulnerability.ID,
				Namespace: m.Vulnerability.Namespace,
			},
			Fix: vulnerability.Fix{State: vulnerability.FixState(m.Vulnerability.Fix.State)},
		}
		for _, related := range m.RelatedVulnerabilities {
			vuln.RelatedVulnerabilities = append(vuln.RelatedVulnerabilities, vulnerability.Reference{ID: related.ID})
		}

		var details match.Details
		for _, d := range m.MatchDetails {
			details = append(details, match.Detail{Type: match.Type(d.Type)})
		}

		out = append(out, match.Match{
			Vulnerability: vuln,
			Package: pkg.Package{
				Name:      m.Artifact.Name,
				Version:   m.Artifact.Version,
				Type:      m.Artifact.Type,
				Language:  m.Artifact.Language,
				PURL:      m.Artifact.PURL,
				Upstreams: m.Artifact.Upstreams,
			},
			Details: details,
		})
	}

	return out, nil
}
