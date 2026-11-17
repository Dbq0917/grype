package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunReconcileIgnores(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.json")
	ignorePath := filepath.Join(dir, "ignore.yaml")
	outputPath := filepath.Join(dir, "migration.json")

	report := `{
	  "matches": [
	    {
	      "vulnerability": {"id": "CVE-2023-0002", "namespace": "nvd:cpe", "fix": {"state": "not-fixed"}},
	      "relatedVulnerabilities": [],
	      "artifact": {"name": "tar", "version": "1.35", "type": "binary", "language": "", "purl": ""},
	      "matchDetails": [{"type": "cpe-match"}]
	    }
	  ],
	  "ignoredMatches": []
	}`
	ignore := `ignore:
  - vulnerability: CVE-2023-0001
    reason: historical cross-ecosystem false positive
    package:
      name: tar
  - vulnerability: CVE-2023-0002
    reason: accepted until GNU tar upgrade
    package:
      name: tar
      version: "1.35"
`
	require.NoError(t, os.WriteFile(reportPath, []byte(report), 0o600))
	require.NoError(t, os.WriteFile(ignorePath, []byte(ignore), 0o600))

	require.NoError(t, runReconcileIgnores(&componentAuditOptions{
		ReportPath: reportPath,
		IgnorePath: ignorePath,
		OutputPath: outputPath,
	}))

	out, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	assert.Contains(t, string(out), `"action": "retire"`)
	assert.Contains(t, string(out), `"action": "retain"`)
	assert.Contains(t, string(out), `"reason": "accepted until GNU tar upgrade"`)
	assert.Contains(t, string(out), `"vulnerabilityId": "CVE-2023-0002"`)
}
