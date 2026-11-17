# Component Identity Matching

## Owner and acceptance

- Owner: Grype matcher maintainers (`@anchore/grype` maintainers)
- Operational escalation: security tooling on-call for the release-gate deployment
- Acceptance date: 2026-12-02
- Regression command: `make test-component-identity`

## Problem

The stock matcher used to run an ecosystem-by-name lookup for every cataloged
package. When a package had no language, package type, or PURL evidence, that
lookup had no ecosystem constraint and searched every language namespace. A
GNU tar CPE could therefore collect npm `tar` advisories, and a CLI-only input
could inherit findings for a library with the same product name.

The fix is in component identification, before the vulnerability lookup, not in
the report presenter or an ignore list.

## Resolution rules

| Package evidence | Lookup |
| --- | --- |
| Type, language, or PURL implies an ecosystem | Name lookup restricted to that ecosystem, plus CPE lookup when enabled |
| CPE only, no ecosystem evidence | CPE lookup only |
| No ecosystem and no CPE | No name or CPE lookup |

The matcher never infers an ecosystem from a package-name prefix. A PURL is the
only fallback used to backfill missing type/language fields. `binary` describes
how a component was cataloged, not an ecosystem, so a binary package with only a
CPE follows the CPE-only path.

## Report traceability

Every retained match keeps its existing `matchDetails` evidence:

- CPE findings carry `searchedBy.cpes` and the matched CPE record.
- Ecosystem findings carry the language namespace and searched package name.
- JSON report field names and shapes are unchanged.

To export the component evidence used for every scanned package:

```sh
grype <target> --component-identity-output component-identity.json
```

The output is deterministic JSON with `schemaVersion`, package identity,
resolved lookup mode, and every contributing type/language/PURL/CPE value.

## Historical ignore migration

`grype/component.ReconcileIgnoreRules` replays raw matches against the existing
ignore rules. Each rule receives one disposition:

- `retire`: no raw match remains, so the whitelist entry can be removed.
- `retain`: the rule still suppresses at least one raw match; the output
  includes the vulnerability, namespace, package, and match type evidence.
- `review`: VEX rules and empty rules cannot be auto-retired.

A retained rule keeps its configured reason. If it has none, `needsReason` is
set and the report explains that a reason is required for audit. Use
`component.WriteIgnoreDispositions` to write the migration report as JSON.

Rules whose matcher false positives disappeared are retired automatically;
rules that still cover a real finding are never removed automatically.

Run the migration against a report produced with suppressed matches included:

```sh
grype <target> -o json --show-suppressed > report.json
grype component-audit reconcile-ignores \
  --report report.json \
  --ignore-file .grype.yaml \
  --output ignore-migration.json
```

The command reads the historical `ignore:` block from `.grype.yaml`, combines
`matches` and `ignoredMatches` into the raw match set, and writes one
disposition per rule. A rule with no remaining raw match is marked `retire`;
every retained rule carries the package, namespace, vulnerability, and match
type that still require it.

## Rollout, canary, and rollback

The strict behavior is the default. For a canary:

1. Run the scan with `--component-identity-output` on a small release-gate
   target.
2. Confirm removed findings are all cross-ecosystem name matches, not CPE
   findings.
3. Run the same target through the full gate before widening.

Rollback is a configuration change, not a binary rollback:

```yaml
match:
  stock:
    allow-ecosystemless-name-matching: true
```

This restores the legacy behavior for a package with no ecosystem evidence.
Remove the setting to re-enable strict component identity. No database rebuild
is needed, and the rollback takes effect on the next scan.

## Performance

The strict path removes a database name lookup for CPE-only packages, so it
does not add work to the matching chain. PURL parsing is only performed when
type and language are both missing. Existing typed packages follow the same
single ecosystem lookup as before.

Local microbenchmark (`go test ./grype/component -run '^$' -bench BenchmarkResolve -benchmem`):

| Case | Time | Allocations |
| --- | ---: | ---: |
| Typed package | 13.43 ns/op | 0 |
| CPE-only package | 20.09 ns/op | 0 |

These are identity-resolution costs only; the removed CPE-only name lookup is a
database query and dominates them.

## Acceptance data

The regression fixture replays 20 candidate records through both paths:

| Scenario | Before | After | Expected |
| --- | ---: | ---: | --- |
| GNU tar CPE with npm `tar` advisories | 20 | 3 | 17 cross-ecosystem findings removed; 3 GNU CPE findings retained |
| CPE-only false positives | 17 | 0 | all cross-ecosystem findings eliminated |
| GNU CPE true positives | 3 | 3 | unchanged |
| Explicit npm `tar` positive control | 17 | 17 | unchanged |

The assertions live in:

- `grype/matcher/internal/common_test.go`
- `grype/component/identity_test.go`
- `grype/component/ignore_reconcile_test.go`

## Continuous verification

`make test-component-identity` runs the component and matcher regression suites.
The same command is suitable for the release-gate job. It requires no live
database or network access because the fixture supplies both the language and
CPE records.
