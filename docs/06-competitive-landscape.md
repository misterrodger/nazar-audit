# Competitive Landscape

How nazar-audit compares to existing tools in the JavaScript package vulnerability scanning space.

## Tool Tiers

### Commercial Platforms

**Snyk** -- The most complete commercial SCA solution. Proprietary vulnerability database with dedicated security research team. Auto-fix PRs, reachability analysis, SAST + SCA + container + IaC in one tool. Requires an account; commercial at scale.

**Socket.dev** -- Uniquely focused on supply chain *behavior* analysis rather than known-CVE matching. 70+ risk signals including malware detection, typosquatting, install script analysis, obfuscated code detection. Detects attacks that have no CVE yet. Install-time blocking via Firewall proxy.

### Multi-Ecosystem OSS Scanners

**OSV-Scanner (Google)** -- Free, open-source, queries the largest aggregated vulnerability database (OSV.dev, 30+ sources). Best guided remediation: analyzes dependency graphs and recommends prioritized upgrades by ROI. Output formats include SARIF, CycloneDX, SPDX, and interactive HTML.

**Trivy (Aqua Security)** -- Broadest scan target coverage: containers, filesystems, git repos, Kubernetes clusters. Combines vuln scanning + IaC misconfiguration + secret detection + license compliance + SBOM generation in one binary.

**Grype (Anchore)** -- SBOM-first vulnerability scanner. Best risk prioritization with EPSS probability scores + CISA KEV (Known Exploited Vulnerabilities). Flexible output templating via Go templates.

### npm Audit Wrappers (Direct Competitors)

**better-npm-audit** -- `.nsprc` exception management with expiry dates, module-level ignoring, table filtering. Unmaintained since Sep 2024, has a critical RCE vulnerability (command injection via `--registry`), npm-only, no JSON output.

**audit-ci (IBM)** -- Most feature-complete CI gate: supports npm/Yarn/pnpm/Bun, rich JSONC allowlist with JSON Schema, expiry/notes per entry. CI-only (no interactive mode), limited output formats, no fix availability display.

**npm-audit-resolver** -- Best interactive triage workflow with per-path decision tracking in `audit-resolve.json`. Git-traceable audit trail. npm-only, no structured output, aging codebase.

### Niche Tools

**retire.js** -- Uniquely scans browser-side JS (via Chrome/Firefox extension) and vendored `.js` files committed to source control but not managed by package managers. CycloneDX SBOM generation.

**lockfile-lint** -- Uniquely addresses lockfile tampering/injection attacks: validates resolved URLs, registry sources, integrity hashes, and package name matching. Complementary to CVE scanners.

## Feature Comparison

| Feature | nazar-audit | npm audit | better-npm-audit | audit-ci | npm-audit-resolver | Snyk | OSV-Scanner |
|---|---|---|---|---|---|---|---|
| npm support | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| pnpm support | Planned (P1) | No | No | Yes | No | Yes | Yes |
| Yarn support | Planned (P1) | No | No | Yes | No | Yes | Yes |
| Bun support | Planned (P1) | No | No | Yes | No | No | Yes |
| Exception management | Yes | No | Yes | Yes | Yes | Yes (.snyk) | Yes (.toml) |
| Expiry on exceptions | Yes | No | Yes | Yes | Yes | Yes | Yes |
| Path-specific exceptions | Planned (P1) | No | No | Yes | Yes | No | No |
| Module-level ignoring | Yes | No | Yes | Yes | No | No | Yes |
| JSON output | Yes | Yes | No | Yes | No | Yes | Yes |
| SARIF output | Planned (P1) | No | No | No | No | Yes | Yes |
| Fix availability display | Yes | Partial | No | No | No | Yes | Yes |
| Table severity filtering | Yes | No | Yes | No | No | No | No |
| Interactive triage | Planned (P1) | No | No | No | Yes | No | No |
| Guided remediation | Planned (P2) | No | No | No | No | Yes | Yes |
| License scanning | Planned (P2) | No | No | No | No | Yes | Experimental |
| SBOM support | Planned (P2) | No | No | No | No | Yes | Yes |
| Lockfile validation | Planned (P2) | No | No | No | No | No | No |
| Reachability analysis | Planned (P2) | No | No | No | No | Yes | Yes (Go/Rust) |
| Supply chain signals | Planned (P3) | No | No | No | No | Partial | No |
| Secure implementation | Yes (execFile) | N/A | No (exec, RCE) | Yes | Unknown | Yes | Yes |
| Zero/minimal deps | Goal | N/A | 5 deps | ~10 deps | ~5 deps | Heavy | Go binary |

## The Gap nazar-audit Fills

No single tool offers all of:
- Lightweight, zero/minimal-dependency CLI
- Multi-package-manager support (npm + pnpm + Yarn + Bun)
- Rich exception management with expiry, path-specificity, and interactive workflow
- Multiple output formats including SARIF
- Fix availability display with upgrade path guidance
- Both local dev and CI/CD optimized
- Lockfile integrity validation
- Security-conscious implementation (no shell injection, no deprecated deps)
