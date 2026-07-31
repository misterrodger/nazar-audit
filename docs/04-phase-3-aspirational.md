# Phase 3: Aspirational

Long-term features that push nazar-audit beyond a traditional vulnerability scanner.

## P3.1 Supply Chain Risk Signals

Behavioral analysis inspired by Socket.dev's 70+ risk signals:

- **Install scripts** -- flag packages with `preinstall`/`postinstall`/`install` scripts
- **Network access** -- flag packages that import `http`, `https`, `net`, `dns`, `fetch`
- **Filesystem access** -- flag packages that write outside their scope
- **Obfuscated code** -- flag packages with minified or obfuscated source
- **Shell execution** -- flag packages that use `child_process`, `exec`, `spawn`
- **Environment variable access** -- flag packages that read `process.env`

These are leading indicators of supply chain attacks that CVE databases won't catch until after the fact.

## P3.2 Package Signature Verification

Verify npm package signatures and provenance attestations:

- Check `dist.signatures` for valid registry signatures
- Verify Sigstore provenance attestations (DSSE envelopes)
- Flag unsigned packages in the dependency tree
- Support `--include-attestations` for full transparency log output

## P3.3 Typosquatting Detection

Flag packages with names suspiciously similar to popular packages:

- Levenshtein distance analysis against top-1000 npm packages
- Detect character substitution patterns (l/1, o/0, rn/m)
- Cross-reference download counts (legitimate packages have many; typosquats have few)

## P3.4 Maintainer Change Alerting

Flag packages where the npm maintainer recently changed:

- Query npm registry for maintainer history
- Alert when a new maintainer publishes within the first 30 days
- Detect maintainer-count reduction (potential account takeover)

## P3.5 OSV.dev as Alternative Data Source

Support querying OSV.dev directly as an alternative (or supplement) to the npm registry advisory API:

- 30+ aggregated advisory sources
- Better coverage for some ecosystems
- Open data with no rate limits
- `--data-source osv` to use OSV instead of registry

## P3.6 Container Dependency Scanning

Scan container images for Node.js dependency vulnerabilities:

- Parse `package-lock.json` from container layers
- Report vulnerabilities in containerized applications
- Support Docker and OCI image formats
