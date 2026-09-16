# Nessus OID4VP

OpenID for Verifiable Presentations — DCQL verification and OID4VCI tooling.

## Prerequisites

- Java 21+
- [JBang](https://www.jbang.dev/) (for CLI)
- Keycloak running on Kubernetes (see [helm/README.md](helm/README.md))

## CLI Usage

### Login

```bash
KC_ADMIN_PASSWORD="$(kubectl --context=rancher-desktop get secret keycloak-secret -o jsonpath='{.data.ADMIN_PASSWORD}' | base64 -d)"
bin/oid4vp login --server http://localhost:30800 --password "${KC_ADMIN_PASSWORD}"
```

Session tokens are stored in `~/.config/nessus-oid4vp/wallet.json` (no password on disk).
