# Nessus OID4VC

OpenID for Verifiable Credential and Presentation.

## Prerequisites

- Java 21+
- [JBang](https://www.jbang.dev/) (for CLI)
- Keycloak running on Kubernetes (see [helm/README.md](helm/README.md))

## CLI Usage

```
Usage: oid4vc [-hvV] [COMMAND]
  -h, --help      Show this help message and exit.
  -v, --verbose   Show request/response details
  -V, --version   Print version information and exit.
Commands:
  config  Configure wallet defaults
  demo    Demo helper commands
  key     Manage keys
  login   Authenticate with Keycloak
  logout  End Keycloak session and clear stored tokens
  offer   Manage credential offers
  show    Show wallet and server state
  vc      Manage verifiable credentials
```

Wallet state is in `~/.config/wallet.json`
