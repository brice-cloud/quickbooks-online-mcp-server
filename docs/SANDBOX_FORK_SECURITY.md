# Sandbox fork security

This fork is a candidate for sandbox read-only use. It is not a claim of perfect security. The controls below are what the code does now. Residual items are not fixed.

## Hard controls

These do not depend on a README flag or on `QUICKBOOKS_DISABLE_*`.

| Control | Behavior |
| --- | --- |
| Environment | Unset or the exact string `sandbox` is accepted. `production`, `Production`, `SANDBOX`, `Sandbox`, `prod`, blanks, and trailing spaces call `process.exit(1)` before an OAuth client or accounting client is constructed. |
| Token file | If the file contains `QUICKBOOKS_ENVIRONMENT` and the value is not exactly `sandbox`, startup exits 1. The file cannot change a bad process environment into a startup, and a sandbox process environment cannot be overridden to production. |
| Accounting host | After the check passes, the client passes `useSandbox: true` to `node-quickbooks`. The attachable upload throws if `isSandbox` is not `true` and otherwise uses only `sandbox-quickbooks.api.intuit.com`. |
| Tool registration | `READ_ONLY_TOOL_ALLOWLIST` is the only read set. Names starting with `create_`, `create-`, `update_`, `update-`, `delete_`, or `delete-` are not registered. `SANDBOX_WRITE_EXCEPTIONS` is an empty frozen list. Adding `create_deposit` later is a reviewed code change to that list, not an environment variable. |
| Credential file keys | The token file may set client id, client secret, refresh token, realm id, and redirect URI. It does not set `QUICKBOOKS_DISABLE_*`, `QBO_PDF_OUTPUT_DIR`, or `QUICKBOOKS_TOKEN_STORE_PATH`. |
| OAuth listener | Redirect registered with Intuit is exactly `http://localhost:8000/callback`. Sockets bind only `127.0.0.1:8000` and `::1:8000`, not `0.0.0.0` or `::`. The Host header must be `localhost:8000`, and the peer address must be loopback. `state` is compared with `crypto.timingSafeEqual`. The callback query string is not logged. The listener times out after five minutes. |
| Token lock | A `*.lock` file is held across one refresh and its write. The write renames a temp file onto the resolved target, including symlink targets. |
| Fatal config | Missing client id or secret, a relative token path, an unreadable token file, and a bad environment exit 1. The old `uncaughtException` logger that could leave exit code 0 is gone. |

## Not a control

- `QUICKBOOKS_DISABLE_WRITE=false` does not register `create_deposit`, `create_payment`, `create_transfer`, `update_company_info`, or `delete_*`.
- Read tools still call QuickBooks when a caller invokes them. The allowlist is not a network firewall.
- `get_deposit` and `search_deposits` read ledger Deposit records. They are not bank-feed Match. No Match tool is registered.
- A sandbox OAuth app and sandbox company are still required before any real read. This repository does not perform that signup.

## Dependency advisories

Overrides and the SDK bump are compatible-version fixes. They are not `npm audit --force`, and nothing in npm config hides findings. Re-run `npm audit --omit=dev` on this lockfile before activation.

Production `npm audit --omit=dev` after the Zod 4.6.7 upgrade reports one moderate and no high or critical findings:

- **Zod:** [GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5) covers npm `zod` versions `< 4.6.6`. The advisory's first patched version is `4.6.6`. This fork depends on `4.6.7`, the current published release at or after that patch. The patch checks `.max()`, `.length()`, and `.size()` before walking elements. An array schema with no size bound can still emit one issue per bad element. Do not treat the upgrade as a cap on every unconstrained array.
- **Moderate, not an activation blocker by itself:** `fast-uri@3.1.7` via `ajv` inside `@modelcontextprotocol/sdk`. The fixed line is fast-uri 4.x. Ajv 8 depends on fast-uri 3, so this fork does not force the major. It is not the Intuit HTTP client.

Cleared on the production tree, including the SDK and `zod-to-json-schema` paths, which resolve to the same `zod@4.6.7`: `axios@1.21.0`, `follow-redirects@1.16.2`, `proxy-addr@2.0.8`, `body-parser@2.4.0`, `decode-uri-component@0.5.1`, `@modelcontextprotocol/sdk@1.32.2`, `hono@4.13.16`, `@hono/node-server@2.1.6`, `ip-address@10.7.6`. `intuit-oauth@4.2.5` still uses `query-string` 6; the decode-uri-component override is what removed that high from the production audit.

The full install, including devDependencies, still reports `handlebars` critical and `brace-expansion` high. Those are test and lint tools. They are not in `npm ci --omit=dev` and they are not in the runtime archive. They are not waived.

## Residual risks

- Refresh tokens and client secrets in the token file are plaintext. The lock is local to one machine and one path. Two different paths for the same file do not share a lock.
- Persist can still fail after Intuit has rotated the token. The error is logged and the in-memory token is kept for that process. The next process can be locked out. The lock reduces the race; it does not make Intuit's rotation atomic with the disk.
- `QBO_PDF_OUTPUT_DIR` in the process environment can still make `get_invoice_pdf` write a PDF locally. The token file cannot set that variable.
- `get_*` and `search_*` tools, including payments, transfers, deposits, and company info, remain callable and will use the network when invoked.
- Supply-chain findings that survive the compatible overrides are listed by `npm audit` and are not waived.

## Activation

Do not point this fork at production credentials. Do not treat a green test run as permission to merge to Intuit or to install it on a shared host until the audit section of the pull request is read. Sandbox reads still require a human sandbox OAuth handshake. Register exactly `http://localhost:8000/callback` on the sandbox app. The process listens on loopback only.
