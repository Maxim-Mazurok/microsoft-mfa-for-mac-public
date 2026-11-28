# Security boundaries

This is an unsupported research prototype, not a replacement for a maintained
authenticator. Same-machine automatic approval is a deliberate security
tradeoff. Browser context is not a cryptographic attestation, and owner-only
files do not isolate malicious processes already running as the same user.
The development host is unsandboxed; its Safari extension has a scoped
filesystem exception. Distribution signing and notarization are not supplied.

Do not attach live activation links, QR codes, MFA seeds, private keys, access
or refresh tokens, account/tenant/device identifiers, browser archives, network
captures, credential exports, or raw server responses to issues or pull requests.
Use invented examples and fixed error codes. Report sensitive findings through
GitHub private vulnerability reporting if enabled, not a public issue.
There is no guaranteed response or security-update schedule.

## Local state

- Keep experiment inputs and outputs under ignored `.secrets/`, with directories
  mode `0700` and files mode `0600`. Never reset consumed attempt locks to retry
  an uncertain network operation.
- Credential export writes secrets to stdout for the native app's captured
  pipe. Do not invoke it in a logged terminal or pipeline.
- Local deletion, uninstalling the app, and ceasing to use MFA do not revoke
  server-side registrations or provider credentials. Review and revoke only
  your identified experimental methods, devices and cloud credentials through
  their respective providers; retain working recovery methods.
- `org.example.*` bundle IDs, Keychain tags and bridge directories identify this
  public development snapshot. They intentionally do not access the original
  private prototype's app state. No migration or compatibility alias is included.

## Before publishing a fork

Scan both source and every Git ref, including commit messages and author emails.
`.gitignore` does not sanitize already tracked content or old commits. Publish
only reviewed Git-tracked source, never a ZIP of a working directory containing
ignored state. Check releases, Actions artifacts/logs, issues, PRs, wiki and other
hosting surfaces separately.

Replacing a branch with clean history does not revoke credentials or necessarily
purge old GitHub objects, cached commit/diff pages, forks, or existing clones.
For a previously private repository containing sensitive history, keep it
private until remote retention is addressed, or publish a separate repository
containing only the reviewed snapshot. Obtain a redistribution review before
adding any vendor application, source extract, symbol dump or disassembly.
