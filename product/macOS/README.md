# Native host

Follow the [app build instructions](../README.md). Use practice mode first.
The public snapshot uses bundle ID `org.example.microsoftmfamac`, separate
from the original prototype. No existing account is automatically imported.

An explicit import selects a research workspace with protected E05/E06
provenance. The exporter passes credentials privately to an add-only login
Keychain item, service `org.example.microsoftmfamac.registration`.
It does not synchronize to iCloud or delete the source state.
Ad-hoc rebuilding can cause Keychain permission prompts. No Data Protection
Keychain or Secure Enclave guarantee is made.

The default `development` bridge uses an owner-only directory at
`~/Library/Application Support/org.example.microsoftmfamac/BrowserBridge/`.
The extension has a read/write sandbox exception for that directory only;
the host is unsandboxed. `--bridge-mode app-group` requires legitimate
signing/provisioning for `group.org.example.microsoftmfamac`; ad-hoc signing
does not grant that access.

Microsoft-required app lock invokes genuine `LAContext` verification.
Optional 30-second Touch ID reuse concerns recent device unlock, not a prior
app approval. Cancellation, timeout, lock, pause and expiry invalidate tickets.
Policy context is acknowledged only when actually visible in the key window.

Launch at login is optional and starts disconnected. Lock/sleep and Safari
termination invalidate automatic context; live lifecycle behavior must still
be tested on the target OS. Do not use synthetic success as proof of live MFA.

```sh
swift test --package-path product/macOS
```

The separate `--self-test-native` mode touches synthetic Keychain items and
local bridge state. It is not part of the pure core suite; do not run it as an
unannounced background check.
