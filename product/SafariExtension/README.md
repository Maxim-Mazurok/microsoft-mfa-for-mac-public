# Safari extension

Build the containing app using the [development instructions](../README.md).
Enable Safari developer features, allow unsigned extensions, then enable the
embedded Microsoft MFA for Mac extension. Safari can reset unsigned-extension
permission after quitting. A loose Resources-folder extension does not test
the containing-app native messaging path.

Access is limited to `login.microsoftonline.com`, `login.microsoft.com` and
`login.windows.net`, in top-level frames. JavaScript receives no authenticator,
provider or Keychain credentials.

The page hook observes classic SAS/BeginAuth and RemoteNGC GetOneTimeCode
responses without initiating or changing them. Only bounded account, number,
flow and session-correlation context passes to the native bridge. Remote
sessions are fingerprinted; initial page configuration alone is detection-only.
The service independently checks the issuer-backed request and current host
state before an approval.

The hook runs in the page's MAIN world and is observable/modifiable there.
This is not protection against a compromised sign-in page or local session.
Missing, stale, conflicting, background or ambiguous context fails closed.
Tab changes, navigation, disappearance and lock revoke automatic context.

The default owner-only bridge directory and its sandbox exception are described
in the [native host documentation](../macOS/README.md). No HTTP approval endpoint
or URL-scheme credential channel is exposed.

## Offline tests

```sh
npm ci --prefix product/SafariExtension
npm test --prefix product/SafariExtension
```

`tests/BridgeTests.swift` tests native message validation and private-file
handling. `tests/ManifestTests.swift` parses the manifest using WebKit.
`tests/run_sandbox_probe.py` is a separate explicit AppKit probe that launches
a signed helper and writes synthetic local files, not a pure unit test.
