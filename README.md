# Microsoft MFA for Mac

Experimental, unofficial macOS Microsoft Authenticator protocol client, with a
SwiftUI menu bar app and Safari extension. Published as a source-only research
snapshot, not a supported authentication product. Not affiliated with or endorsed
by Microsoft, Apple, or Google.

The historical prototype demonstrated classic work/school number-match MFA on
the same Mac as the browser. This is not a claim of current service compatibility.
Passwordless phone sign-in (RemoteNGC) and device registration remain incomplete.
There is no supported onboarding wizard or portable, notarized release.

**Security tradeoff:** approving a sign-in on the machine initiating it removes
the separation provided by a second device. Automatic approval and a compromised
local session can undermine that separation further. Use only accounts and
tenants you are authorized to test; do not weaken organization policy to run it.

## Contents

- [Development app and build](product/README.md)
- [Native host](product/macOS/README.md) and [Safari extension](product/SafariExtension/README.md)
- [Protocol service](product/service/README.md)
- [Standalone diagnostic tools](diagnostic/README.md)
- [Local research keys](product/DeviceIdentity/README.md)
- [Phone-sign-in helper](product/RemoteNGCBootstrap/README.md)
- [Device-registration helper](product/WorkplaceJoinBootstrap/README.md)
- [Security and publication boundaries](SECURITY.md)

This snapshot excludes old Git history, personal setup notes, live research
receipts, browser/session captures, downloaded apps and decompiled/disassembled
vendor dumps. Included fixtures are synthetic. Credentials are not provided:
cloning cannot reproduce the historical registration.

## Offline tests

Python 3.11+, Node.js, Swift/Xcode, and [rtk](https://github.com/rtk-ai/rtk) are
needed for the full suite. Some existing build and terminal-test commands use
`rtk proxy`. Run from the repository root:

```sh
mkdir -p work
python3 -m unittest discover -s diagnostic/tests -q
python3 -m unittest discover -s product/service/tests -q
npm ci --prefix product/SafariExtension
npm test --prefix product/SafariExtension
python3 -m unittest discover -s product/tests -q
python3 -m unittest discover -s product/macOS/Tests -p 'test_*.py' -q
swift test --package-path product/macOS
swift test --package-path product/DeviceIdentity
swift test --package-path product/RemoteNGCBootstrap
swift test --package-path product/WorkplaceJoinBootstrap
```

The isolated workplace-registration tests additionally require the dependencies
in [requirements-wpj.txt](product/service/requirements-wpj.txt) and the built
authorization helper. They are not runtime dependencies of the classic app.
See the [helper instructions](product/WorkplaceJoinBootstrap/README.md).

Tests use synthetic data; live diagnostics, Keychain smoke tests and browser
authentication are separate, explicit operations. Offline passing tests do not
establish Microsoft acceptance or production safety.

## License

Original project code is available under the [MIT License](LICENSE).
The license does not grant rights to Microsoft, Apple, or Google trademarks,
services, proprietary applications, or separately licensed dependencies.
No proprietary application binaries or raw reverse-engineered source dumps
are distributed in this snapshot.
