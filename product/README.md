# Development app

The classic MFA prototype combines a SwiftUI menu bar host, a private Python
child process and an embedded Safari extension. It starts disconnected.
Connecting, importing credentials and enabling Safari are explicit actions.
There is no registration wizard; a clean clone has no usable account.

## Build

Requires Apple silicon, macOS 15.4+, Xcode, XcodeGen, Python 3.11+ and `rtk`.
From the repository root:

```sh
python3 product/build.py --test
open 'product/build/DerivedData/Build/Products/Debug/Microsoft MFA for Mac.app' --args --demo
```

Practice mode uses invented requests without credentials or network access.
Building does not launch the app. The builder refuses to replace a running
target; `--derived-data product/build/Separate/DerivedData` selects another
output. Do not run multiple live listeners for the same registration.

The local build is ad-hoc signed and records the chosen Python interpreter
path; it is not a portable distribution. `--python /absolute/path/to/python3`
selects an interpreter. `project.yml` generates the Xcode project.

## Boundaries

- Classic automatic approval requires a unique, fresh account/session match,
  an unlocked/unpaused host, and genuine system verification when required.
  Ambiguous requests remain manual. There is no number-only matching fallback.
- The service persists opaque replay claims before sending and does not retry
  an uncertain approval.
- RemoteNGC detection is separate from approval: a suitable registered
  asymmetric credential and device binding are not implemented end to end.
- Long-term provider-token repair, portable signing, notarization and live
  sleep/wake recovery are not established by the synthetic suites.
- Import accepts protected E05/E06 research provenance only. It is add-only;
  it does not enroll, repair, delete or revoke an authentication method.

See [native setup](macOS/README.md), [Safari setup](SafariExtension/README.md),
[service details](service/README.md) and [security limitations](../SECURITY.md).
