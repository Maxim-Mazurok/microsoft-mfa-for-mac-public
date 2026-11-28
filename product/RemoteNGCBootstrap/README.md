# Phone-sign-in research helper

This isolated AppKit helper validates a private NGC-B01 authorization manifest,
presents a Continue in browser action and starts one `ASWebAuthenticationSession`
only after that action. It does not enroll keys, exchange tokens, approve MFA
or read the classic app's Keychain item.

```sh
python3 product/RemoteNGCBootstrap/build.py
swift test --package-path product/RemoteNGCBootstrap
```

Requires Apple silicon, macOS 15.4+, Xcode and `rtk`. Output:
`product/build/RemoteNGCBootstrap/Phone Sign-in Research.app`.
Building does not open browser authentication.

The executable supports `--validate-input /absolute/private/auth-input.json`
for no-UI validation of a synthetic manifest. Real inputs and callbacks must
remain in an owner-only directory, not command lines or logs. The native
request/callback checks bind destination, tenant, state, PKCE, client and scopes.
Consumed session locks are not reusable. Rejected callback candidates are
private diagnostics, not authorization-code exchange input.

The separate Python orchestrator is in `product/service/ngc_bootstrap.py`.
Offline tests do not establish Microsoft acceptance of this unsupported
client/redirect or the availability of a passwordless signing credential.
