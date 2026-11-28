# Isolated research keys

This helper creates local software RSA-2048 signing keys in the login Keychain.
It does not authenticate, contact Microsoft, register a device, install a
profile or access the classic app's credentials. Keys are not Secure Enclave
keys and provide no hardware-attestation or compliance claim.

```sh
python3 product/DeviceIdentity/build.py
swift test --package-path product/DeviceIdentity
```

Building does not create or query keys. Output:
`product/build/DeviceIdentity/DeviceIdentityTool`. Requires Apple silicon,
macOS 15.4+, Xcode and `rtk`.

The helper accepts one JSON document through stdin, with `v:1`, an action
(`create`, `public`, `sign`, `delete`), a fresh UUID `namespace` and role
(`device` or `transport`). Signing additionally requires `data_base64`.
Capture outputs privately. Application tags use
`org.example.microsoftmfamac.device-identity.research.<namespace>.<role>`.
Lookups and deletion are constrained to the exact tag and key type.

`smoke_test.py --synthetic-only` separately creates and deletes synthetic
Keychain keys. It is an explicit local-state-changing check, not part of the
pure core suite. Never delete a real key until its corresponding server-side
registration has been deliberately retired.
