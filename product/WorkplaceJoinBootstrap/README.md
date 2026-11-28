# Device-registration authorization helper

This separate WPJ-A01 helper starts one interactive authorization session after
an explicit Continue in browser action. It does not itself exchange a token,
create a device, install a profile, enroll in management or access classic MFA
credentials. Stop if any browser prompt requests device management or compliance.

```sh
python3 product/WorkplaceJoinBootstrap/build.py
swift test --package-path product/WorkplaceJoinBootstrap
python3 product/WorkplaceJoinBootstrap/offline_check.py
```

Requires Apple silicon, macOS 15.4+, Xcode and `rtk`. Output:
`product/build/WorkplaceJoinBootstrap/Device Registration Authorization.app`.
Building does not authenticate. The offline check uses synthetic manifests.

For the separate Python research suite:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r product/service/requirements-wpj.txt
.venv/bin/python -m unittest discover -s product/tests-wpj -q
```

The tests require the built authorization helper. They use invented inputs
and keys, not live accounts or provider requests.

The helper's callback requires the exact `msauth` scheme and
`Microsoft.AAD.BrokerPlugin` host with an empty path, matching state and exactly
one code or error. Inputs and outputs are private; consumed locks must not be
reset. Callback acceptance does not establish token issuance, successful device
registration or passwordless approval. The registration modules remain
unsupported, separate research code.
