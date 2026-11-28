# Protocol service

The native host owns Keychain and system verification. `main.py` is its private
Python 3.11+ child process, using the standard library. JSON-lines messages
have `version:1` and are bounded to 64 KiB. Credentials arrive through a private
pipe, not browser JavaScript or a listening web endpoint.

The child starts offline. An explicit connect uses an existing provider identity;
it does not enroll or rotate credentials. Classic matching requires the exact
normalized account and a shared session/request identifier, uniqueness and
freshness. Number-only matching is not supported. Required context and real
macOS verification are rechecked before sending. Durable opaque claims suppress
duplicate or uncertain approvals across restarts.

Credentials and pending account/location data remain in memory. Owner-only
state stores opaque claims and fixed outcomes, not raw requests or tokens.
Python does not provide guaranteed secret-memory erasure.

`--export-research <workspace>` is only for captured native import. Its stdout
contains secrets; never run it in a logged shell. Import validates protected
P01/P03/E05/E06 provenance and does not create or replace a registration.

`vendor/` contains project-owned diagnostic modules, not copied vendor
application code. `vendor/PROVENANCE.json` pins the publication versions by
SHA-256; it is not a claim that anonymized files are byte-identical to historical
executed sources. Protocol codecs remain unsupported research implementations.
Original binary evidence and private receipts are intentionally not distributed.

RemoteNGC and workplace-registration modules remain separate experimental
paths. Detection or a successful callback is not a registered credential,
approved sign-in, attestation or device compliance claim.

```sh
python3 -m unittest discover -s product/service/tests -q
python3 -m unittest discover -s product/tests -q
```
