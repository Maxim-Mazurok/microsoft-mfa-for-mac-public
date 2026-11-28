# Standalone diagnostics

These are bounded research tools, not a supported enrollment workflow.
The original personal setup, attempt receipts and raw vendor evidence are not
distributed. Existing experiment identifiers describe stages, not credentials
available in this clone.

E01 checks enrollment input; P01/P02/P03 investigate push-provider transport;
E02-E05 cover enrollment/validation and request handling; E06 covers a deliberate
same-machine approval. RemoteNGC and workplace registration are separate.
Do not run live stages merely to try the project or reset their persistent
attempt locks. Use only an authorized test account with recovery methods.

## Offline first

From the repository root, using Python 3.11+:

```sh
mkdir -p work
python3 diagnostic/e01.py demo
python3 diagnostic/p02_prepare.py demo
python3 -m unittest discover -s diagnostic/tests -q
```

Fixtures are invented. The diagnostic suite blocks real network access in its
transport tests; terminal tests also require `rtk`. Live modes require explicit
flags and protected local inputs. Do not place activation codes, tokens or
decoded QR data in command-line arguments, logs, issues or chat.

## Own-project P02 configuration

Start from [p02-config.example.json](p02-config.example.json). Fill in your own
Firebase project, sender number, Android app ID, API key and certificate digest.
Confirm ownership explicitly; the flag is a user declaration, not independent
proof. Register the probe package `org.example.macmfaprobe`.

Store the real configuration at `.secrets/push/p02-setup/config.json`, with
parent directories `0700` and file mode `0600`. The executor also validates a
matching `probe.der`, successful P01 provenance, and a fresh sender token bound
to `p02-sender@<your-project>.iam.gserviceaccount.com`. None are supplied here.

The sender helper has no built-in login account. With a separately authorized,
isolated gcloud login under `.secrets/push/p02-setup/gcloud` and the required
impersonation permissions, its explicit one-attempt command is:

```sh
python3 diagnostic/p02_sender.py mint --once --account researcher@example.test
```

Replace the example account locally; this command contacts Google and is not
an offline test. The helper finds `gcloud` on PATH, requests a short-lived token
once and stores it privately. It does not create projects, grant permissions,
download service-account keys or retry failures. `python3 diagnostic/p02_sender.py`
without arguments is offline and does not mint a token.

Local file deletion does not revoke provider credentials or Microsoft methods.
Review the [security boundaries](../SECURITY.md) before any live use.
