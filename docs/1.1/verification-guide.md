# Verify KITPro Linux Server 1.1 artifacts

The frozen release-candidate ISO is:

```text
1192bb1d015794a020782ac650a1d8f9e83aec01c6a827f7b908da85ce74c2fe  kitpro-linux-server-1.1.0-rc1-candidate.10-x86_64.iso
```

Recalculate the ISO SHA-256 and compare it exactly. Final public release must
also provide detached signatures for `SHA256SUMS` and the release manifest.
Verify those signatures using a fresh public-only keyring and require ISO
fingerprint `607D71E399E645164471C8EBA998AA6B6095B621`.

The current local candidate has not completed that offline signing ceremony.
Do not treat the checksum alone as proof of the final public release.
