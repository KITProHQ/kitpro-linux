# Verify KITPro Linux Server 1.1 artifacts

The frozen release-candidate ISO is:

```text
112955a88406f1a04364705df9e53b00449ab002699369cd511a8cad54cab36d  kitpro-linux-server-1.1.0-rc1-candidate.17-x86_64.iso
```

Recalculate the ISO SHA-256 and compare it exactly. Verify the detached
signatures for `SHA256SUMS` and `release-manifest.json` using a fresh
public-only keyring. Require ISO fingerprint
`607D71E399E645164471C8EBA998AA6B6095B621` and confirm that the keyring contains
no secret keys.

The detached signature files have these SHA-256 values:

```text
ea578c89cc96a000be8b224daa92ea71a290c8f5e2eb210e0cb243e4a14ef05a  SHA256SUMS.sig
40b18d50fc677afb5ab5b0a08d66ebfffc2f66f0736f74657abcfe1ccdfbb6ad  release-manifest.json.sig
```

A valid signature authenticates the metadata. It does not replace the ISO
checksum comparison.
