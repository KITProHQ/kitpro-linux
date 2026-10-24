# Verify release-candidate artifacts

The Production ISO signing fingerprint is:

`607D71E399E645164471C8EBA998AA6B6095B621`

Obtain the public key and certification evidence through KITPro's public trust
distribution. Compare the complete fingerprint through an independently trusted
source. Use a dedicated verification keyring that contains no private keys.

With that keyring in `VERIFY_HOME`, verify both detached signatures and then the
listed artifact hashes:

```bash
gpg --homedir "$VERIFY_HOME" --status-fd 1 \
  --verify SHA256SUMS.asc SHA256SUMS
gpg --homedir "$VERIFY_HOME" --status-fd 1 \
  --verify release-manifest.json.asc release-manifest.json
sha256sum --check SHA256SUMS
```

Require successful verification and a `VALIDSIG` for the exact fingerprint
above. A checksum proves byte equality, not publisher identity. Compare the
manifest's ISO filename, size, hash, source commit and tree, production
generation hash, and qualification references with the release notes.

Package and Repository keys authenticate packages and repository databases.
They do not replace the offline ISO release signature.

See [artifacts.md](artifacts.md) for the proposed publication inventory.
