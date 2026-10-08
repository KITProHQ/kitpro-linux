# Verify RC2 release artifacts

Draft. No RC2 artifact or signature is available from this preparation checkpoint.

The Production ISO signing fingerprint is:

`607D71E399E645164471C8EBA998AA6B6095B621`

Obtain its public key and certification evidence through the approved public
trust distribution and compare the complete fingerprint through an independently
trusted source. Import public trust into a dedicated verification keyring.
Never import a private signing key to verify a download.

With the public verification home in VERIFY_HOME, verify both detached signatures:

```bash
gpg --homedir "$VERIFY_HOME" --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS
gpg --homedir "$VERIFY_HOME" --status-fd 1 --verify release-manifest.json.asc release-manifest.json
sha256sum --check SHA256SUMS
```

Require a successful verification and VALIDSIG for the exact Production ISO
fingerprint. A checksum alone proves byte equality, not publisher identity.
Compare the manifest's ISO filename, size, hash, source commit/tree, production
generation hash, and qualification references with the release evidence.

Unsigned or unqualified preparation artifacts are not installable release
candidates. Package and Repository keys authenticate packages and databases;
they do not substitute for the offline ISO release signature.
