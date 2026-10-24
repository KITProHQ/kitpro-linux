# Verify KITPro Linux Server 1.0 release artifacts

Download the frozen artifacts from the
[official 1.0 release](https://github.com/KITProHQ/kitpro-linux/releases/tag/v1.0.0).
The ISO filename retains `rc3` because the qualified media was published
unchanged.

The Production ISO signing fingerprint is:

`607D 71E3 99E6 4516 4471 C8EB A998 AA6B 6095 B621`

The finalized repository copy is
[`keys/kitpro-linux-production-iso.asc`](../../keys/kitpro-linux-production-iso.asc).
An independent mirror is planned at
`https://kitpro.us/keys/kitpro-linux-production-iso.asc`, but that mirror is
pending deployment and must not be treated as live until separately verified.

Importing a public key does not establish that it belongs to KITPro. Verify the
complete displayed fingerprint through an independently trusted source and
confirm that it matches the fingerprint above.

From the repository root, import and inspect the repository copy:

```bash
gpg --import keys/kitpro-linux-production-iso.asc
gpg --fingerprint 607D71E399E645164471C8EBA998AA6B6095B621
```

Verify both detached signatures and then the listed artifact hashes:

```bash
gpg --verify SHA256SUMS.asc SHA256SUMS
gpg --verify release-manifest.json.asc release-manifest.json
sha256sum --check SHA256SUMS
```

Require successful verification and the exact Production ISO fingerprint. A
checksum proves byte equality, not publisher identity. Compare the manifest's
ISO filename, size, hash, source commit and tree, production generation hash,
and qualification references with the release notes.

Package and Repository keys authenticate packages and repository databases.
They do not replace the offline ISO release signature.

See [artifacts.md](artifacts.md) for the published release inventory.
