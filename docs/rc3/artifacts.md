# Proposed 1.0 release artifact inventory

No artifact in this inventory has been published. The proposed release title is
`KITPro Linux Server 1.0`. The proposed source tag is `v1.0.0`, targeting the
final sanitized public-history candidate after every publication gate passes.

| Artifact | Purpose | SHA-256 |
| --- | --- | --- |
| `kitpro-linux-server-1.0-rc3-x86_64.iso` | Qualified installation and rescue media | `b65845c13d8a04cea7df5cb4b346f6048cbac19bf8bb9e0cdc7d7a4162b99e6c` |
| `SHA256SUMS` | Signed artifact hash list | `4a2497199a3c5108762681278175e6dbd7e63c3e21e8112e653a4da74056b531` |
| `SHA256SUMS.asc` | Detached OpenPGP signature for `SHA256SUMS` | `92d1b97885b3cf8a4d7e8f3bc3342173b8b6e9cac33112466a70685ec6a943ff` |
| `release-manifest.json` | Release identity, source, generation, and qualification metadata | `ca180030c05f3f0a3b02762052d66f80c4282b9a247f60427292a3dcbdb8b5c2` |
| `release-manifest.json.asc` | Detached OpenPGP signature for the release manifest | `0ff20ae94362679b001a586d62fb4083777c8b8ebc711b663bef991bbc4dd04d` |
| `iso-packages.spdx.json` | SPDX 2.3 inventory for ISO packages | `fd7c4ddc882c40f642031ee3f989f3325d7188bcd9ecb83dda6710cde9a2e76d` |
| `production-generation.spdx.json` | SPDX 2.3 inventory for production generation `1.0-g0002` | `c3eba6601dc493b4a7e935ef0b30211d0d54122dc6a71e62cd80807bfa8bf194` |

The ISO is 1,230,045,184 bytes. Its SquashFS SHA-256 is
`ec4412130042949c5f85f8f9cec1c52ab66b67de862e05ed519c4301f5372f94`.
Its boot inventory SHA-256 is
`be524eaaec2b4e301fd1a0a0ca8fd7642c2790619fb67b6332f6f552a48992ba`.

The detached signatures verify with Production ISO fingerprint
`607D71E399E645164471C8EBA998AA6B6095B621`. Do not regenerate them during
publication preparation.
