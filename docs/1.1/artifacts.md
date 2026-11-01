# Release artifact inventory

| Artifact | SHA-256 | Status |
| --- | --- | --- |
| `kitpro-linux-server-1.1.0-rc1-candidate.17-x86_64.iso` | `112955a88406f1a04364705df9e53b00449ab002699369cd511a8cad54cab36d` | Qualified; covered by signed metadata |
| `SHA256SUMS` | `92db85894361e423e8027a20d48d8cdb8f4f0eb9c96765e87265b56f4c0d9c93` | Signed and independently verified |
| `SHA256SUMS.sig` | `ea578c89cc96a000be8b224daa92ea71a290c8f5e2eb210e0cb243e4a14ef05a` | ISO signer fingerprint verified |
| `release-manifest.json` | `77aa57cf0ff5bce9ec92812e05af03e9ee272d98a504b04d651497ee9da860e0` | Signed release metadata |
| `release-manifest.json.sig` | `40b18d50fc677afb5ab5b0a08d66ebfffc2f66f0736f74657abcfe1ccdfbb6ad` | ISO signer fingerprint verified |
| Installer runtime lock | `57881abba319b235ce6e9eaf82d5138d311e1fffc16d3bf2128fa0e0f9af7ed6` | Qualified candidate.17 lock |
| SPDX 2.3 package inventory | `41643c71761a70cb42130b931939d14855e017319d420407e514e34c56e6c9ad` | 199-package inventory |

The production package generation contains 199 core packages, 36 explicitly
installed packages, and no default KITPro Console or Docker installation.
The signed ISO metadata verifies with fingerprint
`607D71E399E645164471C8EBA998AA6B6095B621`.
