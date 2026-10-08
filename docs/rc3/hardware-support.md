# KITPro Linux Server 1.0 hardware requirements

RAM requirements are frozen by installation-memory qualification. Prior RC2
TCG and KVM installations passed at 2 GiB; RC3 requalification is pending. Physical hardware qualification
remains pending:

| Requirement | Minimum | Recommended |
| --- | --- | --- |
| Architecture | x86_64 | Modern Intel/AMD x86_64 |
| Firmware | UEFI, Secure Boot disabled | UEFI |
| Installation RAM | 2 GiB | 4 GiB or more |
| Installed/runtime RAM | 2 GiB | 4 GiB or more |
| Target disk | 16 GiB | 32 GiB or larger SSD/NVMe |
| USB installation media | 4 GiB | 4 GiB or larger |
| Network | Supported network adapter | Wired Ethernet |

The [installation-memory qualification](../installation-memory-qualification.md)
proves the RAM values using clean native production-intent media under TCG and
KVM, including repeated 2 GiB installations and separate 2 GiB runtime validation.
Native installation trials used 16 GiB disks. RC3 fresh-install checks remain pending. Physical qualification and offline
signatures are still required before complete RC3 acceptance.

KITPro targets standard x86_64 UEFI server and homelab hardware supported by the
upstream Linux kernel. Qualification does not imply universal support for RAID
controllers, SAS HBAs, NICs, firmware, or enterprise platforms. Beelink NVMe and
Intel I226-V/igc qualification remains a specific RC3 gate.
