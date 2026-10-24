# KITPro Linux Server 1.0 hardware requirements

| Requirement | Minimum | Recommended |
| --- | --- | --- |
| Architecture | x86_64 | Modern Intel/AMD x86_64 |
| Firmware | UEFI, Secure Boot disabled | UEFI |
| Installation RAM | 2 GiB | 4 GiB or more |
| Installed/runtime RAM | 2 GiB | 4 GiB or more |
| Target disk | 16 GiB | 32 GiB or larger SSD/NVMe |
| USB installation media | 4 GiB | 4 GiB or larger |
| Network | Supported network adapter | Wired Ethernet |

RC3 passed repeated virtual installation and runtime validation at 2 GiB RAM.
It also passed physical installation, update, fallback, rescue, power-cycle, and
14-day burn-in checks on a compact x86_64 system with NVMe storage and wired
Ethernet.

KITPro targets standard x86_64 UEFI server and homelab hardware supported by the
upstream Linux kernel. Qualification does not imply support for every RAID
controller, SAS HBA, NIC, firmware implementation, wireless adapter, or
enterprise platform.
