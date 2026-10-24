# KITPro Linux Server 1.0 release notes

KITPro Linux Server 1.0 was officially released on October 24, 2026. The
[final release](https://github.com/KITProHQ/kitpro-linux/releases/tag/v1.0.0)
uses the qualified RC3 ISO unchanged, so its filename retains `rc3`.

The frozen RC3 target uses production generation `1.0-g0002`, kernel
`6.18.55-1`, and 199 packages, 36 of them explicit. Its two independently
created media builds matched bit-for-bit. Virtual and physical qualification,
offline signing verification, rescue checks, support-bundle locale regression,
and the 14-day physical burn-in passed. The burn-in covered every required warm
reboot and cold cycle and found zero defects.

The guided installer supports whole-disk GPT/UEFI installation with ext4,
hostname, timezone, locale, DHCP or static IPv4, an administrator password, and
optional SSH public-key access. Sudo requires the administrator password. SSH
disables root and password login. Installation requires an exact `ERASE`
confirmation for the selected disk.

The administrator baseline includes nano, vim, bash-completion, less, which,
man-db, man-pages, rsync, jq, bind/dig, tcpdump, dmidecode, smartmontools,
nvme-cli, and strace. KITPro also supplies health, kernel fallback, rescue, and
local sanitized support-bundle tools.

Known limitations are documented in [known-limitations.md](known-limitations.md).
Release artifacts and their hashes are listed in [artifacts.md](artifacts.md).
