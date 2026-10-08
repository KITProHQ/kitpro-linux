# KITPro Linux Server 1.0 RC2 release notes

Draft. RC2 has not yet been built, signed, or qualified. This is not a public release announcement.

The candidate targets product version 1.0, production generation 1.0-g0002,
and linux-lts 6.18.55-1. The installed system retains version 1.0; RC2 appears
in media and release metadata. The frozen target contains 199 packages,
including 36 explicitly installed packages.

The installer supports whole-disk GPT/UEFI installation with ext4, hostname,
timezone, locale, DHCP or static IPv4, an administrator password, and optional
SSH public-key access. Sudo requires the administrator password. SSH disables
root and password login. Installation requires an exact ERASE confirmation.

The administrator baseline includes nano, vim, bash-completion, less, which,
man-db, man-pages, rsync, jq, bind/dig, tcpdump, dmidecode, smartmontools,
nvme-cli, and strace. KITPro supplies health, kernel fallback, rescue, and
local support-bundle tools.

The production repository transition and fallback already passed TCG and KVM
qualification. Those results do not establish fresh-install RC2 media or
Beelink qualification; the RC2 qualification report must supply those results.

See the installation, verification, limitations, support, hardware, and privacy
statements in this directory. Do not publish these drafts as a completed RC.
