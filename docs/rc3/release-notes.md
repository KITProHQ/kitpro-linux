> Draft: RC3 has not been frozen, built, or qualified. Prior RC2 virtual results
> are historical evidence only. RC3 corrects locale-dependent support-bundle
> ordering. See [ordering contract](support-bundle-ordering.md).

# KITPro Linux Server 1.0 RC3 release notes

Engineering release candidate, not publicly released. RC3 builds, virtual tests,
offline signatures, and physical qualification remain pending; see
[qualification status](qualification-status.md).

The candidate targets product version 1.0, production generation 1.0-g0002,
and linux-lts 6.18.55-1. The installed system retains version 1.0; RC3 appears
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
qualification. Those results do not establish fresh-install RC3 media or
Beelink qualification; the RC3 qualification report must supply those results.

See the installation, verification, limitations, support, hardware, and privacy
statements in this directory. Publication requires completion of the remaining gates and separate authorization.
