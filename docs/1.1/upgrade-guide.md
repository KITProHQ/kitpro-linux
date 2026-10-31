# Upgrade from KITPro Linux Server 1.0

The supported transition begins at production generation `1.0-g0002` and ends
at `1.1-g0001`. Do not substitute an Arch rolling-release repository or an
untrusted local package directory.

Before approval, verify the installed generation, create a recoverable backup
or snapshot, confirm production repository signatures, and preserve
administrator data and configuration. The transition requires explicit
administrator confirmation and a real package-manager transaction.

After the transaction, reboot into `6.18.59-1-lts`, verify the 1.1 release and
generation identities, and confirm AppArmor, networking, DNS, SSH, and systemd
health. Keep the `6.18.55-1-lts` boot entry until the new kernel is accepted.

Interrupted operations stop for inspection. Automatic rollback is not claimed.
Restore the documented backup checkpoint when recovery is required. Downgrades
and release-namespace substitution are unsupported.
