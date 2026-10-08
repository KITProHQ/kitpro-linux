# RC3 known limitations and qualification gates

These limits apply to RC3. RC3 qualification is pending; physical qualification
and offline release signatures remain pending.

- UEFI x86_64 only; Secure Boot and legacy BIOS are not supported.
- Whole-disk installation only. No dual boot, custom partition layout, or
  preservation of existing data on the selected target is promised.
- Wired networking is the supported qualification path. DHCP and static IPv4
  are supported; arbitrary wireless hardware is not qualified.
- The installer uses ext4. RAID, LVM, encryption, and ZFS installation workflows
  are not supported.
- Physical lifecycle qualification covers one platform, subject to the recorded
  Beelink RC3 result; this is not a general hardware certification.
- Previous-kernel selection is manual in the boot menu.
- SSH is optional, key-only, and denies root login.
- Previous-kernel fallback requires a prior known-good kernel retained through
  a genuine update. Fresh installation alone does not create one.
- Offline rescue inspection mounts root and ESP read-only by default. Repairs
  require explicit authorization and are distinct from inspection.
- RC qualification does not establish support for every RAID/HBA/NIC platform.

Block release on installation, boot, trust, update, fallback, rescue,
reproducibility, identity, security, secret-exposure, or data-loss defects.
Do not treat successful repository qualification as successful media qualification.

The optional virtualization collector previously warned on bare-metal detection.
Its accepted exit status now includes the documented no-virtualization result.
The focused collector test passes; live Beelink bundle validation is still required.
