# Known limitations

- Secure Boot is not qualified and must remain disabled.
- The current candidate is x86_64 and UEFI-only.
- RAID, general dual boot, and advanced multi-disk layouts are unsupported.
- Physical installation covered one AZW Beelink ME Pro with its WD PC SN540
  NVMe and Intel I226-V wired network interface. This result is not universal
  hardware certification.
- Quick ext4 was exercised on physical hardware. Encrypted LVM and
  preservation/EFI reuse were exercised in disposable QEMU.
- Automatic interrupted-upgrade rollback is not implemented; recovery uses an
  explicit checkpoint and inspection workflow.
- Wi-Fi installation is not a qualified release path.
