# Known limitations

- Secure Boot is not qualified and must remain disabled.
- The current candidate is x86_64 and UEFI-only.
- The exact Linux 1.1 ISO has completed QEMU qualification but has not yet
  completed separately authorized physical-hardware installation.
- Offline ISO signatures are not claimed until the isolated signing ceremony
  and independent public-only verification complete.
- Automatic interrupted-upgrade rollback is not implemented; recovery uses an
  explicit checkpoint and inspection workflow.
- Hardware qualification is platform-specific and does not imply support for
  every storage controller, NIC, HBA, or firmware implementation.
