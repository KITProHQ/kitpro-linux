# Install KITPro Linux Server in Proxmox VE

Use OVMF for a UEFI installation. KITPro Linux Server RC3 and the
[v1.1.0 release](https://github.com/KITProHQ/kitpro-linux/releases/tag/v1.1.0)
document Secure Boot as unsupported. Disable Secure Boot for these releases.
Release checksums and OpenPGP signatures do not establish UEFI Secure Boot trust.

## Configure the VM

1. Select **OVMF (UEFI)** firmware and the **q35** machine type.
2. Add a 4 MB EFI disk to retain the VM's firmware settings.
   [Disable Secure Boot in OVMF](#disable-secure-boot-in-ovmf) before retrying the ISO.
   The reported VM used `pre-enrolled-keys=1`. That option and OVMF selection
   alone do not establish the effective Secure Boot state.
3. Add the intended virtual installation disk. VirtIO SCSI with the
   `virtio-scsi-single` controller is the configuration in the external RC3 report.
4. Verify the release checksums and signatures, then attach the verified ISO as
   the virtual CD-ROM. In the VM's **Options > Boot Order**, enable that drive
   and place it before the virtual disk for installation.
5. Boot the installer and complete the release's installation procedure.
6. After installation, shut down the VM and remove the ISO from the virtual CD-ROM.
7. Enable the installed virtual disk in **Options > Boot Order** and place it first.
   Boot from that disk and confirm a local login before treating installation
   and disk boot as verified.

These settings address the reported firmware rejection. They do not qualify
other VM configurations or establish that an installation error has been fixed.

## Disable Secure Boot in OVMF

For an existing VM with pre-enrolled keys, disable Secure Boot inside the VM:

1. Open the VM console, start or reset the VM, and press **Esc** during firmware startup.
2. Open **Device Manager > Secure Boot Configuration** in the OVMF menu.
   Menu layout can vary with the installed firmware version.
3. Clear **Attempt Secure Boot**. Accept any firmware save prompt, then reset the VM.
4. Re-enter the firmware menu and confirm **Current Secure Boot State** is disabled
   before selecting the installation media.

The [Proxmox firmware documentation](https://github.com/proxmox/pve-docs/blob/master/qm.adoc#bios-and-uefi)
explains the EFI disk, pre-enrolled keys, and entering OVMF with Esc.
The [upstream firmware menu definitions](https://github.com/tianocore/edk2/blob/master/SecurityPkg/VariableAuthenticated/SecureBootConfigDxe/SecureBootConfigStrings.uni)
identify the Secure Boot toggle and state display. Changing the toggle takes effect
following a firmware reset. These instructions were reviewed against those sources;
they are not an independent test of Edward's VM.

## Recognize a Secure Boot rejection

The external RC3 report included this firmware error:

```text
failed to load Boot0002 "UEFI QEMU DVD-ROM"
Access Denied -- rejected probably by Secure Boot

No bootable option or device was found.
```

If this error appears, confirm that the VM uses OVMF and that Secure Boot is
disabled. A missing boot option by itself does not identify the cause. Record
the firmware settings and ISO identity before changing other VM settings.

## Report a separate installation failure

If the ISO boots but the installer later fails, record the installer version,
ISO filename and checksum, full error text, and the step that failed. Include
sanitized installer logs and the VM's firmware, disk, controller, and resource
settings. Remove credentials, personal addresses, VM identifiers, MAC addresses,
and UUIDs before sharing diagnostics.

Keep an installer failure separate from a firmware rejection. A configuration
change that allows the ISO to boot does not establish that installation or the
first boot from disk succeeds.

## Evidence and limits

Edward [@nex-el](https://github.com/nex-el) reported that the configuration
adjustments allowed RC3 to boot and install in
[Proxmox issue #1](https://github.com/KITProHQ/kitpro-linux/issues/1#issuecomment-6722766572).
His comment mentions setting the CD-ROM to none and booting again, but also
leaves installation and disk-boot checks under "To be tested". Explicit
confirmation of boot from the installed disk after removing the ISO is pending.
No independent engineering reproduction was performed for this documentation.

His [supporting repository](https://github.com/nex-el/KITPro-Linux-Server-1.1)
also reports a separate installer failure using
`kitpro-linux-server-1.1.0-rc1-candidate.17-x86_64.iso`. That candidate result does
not establish a defect in the final v1.1.0 ISO or invalidate the RC3 firmware
workaround. The [separate candidate installer issue](https://github.com/KITProHQ/kitpro-linux/issues/2)
tracks that error and pending validation. The same Proxmox behavior on the final
v1.1.0 ISO remains untested.

The historical [RC3 installation guide](rc3/installation-guide.md) and
[RC3 limitations](rc3/known-limitations.md) also require Secure Boot disabled.
The [final v1.1.0 installation guide](https://github.com/KITProHQ/kitpro-linux/blob/v1.1.0/docs/1.1/installation-guide.md)
requires UEFI with Secure Boot disabled and a boot from disk after media removal.
These instructions describe RC3 and v1.1.0. They do not define support for future releases.
