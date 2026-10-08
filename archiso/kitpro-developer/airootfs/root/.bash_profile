#!/usr/bin/env bash

current_tty=$(tty 2>/dev/null || true)
qemu_serial=false
if [[ -r /sys/firmware/qemu_fw_cfg/by_name/opt/kitpro/phase8-guided/raw \
   || -r /sys/firmware/qemu_fw_cfg/by_name/opt/kitpro/phase8-rescue/raw ]]; then
    qemu_serial=true
fi

# The fw_cfg device can become usable after the acceptance unit's initial
# ConditionPathExists check under slow TCG boot. A serial login is therefore a
# safe late activation point for the same idempotent systemd service. This does
# not run installer logic in the shell and is gated by the explicit Phase 4
# marker that the acceptance harness supplies.
if [[ $current_tty == /dev/ttyS0 \
   && -r /sys/firmware/qemu_fw_cfg/by_name/opt/kitpro/acceptance/raw ]]; then
    marker=/run/kitpro-media-acceptance-triggered
    if [[ ! -e $marker ]]; then
        touch "$marker"
        printf '%s\n' 'KITPRO_MEDIA_ACCEPTANCE_TRIGGERED installation'
        systemctl start --no-block kitpro-media-acceptance.service
    fi
fi

# Physical media owns tty1. QEMU's guided acceptance remains serial-driven via
# an explicit fw_cfg marker; an ordinary physical serial login stays a shell
# and cannot race a second installer against the local console.
# Exactly one console owns automatic mode startup. Physical media uses tty1;
# explicit QEMU acceptance uses ttyS0. Starting both against the same live
# runtime races keyring preparation and can deadlock rescue startup.
if [[ ( $current_tty == /dev/tty1 && $qemu_serial == false ) \
   || ( $current_tty == /dev/ttyS0 && $qemu_serial == true ) ]]; then
    marker=/run/kitpro-console-mode-started-${current_tty##*/}
    if [[ ! -e $marker ]]; then
        touch "$marker"
        if [[ -r /sys/firmware/qemu_fw_cfg/by_name/opt/kitpro/phase8-rescue/raw ]]; then
            printf '%s\n' 'KITPRO_MEDIA_MODE_STARTED rescue'
            exec /usr/local/bin/kitpro-rescue shell
        elif grep -qw 'kitpro.mode=install' /proc/cmdline; then
            printf '%s\n' 'KITPRO_MEDIA_MODE_STARTED install'
            exec /usr/local/bin/kitpro-installer
        elif grep -qw 'kitpro.mode=rescue' /proc/cmdline; then
            printf '%s\n' 'KITPRO_MEDIA_MODE_STARTED rescue'
            exec /usr/local/bin/kitpro-rescue shell
        fi
    fi
fi

printf '%s\n' 'KITPro Linux Server development shell'
printf '%s\n' "Run 'kitpro-installer' or 'kitpro-rescue --help'."
