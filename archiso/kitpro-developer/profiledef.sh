#!/usr/bin/env bash
# shellcheck disable=SC2034

iso_name="kitpro-linux-server"
iso_label="KITPRO_0_8_DEV"
iso_publisher="KITPro <https://kitpro.us>"
iso_application="KITPro Linux Server Developer Installation Media"
iso_version="0.8.0-dev.18"
install_dir="kitpro"
buildmodes=('iso')
bootmodes=('uefi.systemd-boot')
arch="x86_64"
pacman_conf="pacman.conf"
airootfs_image_type="squashfs"
airootfs_image_tool_options=(
  '-comp' 'xz'
  '-Xbcj' 'x86,arm64'
  '-b' '1M'
  '-Xdict-size' '1M'
  '-processors' '4'
  '-wildcards'
  '-e' 'var/cache/ldconfig/aux-cache'
)
file_permissions=(
  ["/root"]="0:0:700"
  ["/root/.bash_profile"]="0:0:600"
  ["/usr/local/bin/kitpro-install"]="0:0:755"
  ["/usr/local/bin/kitpro-installer"]="0:0:755"
  ["/usr/local/bin/kitpro-rescue"]="0:0:755"
  ["/usr/local/lib/kitpro-linux/media-acceptance"]="0:0:755"
  ["/usr/bin/kitpro-health"]="0:0:755"
  ["/usr/bin/kitpro-kernel-status"]="0:0:755"
  ["/usr/bin/kitpro-support-bundle"]="0:0:755"
  ["/usr/lib/kitpro-linux/kernel-lifecycle"]="0:0:755"
  ["/usr/lib/kitpro-linux/system-health"]="0:0:755"
  ["/usr/lib/kitpro-linux/support-bundle"]="0:0:755"
  ["/opt/kitpro-linux/runtime/kernel-lifecycle"]="0:0:755"
  ["/opt/kitpro-linux/runtime/kitpro-health"]="0:0:755"
  ["/opt/kitpro-linux/runtime/kitpro-kernel-status"]="0:0:755"
  ["/opt/kitpro-linux/runtime/kitpro-support-bundle"]="0:0:755"
  ["/opt/kitpro-linux/runtime/support-bundle"]="0:0:755"
  ["/opt/kitpro-linux/runtime/system-health"]="0:0:755"
)
