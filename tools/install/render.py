"""Pure renderers for installed-system configuration."""

from __future__ import annotations

from tools.install.model import InstallSpec


def networkd(spec: InstallSpec) -> str:
    lines = ["[Match]", "Name=en*", "", "[Network]"]
    if spec.network.mode == "dhcp":
        lines.extend(["DHCP=yes", "IPv6AcceptRA=yes"])
    else:
        lines.extend(
            [
                f"Address={spec.network.address}/{spec.network.prefix}",
                f"Gateway={spec.network.gateway}",
                *[f"DNS={resolver}" for resolver in spec.network.dns],
                "IPv6AcceptRA=no",
            ]
        )
    return "\n".join(lines) + "\n"


def nftables(spec: InstallSpec) -> str:
    ssh_rule = "\n        tcp dport 22 ct state new accept" if spec.firewall.ssh else ""
    return f"""#!/usr/bin/nft -f
flush ruleset

table inet filter {{
    chain input {{
        type filter hook input priority filter; policy drop;
        iifname "lo" accept
        ct state established,related accept
        meta l4proto {{ icmp, ipv6-icmp }} accept{ssh_rule}
    }}

    chain forward {{
        type filter hook forward priority filter; policy drop;
    }}

    chain output {{
        type filter hook output priority filter; policy accept;
    }}
}}
"""


def sshd(spec: InstallSpec) -> str:
    return (
        "PermitRootLogin no\n"
        "PasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\n"
        "PubkeyAuthentication yes\n"
        "AuthenticationMethods publickey\n"
        f"AllowUsers {spec.administrator.username}\n"
    )


def loader_entry(
    root_partition_uuid: str,
    title: str = "KITPro Linux Server",
    *,
    compatibility_graphics: bool = False,
) -> str:
    suffix = " - Compatibility Graphics" if compatibility_graphics else ""
    graphics = " nomodeset" if compatibility_graphics else ""
    return (
        f"title {title}{suffix}\n"
        "linux /vmlinuz-linux-lts\n"
        "initrd /initramfs-linux-lts.img\n"
        f"options root=PARTUUID={root_partition_uuid} rw "
        f"console=ttyS0,115200n8 console=tty0{graphics}\n"
    )


def fstab(esp_partition_uuid: str, root_partition_uuid: str) -> str:
    return (
        f"PARTUUID={root_partition_uuid} / ext4 defaults 0 1\n"
        f"PARTUUID={esp_partition_uuid} /efi vfat umask=0077 0 2\n"
    )
