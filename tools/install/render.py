"""Pure renderers for installed-system configuration."""

from __future__ import annotations

from tools.install.model import InstallSpec

SECURITY_BOOT_OPTIONS = (
    "lsm=landlock,lockdown,yama,integrity,apparmor,bpf apparmor=1 security=apparmor"
)


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
    root_flags: str | None = None,
) -> str:
    suffix = " - Compatibility Graphics" if compatibility_graphics else ""
    graphics = " nomodeset" if compatibility_graphics else ""
    flags = f" rootflags={root_flags}" if root_flags else ""
    return (
        f"title {title}{suffix}\n"
        "linux /vmlinuz-linux-lts\n"
        "initrd /initramfs-linux-lts.img\n"
        f"options root=PARTUUID={root_partition_uuid} rw{flags} "
        f"console=ttyS0,115200n8 console=tty0 {SECURITY_BOOT_OPTIONS}{graphics}\n"
    )


def fstab(esp_partition_uuid: str, root_partition_uuid: str) -> str:
    return (
        f"PARTUUID={root_partition_uuid} / ext4 defaults 0 1\n"
        f"PARTUUID={esp_partition_uuid} /efi vfat umask=0077 0 2\n"
    )


def fstab_from_plan(plan: dict[str, object]) -> str:
    """Render mounts from the authoritative ordered storage plan."""
    table = plan["partition_table"]
    assert isinstance(table, dict)
    esp = table["esp"]
    root = table["root"]
    assert isinstance(esp, dict) and isinstance(root, dict)
    root_options = ["defaults"]
    root_filesystem = root.get("inner_filesystem", root.get("filesystem", "ext4"))
    root_source = (
        root["mapper_device"]
        if "lvm" in table
        else f"/dev/mapper/{table['encryption']['mapper_name']}"
        if "encryption" in table
        else f"PARTUUID={root['partition_uuid']}"
    )
    if root_filesystem == "btrfs":
        root_options = ["subvol=@"]
        if table.get("compression") == "zstd":
            root_options.append("compress=zstd")
    lines = [
        f"{root_source} / {root_filesystem} {','.join(root_options)} 0 "
        + ("0" if root_filesystem == "btrfs" else "1"),
        f"PARTUUID={esp['partition_uuid']} /efi vfat umask=0077 0 2",
    ]
    if root_filesystem == "btrfs":
        for subvolume in table.get("subvolumes", []):
            if subvolume["mount_point"] == "/":
                continue
            options = [f"subvol={subvolume['name']}"]
            if table.get("compression") == "zstd":
                options.append("compress=zstd")
            lines.append(f"{root_source} {subvolume['mount_point']} btrfs {','.join(options)} 0 0")
    mount_items = table["lvm"]["logical_volumes"] if "lvm" in table else table.get("partitions", [])
    for partition in mount_items:
        role = partition.get("role")
        if role in {"esp", "root"}:
            continue
        if role == "swap":
            source = (
                partition["mapper_device"]
                if "lvm" in table
                else f"PARTUUID={partition['partition_uuid']}"
            )
            lines.append(f"{source} none swap defaults 0 0")
            continue
        mount_point = partition.get("mount_point")
        if mount_point:
            source = (
                partition["mapper_device"]
                if "lvm" in table
                else f"PARTUUID={partition['partition_uuid']}"
            )
            lines.append(f"{source} {mount_point} {partition['filesystem']} defaults 0 2")
    if "partitions" not in table:
        home = table.get("home")
        if isinstance(home, dict):
            lines.append(f"PARTUUID={home['partition_uuid']} /home ext4 defaults 0 2")
        swap = table.get("swap")
        if isinstance(swap, dict):
            lines.append(f"PARTUUID={swap['partition_uuid']} none swap defaults 0 0")
    return "\n".join(lines) + "\n"
