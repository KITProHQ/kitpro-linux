"""Pure storage inventory normalization and eligibility policy.

Hardware discovery remains an environmental concern.  This module owns the
side-effect-free vocabulary shared by the native installer and the privileged
backend so a disk has one eligibility meaning throughout the workflow.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class StorageRejection(StrEnum):
    INSTALLATION_MEDIA = "installation-media"
    RUNNING_SYSTEM = "running-system"
    READ_ONLY = "read-only"
    READ_ONLY_UNKNOWN = "read-only-status-unavailable"
    MOUNTED = "mounted"
    MISSING_STABLE_IDENTITY = "missing-stable-identity"
    DUPLICATE_STABLE_IDENTITY = "duplicate-stable-identity"
    UNSUPPORTED_DEVICE = "unsupported-device-configuration"
    INCOMPLETE_OBSERVATION = "incomplete-observation"
    INSUFFICIENT_CAPACITY = "insufficient-capacity"


REJECTION_MESSAGES: dict[str, str] = {
    StorageRejection.INSTALLATION_MEDIA: "active installation media",
    StorageRejection.RUNNING_SYSTEM: "backs the running system",
    StorageRejection.READ_ONLY: "device is read-only",
    StorageRejection.READ_ONLY_UNKNOWN: "read-only status could not be verified",
    StorageRejection.MOUNTED: "device or a child filesystem is mounted",
    StorageRejection.MISSING_STABLE_IDENTITY: "no stable device identity was reported",
    StorageRejection.DUPLICATE_STABLE_IDENTITY: "stable identity is shared by another disk",
    StorageRejection.UNSUPPORTED_DEVICE: "device configuration is unsupported",
    StorageRejection.INCOMPLETE_OBSERVATION: "required device facts could not be inspected",
    StorageRejection.INSUFFICIENT_CAPACITY: "target disk is too small for the installation minimum",
}


@dataclass(frozen=True, slots=True)
class StorageEligibility:
    """Selection policy resulting from one normalized storage observation."""

    eligible: bool
    requires_destructive_confirmation: bool
    rejection_reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "eligible": self.eligible,
            "requires_destructive_confirmation": self.requires_destructive_confirmation,
            "rejection_reasons": list(self.rejection_reasons),
        }


def _normalized(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    result = " ".join(value.strip().lower().split())
    return result or None


def stable_identity_tokens(identity: Mapping[str, Any]) -> tuple[str, ...]:
    """Return normalized identifiers suitable for ambiguity detection."""
    tokens: set[str] = set()
    for field in ("wwn", "serial"):
        value = _normalized(identity.get(field))
        if value:
            tokens.add(f"{field}:{value}")
    stable_ids = identity.get("stable_ids", ())
    if isinstance(stable_ids, (list, tuple)):
        for item in stable_ids:
            value = _normalized(item)
            if value:
                tokens.add(f"by-id:{value}")
    return tuple(sorted(tokens))


def duplicate_identity_tokens(
    identities: Iterable[Mapping[str, Any]],
) -> frozenset[str]:
    """Return identifiers that occur in more than one disk observation."""
    counts: dict[str, int] = {}
    for identity in identities:
        for token in stable_identity_tokens(identity):
            counts[token] = counts.get(token, 0) + 1
    return frozenset(token for token, count in counts.items() if count > 1)


def evaluate_storage_eligibility(
    *,
    target_type: str,
    device_type: str,
    size_bytes: int,
    minimum_capacity_bytes: int,
    identity: Mapping[str, Any],
    mounted_paths: Iterable[str],
    read_only: bool | None,
    protection_reasons: Iterable[str] = (),
    observation_errors: Iterable[str] = (),
    duplicate_tokens: Iterable[str] = (),
) -> StorageEligibility:
    """Apply fail-closed selection rules to normalized discovery facts."""
    reasons: set[str] = set(protection_reasons)
    if target_type == "block":
        if device_type != "disk":
            reasons.add(StorageRejection.UNSUPPORTED_DEVICE)
        if read_only is True:
            reasons.add(StorageRejection.READ_ONLY)
        elif read_only is None:
            reasons.add(StorageRejection.READ_ONLY_UNKNOWN)
        identity_tokens = stable_identity_tokens(identity)
        if not identity_tokens:
            reasons.add(StorageRejection.MISSING_STABLE_IDENTITY)
        if set(identity_tokens) & set(duplicate_tokens):
            reasons.add(StorageRejection.DUPLICATE_STABLE_IDENTITY)
    elif target_type != "image":
        reasons.add(StorageRejection.UNSUPPORTED_DEVICE)
    if tuple(mounted_paths):
        reasons.add(StorageRejection.MOUNTED)
    if size_bytes < minimum_capacity_bytes:
        reasons.add(StorageRejection.INSUFFICIENT_CAPACITY)
    if tuple(observation_errors):
        reasons.add(StorageRejection.INCOMPLETE_OBSERVATION)
    ordered = tuple(sorted(str(reason) for reason in reasons))
    return StorageEligibility(
        eligible=not ordered,
        requires_destructive_confirmation=not ordered,
        rejection_reasons=ordered,
    )


def rejection_message(reason: str) -> str:
    return REJECTION_MESSAGES.get(reason, reason.replace("-", " "))
