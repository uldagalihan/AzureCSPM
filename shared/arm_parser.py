"""
Azure Resource Manager (ARM) ID parsing utilities.

All Azure resources carry a canonical ID of the form:
    /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}

The helpers in this module extract the meaningful components from those IDs
so that individual scripts do not need to duplicate the regex logic.
"""
import re
from typing import Optional, Tuple

# Generic 5-part ARM pattern (subscription, RG, provider, type, name).
_ARM_PATTERN = re.compile(
    r"/subscriptions/(?P<subscription_id>[^/]+)"
    r"/resourceGroups/(?P<resource_group>[^/]+)"
    r"/providers/(?P<provider>[^/]+)"
    r"/(?P<resource_type>[^/]+)"
    r"/(?P<resource_name>[^/]+)",
    re.IGNORECASE,
)

# Specialised patterns for the most common resource types.
_VM_PATTERN = re.compile(
    r"/subscriptions/(?P<subscription_id>[^/]+)"
    r"/resourceGroups/(?P<resource_group>[^/]+)"
    r"/providers/Microsoft\.Compute/virtualMachines"
    r"/(?P<resource_name>[^/]+)",
    re.IGNORECASE,
)

_KV_PATTERN = re.compile(
    r"/subscriptions/(?P<subscription_id>[^/]+)"
    r"/resourceGroups/(?P<resource_group>[^/]+)"
    r"/providers/Microsoft\.KeyVault/vaults"
    r"/(?P<resource_name>[^/]+)",
    re.IGNORECASE,
)

_UAMI_PATTERN = re.compile(
    r"/subscriptions/(?P<subscription_id>[^/]+)"
    r"/resourceGroups/(?P<resource_group>[^/]+)"
    r"/providers/Microsoft\.ManagedIdentity/userAssignedIdentities"
    r"/(?P<resource_name>[^/]+)",
    re.IGNORECASE,
)

_NIC_PATTERN = re.compile(
    r"/subscriptions/(?P<subscription_id>[^/]+)"
    r"/resourceGroups/(?P<resource_group>[^/]+)"
    r"/providers/Microsoft\.Network/networkInterfaces"
    r"/(?P<resource_name>[^/]+)",
    re.IGNORECASE,
)

_PUBLIC_IP_PATTERN = re.compile(
    r"/subscriptions/(?P<subscription_id>[^/]+)"
    r"/resourceGroups/(?P<resource_group>[^/]+)"
    r"/providers/Microsoft\.Network/publicIPAddresses"
    r"/(?P<resource_name>[^/]+)",
    re.IGNORECASE,
)


def parse_arm_id(
    arm_id: str,
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Parse a generic Azure ARM resource ID into its five components.

    Args:
        arm_id: Full ARM resource ID string.

    Returns:
        Tuple of (subscription_id, resource_group, provider, resource_type,
        resource_name). All elements are ``None`` if the ID cannot be parsed.
    """
    match = _ARM_PATTERN.match(arm_id)
    if match:
        return (
            match.group("subscription_id"),
            match.group("resource_group"),
            match.group("provider"),
            match.group("resource_type"),
            match.group("resource_name"),
        )
    return None, None, None, None, None


def parse_vm_arm_id(arm_id: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Parse a Virtual Machine ARM resource ID.

    Args:
        arm_id: Full ARM resource ID for a VM resource.

    Returns:
        Tuple of (subscription_id, resource_group, vm_name).
        All elements are ``None`` if the ID cannot be parsed.
    """
    match = _VM_PATTERN.match(arm_id)
    if match:
        return (
            match.group("subscription_id"),
            match.group("resource_group"),
            match.group("resource_name"),
        )
    return None, None, None


def parse_kv_arm_id(arm_id: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Parse a Key Vault ARM resource ID.

    Args:
        arm_id: Full ARM resource ID for a Key Vault resource.

    Returns:
        Tuple of (subscription_id, resource_group, vault_name).
        All elements are ``None`` if the ID cannot be parsed.
    """
    match = _KV_PATTERN.match(arm_id)
    if match:
        return (
            match.group("subscription_id"),
            match.group("resource_group"),
            match.group("resource_name"),
        )
    return None, None, None


def parse_uami_arm_id(arm_id: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Parse a User-Assigned Managed Identity (UAMI) ARM resource ID.

    Args:
        arm_id: Full ARM resource ID for a UAMI resource.

    Returns:
        Tuple of (subscription_id, resource_group, identity_name).
        All elements are ``None`` if the ID cannot be parsed.
    """
    match = _UAMI_PATTERN.match(arm_id)
    if match:
        return (
            match.group("subscription_id"),
            match.group("resource_group"),
            match.group("resource_name"),
        )
    return None, None, None


def parse_nic_arm_id(arm_id: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Parse a Network Interface (NIC) ARM resource ID.

    Args:
        arm_id: Full ARM resource ID for a NIC resource.

    Returns:
        Tuple of (subscription_id, resource_group, nic_name).
        All elements are ``None`` if the ID cannot be parsed.
    """
    match = _NIC_PATTERN.match(arm_id)
    if match:
        return (
            match.group("subscription_id"),
            match.group("resource_group"),
            match.group("resource_name"),
        )
    return None, None, None


def parse_public_ip_arm_id(
    arm_id: str,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Parse a Public IP Address ARM resource ID.

    Args:
        arm_id: Full ARM resource ID for a Public IP Address resource.

    Returns:
        Tuple of (subscription_id, resource_group, ip_name).
        All elements are ``None`` if the ID cannot be parsed.
    """
    match = _PUBLIC_IP_PATTERN.match(arm_id)
    if match:
        return (
            match.group("subscription_id"),
            match.group("resource_group"),
            match.group("resource_name"),
        )
    return None, None, None
