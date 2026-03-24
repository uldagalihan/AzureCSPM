"""
Microsoft Graph API helpers for Azure CSPM.

Provides principal display-name resolution for users, groups,
service principals, and devices via the Microsoft Graph v1.0 API.
"""
import logging
from typing import Dict, Optional

import requests

logger = logging.getLogger(__name__)

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# Maps Azure RBAC principal types to their Graph API collection endpoints.
_PRINCIPAL_ENDPOINTS: Dict[str, str] = {
    "User": "users",
    "Group": "groups",
    "ForeignGroup": "groups",
    "ServicePrincipal": "servicePrincipals",
    "Device": "devices",
}


def get_principal_display_name(
    principal_id: str,
    principal_type: str,
    graph_token: str,
    cache: Dict[str, str],
    timeout: int = 30,
) -> str:
    """Resolve an Azure AD principal's display name via the Microsoft Graph API.

    Results are stored in *cache* by ``principal_id`` to avoid redundant
    API calls within the same script run. The cache dict is managed by the
    caller and can be shared across multiple calls.

    Args:
        principal_id: Object ID (GUID) of the Azure AD principal.
        principal_type: Type string from the role-assignment (e.g. ``"User"``,
            ``"ServicePrincipal"``, ``"Group"``, ``"Device"``).
        graph_token: Bearer token for Microsoft Graph.
        cache: Mutable dict used as an in-memory lookup cache.
        timeout: HTTP request timeout in seconds.

    Returns:
        Display name string, or one of ``"Not Found"``, ``"Forbidden"``,
        ``"Lookup Failed"`` when the lookup cannot be completed.
    """
    if principal_id in cache:
        return cache[principal_id]

    endpoint = _PRINCIPAL_ENDPOINTS.get(principal_type)
    if endpoint:
        url = f"{_GRAPH_BASE}/{endpoint}/{principal_id}"
    else:
        # Fall back to directoryObjects for unrecognised principal types.
        url = f"{_GRAPH_BASE}/directoryObjects/{principal_id}"

    headers = {"Authorization": f"Bearer {graph_token}"}
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
    except requests.exceptions.RequestException as exc:
        logger.warning("Graph API request failed for principal %s: %s", principal_id, exc)
        cache[principal_id] = "Lookup Failed"
        return "Lookup Failed"

    if response.status_code == 404:
        display_name = "Not Found"
    elif response.status_code == 403:
        display_name = "Forbidden"
    elif response.status_code == 200:
        data = response.json()
        # Different object types expose the name under different fields.
        display_name = (
            data.get("displayName")
            or data.get("appDisplayName")
            or data.get("deviceId")
            or "Unnamed"
        )
    else:
        logger.warning(
            "Unexpected Graph response for %s: HTTP %s — %s",
            principal_id,
            response.status_code,
            response.text[:200],
        )
        display_name = "Lookup Failed"

    cache[principal_id] = display_name
    return display_name


def get_service_principal_display_name(
    principal_id: str,
    graph_token: str,
    cache: Dict[str, str],
    timeout: int = 30,
) -> str:
    """Convenience wrapper for resolving a Service Principal display name.

    Args:
        principal_id: Object ID of the service principal.
        graph_token: Bearer token for Microsoft Graph.
        cache: Mutable dict used as an in-memory lookup cache.
        timeout: HTTP request timeout in seconds.

    Returns:
        Display name string, or a failure description string.
    """
    return get_principal_display_name(
        principal_id=principal_id,
        principal_type="ServicePrincipal",
        graph_token=graph_token,
        cache=cache,
        timeout=timeout,
    )


def get_display_name_and_type(
    object_id: str,
    graph_token: str,
    cache: Dict[str, str],
    timeout: int = 30,
) -> tuple:
    """Probe multiple Graph endpoints to resolve a principal's name and type.

    Used when the principal type is not known in advance (e.g. Key Vault
    access policies which only expose an objectId).

    Args:
        object_id: Azure AD object ID (GUID).
        graph_token: Bearer token for Microsoft Graph.
        cache: Mutable dict used as an in-memory lookup cache.
        timeout: HTTP request timeout in seconds.

    Returns:
        Tuple of (display_name: str, principal_type: str).
    """
    if object_id in cache:
        return cache[object_id]

    headers = {"Authorization": f"Bearer {graph_token}"}
    probes = [
        (f"{_GRAPH_BASE}/users/{object_id}", "User"),
        (f"{_GRAPH_BASE}/groups/{object_id}", "Group"),
        (f"{_GRAPH_BASE}/servicePrincipals/{object_id}", "ServicePrincipal"),
    ]
    for url, principal_type in probes:
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
        except requests.exceptions.RequestException:
            continue
        if resp.status_code == 200:
            data = resp.json()
            name = data.get("displayName") or data.get("appDisplayName") or "Unnamed"
            result = (name, principal_type)
            cache[object_id] = result
            return result

    result = ("Not Found", "Unknown")
    cache[object_id] = result
    return result
