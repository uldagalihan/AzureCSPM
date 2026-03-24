"""
OAuth 2.0 token acquisition for Azure CSPM.

Provides helpers to obtain bearer tokens for the Azure Management API and
the Microsoft Graph API using the client-credentials flow.
"""
import logging

import requests

logger = logging.getLogger(__name__)

MANAGEMENT_RESOURCE = "https://management.azure.com/"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


def get_token(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    resource: str = MANAGEMENT_RESOURCE,
    timeout: int = 30,
) -> str:
    """Acquire an Azure AD access token via the client-credentials flow (v1 endpoint).

    Suitable for the Azure Management API and any resource that accepts the
    ``resource`` parameter (OAuth 2.0 v1 token endpoint).

    Args:
        tenant_id: Azure AD tenant (directory) ID.
        client_id: Application (client) ID of the registered app.
        client_secret: Client secret value for the registered app.
        resource: Target resource URI. Defaults to the Azure Management API.
        timeout: HTTP request timeout in seconds.

    Returns:
        Bearer access token string.

    Raises:
        requests.HTTPError: If the token endpoint returns a non-2xx response.
    """
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "resource": resource,
    }
    response = requests.post(url, data=payload, timeout=timeout)
    response.raise_for_status()
    return response.json()["access_token"]


def get_graph_token(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    timeout: int = 30,
) -> str:
    """Acquire a Microsoft Graph access token (v2.0 endpoint, scope-based).

    Uses the ``/.default`` scope which grants all application permissions
    configured for the app registration.

    Args:
        tenant_id: Azure AD tenant (directory) ID.
        client_id: Application (client) ID of the registered app.
        client_secret: Client secret value for the registered app.
        timeout: HTTP request timeout in seconds.

    Returns:
        Bearer access token string for Microsoft Graph.

    Raises:
        requests.HTTPError: If the token endpoint returns a non-2xx response.
    """
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": GRAPH_SCOPE,
    }
    response = requests.post(url, data=payload, timeout=timeout)
    response.raise_for_status()
    return response.json()["access_token"]
