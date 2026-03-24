"""
Core Azure Management REST API helpers.

Provides subscription listing (with optional single-subscription override) and
a generic paginated GET helper that follows ``nextLink`` responses.
"""
import logging
from typing import List, Optional

import requests

logger = logging.getLogger(__name__)

_SUBSCRIPTIONS_URL = "https://management.azure.com/subscriptions?api-version=2020-01-01"


def get_subscriptions(
    token: str,
    subscription_id: Optional[str] = None,
    timeout: int = 30,
) -> List[str]:
    """Return the list of subscription IDs to process.

    If *subscription_id* is provided (e.g. from the ``AZURE_SUBSCRIPTION_ID``
    environment variable), it is returned as a single-element list and the API
    is not called.  Otherwise, all subscriptions accessible to the service
    principal are enumerated.

    Args:
        token: Azure Management API bearer token.
        subscription_id: Optional subscription ID override.
        timeout: HTTP request timeout in seconds.

    Returns:
        List of subscription ID strings.

    Raises:
        requests.HTTPError: If the subscriptions API call returns an error.
    """
    if subscription_id:
        logger.info("Using explicit subscription: %s", subscription_id)
        return [subscription_id]

    logger.info("Enumerating all accessible subscriptions...")
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(_SUBSCRIPTIONS_URL, headers=headers, timeout=timeout)
    response.raise_for_status()
    subs = [sub["subscriptionId"] for sub in response.json().get("value", [])]
    logger.info("Found %d subscription(s).", len(subs))
    return subs


def paginated_get(url: str, token: str, timeout: int = 30) -> List[dict]:
    """Fetch all pages from a paginated Azure REST API endpoint.

    Follows the ``nextLink`` field in each response until exhausted.

    Args:
        url: Initial request URL (may include query parameters).
        token: Azure Management API bearer token.
        timeout: HTTP request timeout in seconds.

    Returns:
        Flat list of all resource objects collected across all pages.

    Raises:
        requests.HTTPError: If any page request returns a non-2xx response.
    """
    headers = {"Authorization": f"Bearer {token}"}
    results: List[dict] = []
    page = 1
    while url:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        batch = data.get("value", [])
        results.extend(batch)
        logger.debug("Page %d: retrieved %d item(s).", page, len(batch))
        url = data.get("nextLink")
        page += 1
    return results
