"""
User-Assigned Managed Identity (UAMI) inventory.

Enumerates all User-Assigned Managed Identities across accessible subscriptions
(or a specific subscription when AZURE_SUBSCRIPTION_ID is set), resolves each
identity's associated service principal display name via Microsoft Graph, and
exports the results to CSV.

Output: output/user_assigned_identities.csv

Required permissions:
    Microsoft.ManagedIdentity/userAssignedIdentities/read
    Graph: Application.Read.All (or equivalent)
"""
import csv
import logging
import os
import sys

import requests
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.auth import get_token, get_graph_token
from shared.azure_api import get_subscriptions
from shared.graph import get_service_principal_display_name

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(_PROJECT_ROOT, "output")

TENANT_ID = os.environ["AZURE_TENANT_ID"]
CLIENT_ID = os.environ["AZURE_CLIENT_ID"]
CLIENT_SECRET = os.environ["AZURE_CLIENT_SECRET"]
SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")  # optional

API_VERSION = "2024-11-30"


def get_user_assigned_identities(subscription_id: str, token: str) -> list:
    """Retrieve all User-Assigned Managed Identities for a subscription.

    Args:
        subscription_id: Azure subscription ID.
        token: Azure Management API bearer token.

    Returns:
        List of UAMI resource objects.
    """
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/providers/Microsoft.ManagedIdentity/userAssignedIdentities"
        f"?api-version={API_VERSION}"
    )
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json().get("value", [])


def save_to_csv(data: list, filepath: str) -> None:
    """Write UAMI inventory records to a CSV file.

    Args:
        data: List of flat dicts with identity fields.
        filepath: Destination file path.
    """
    fieldnames = [
        "resource_id", "resource_type", "resource_name",
        "client_id", "principal_id", "service_principal_display_name",
    ]
    with open(filepath, mode="w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
    logger.info("Exported %d record(s) to '%s'.", len(data), filepath)


def main() -> None:
    """Entry point: collect UAMI data across all accessible subscriptions."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "user_assigned_identities.csv")

    logger.info("Acquiring tokens...")
    mgmt_token = get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    graph_token = get_graph_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)

    subscriptions = get_subscriptions(mgmt_token, subscription_id=SUBSCRIPTION_ID)

    records = []
    spn_cache: dict = {}

    for sub_id in subscriptions:
        logger.info("Fetching User-Assigned Identities for subscription: %s", sub_id)
        try:
            identities = get_user_assigned_identities(sub_id, mgmt_token)
            for identity in identities:
                props = identity.get("properties", {})
                principal_id = props.get("principalId", "")
                records.append(
                    {
                        "resource_id": identity.get("id", ""),
                        "resource_type": identity.get("type", ""),
                        "resource_name": identity.get("name", ""),
                        "client_id": props.get("clientId", ""),
                        "principal_id": principal_id,
                        "service_principal_display_name": get_service_principal_display_name(
                            principal_id, graph_token, spn_cache
                        ),
                    }
                )
        except requests.exceptions.RequestException as exc:
            logger.error("Request failed for subscription %s: %s", sub_id, exc)

    save_to_csv(records, output_path)


if __name__ == "__main__":
    main()
