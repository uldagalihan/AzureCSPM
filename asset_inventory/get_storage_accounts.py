"""
Azure Storage Account metadata inventory.

Enumerates all Storage Accounts across accessible subscriptions (or a specific
subscription when AZURE_SUBSCRIPTION_ID is set), extracts encryption, tier,
endpoint, and provisioning details, and exports the results to Excel.

Output: output/storage_account_inventory.xlsx

Required permissions:
    Microsoft.Storage/storageAccounts/read
"""
import logging
import os
import sys

import pandas as pd
import requests
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.auth import get_token
from shared.azure_api import get_subscriptions

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(_PROJECT_ROOT, "output")

TENANT_ID = os.environ["AZURE_TENANT_ID"]
CLIENT_ID = os.environ["AZURE_CLIENT_ID"]
CLIENT_SECRET = os.environ["AZURE_CLIENT_SECRET"]
SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")  # optional

STORAGE_API_VERSION = "2024-01-01"


def fetch_storage_accounts(subscription_id: str, token: str) -> list:
    """Retrieve all Storage Accounts for a subscription.

    Args:
        subscription_id: Azure subscription ID.
        token: Azure Management API bearer token.

    Returns:
        List of Storage Account resource objects.
    """
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/providers/Microsoft.Storage/storageAccounts"
        f"?api-version={STORAGE_API_VERSION}"
    )
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json().get("value", [])


def extract_endpoints(endpoints: dict) -> dict:
    """Extract named service endpoint URLs from the primaryEndpoints dict.

    Args:
        endpoints: The ``primaryEndpoints`` property dict from the API response.

    Returns:
        Flat dict with keys ``endpoint_<service>`` for each recognized service.
    """
    result = {}
    for service in ("web", "dfs", "blob", "file", "queue", "table"):
        result[f"endpoint_{service}"] = endpoints.get(service, "")
    return result


def process_storage_accounts(storage_accounts: list) -> list:
    """Flatten Storage Account resource objects into export-ready records.

    Args:
        storage_accounts: List of Storage Account objects from the Azure API.

    Returns:
        List of flat dicts with normalized fields.
    """
    records = []
    for sa in storage_accounts:
        props = sa.get("properties", {})
        encryption = props.get("encryption", {})
        blob_enc = encryption.get("services", {}).get("blob", {})
        file_enc = encryption.get("services", {}).get("file", {})
        endpoints = extract_endpoints(props.get("primaryEndpoints", {}))
        records.append(
            {
                "id": sa.get("id", ""),
                "name": sa.get("name", ""),
                "location": sa.get("location", ""),
                "kind": sa.get("kind", ""),
                "sku_name": sa.get("sku", {}).get("name", ""),
                "sku_tier": sa.get("sku", {}).get("tier", ""),
                "provisioning_state": props.get("provisioningState", ""),
                "supports_https_only": props.get("supportsHttpsTrafficOnly", ""),
                "primary_status": props.get("statusOfPrimary", ""),
                "secondary_status": props.get("statusOfSecondary", ""),
                "encryption_key_source": encryption.get("keySource", ""),
                "blob_encryption_enabled": blob_enc.get("enabled", ""),
                "file_encryption_enabled": file_enc.get("enabled", ""),
                **endpoints,
            }
        )
    return records


def main() -> None:
    """Entry point: collect Storage Account metadata across all accessible subscriptions."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "storage_account_inventory.xlsx")

    logger.info("Acquiring Azure Management token...")
    token = get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)

    subscriptions = get_subscriptions(token, subscription_id=SUBSCRIPTION_ID)
    all_records = []

    for sub_id in subscriptions:
        logger.info("Fetching Storage Accounts for subscription: %s", sub_id)
        try:
            accounts = fetch_storage_accounts(sub_id, token)
            processed = process_storage_accounts(accounts)
            logger.info("  Found %d account(s).", len(processed))
            all_records.extend(processed)
        except requests.exceptions.RequestException as exc:
            logger.error("Request failed for subscription %s: %s", sub_id, exc)

    if all_records:
        pd.DataFrame(all_records).to_excel(output_path, index=False)
        logger.info("Exported %d account(s) to '%s'.", len(all_records), output_path)
    else:
        logger.warning("No Storage Accounts found.")


if __name__ == "__main__":
    main()
