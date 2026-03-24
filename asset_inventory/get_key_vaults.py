"""
Key Vault metadata inventory.

Enumerates all Key Vaults across accessible subscriptions (or a specific
subscription when AZURE_SUBSCRIPTION_ID is set) and exports their metadata
to an Excel file. The output is used as the input CSV for the access security
scripts (keyVaults_AccessPolicy.py, keyVaults_rbac.py).

Output: output/key_vaults.xlsx  (also saves output/key_vaults.csv)

Required permissions:
    Microsoft.KeyVault/vaults/read
    (via resource filter on the subscriptions/resources endpoint)
"""
import csv
import json
import logging
import os
import sys

import pandas as pd
import requests
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.auth import get_token
from shared.azure_api import get_subscriptions, paginated_get

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(_PROJECT_ROOT, "output")

TENANT_ID = os.environ["AZURE_TENANT_ID"]
CLIENT_ID = os.environ["AZURE_CLIENT_ID"]
CLIENT_SECRET = os.environ["AZURE_CLIENT_SECRET"]
SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")  # optional

RESOURCES_API_VERSION = "2021-04-01"


def get_key_vaults(subscription_id: str, token: str) -> list:
    """Retrieve all Key Vault resources for a subscription using a resource filter.

    Follows pagination via ``nextLink``.

    Args:
        subscription_id: Azure subscription ID.
        token: Azure Management API bearer token.

    Returns:
        List of Key Vault resource objects with normalized fields.
    """
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/resources?$filter=resourceType eq 'Microsoft.KeyVault/vaults'"
        f"&api-version={RESOURCES_API_VERSION}"
    )
    raw_items = paginated_get(url, token)
    return [
        {
            "SubscriptionId": subscription_id,
            "ID": item.get("id", ""),
            "Name": item.get("name", ""),
            "Type": item.get("type", ""),
            "Location": item.get("location", ""),
            "Tags": json.dumps(item.get("tags", {})) if item.get("tags") else "",
        }
        for item in raw_items
    ]


def main() -> None:
    """Entry point: collect Key Vault metadata across all accessible subscriptions."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_xlsx = os.path.join(OUTPUT_DIR, "key_vaults.xlsx")
    output_csv = os.path.join(OUTPUT_DIR, "key_vaults.csv")

    logger.info("Acquiring Azure Management token...")
    token = get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)

    subscriptions = get_subscriptions(token, subscription_id=SUBSCRIPTION_ID)

    all_vaults = []
    for sub_id in subscriptions:
        logger.info("Fetching Key Vaults for subscription: %s", sub_id)
        try:
            vaults = get_key_vaults(sub_id, token)
            logger.info("  Found %d vault(s).", len(vaults))
            all_vaults.extend(vaults)
        except requests.exceptions.HTTPError as exc:
            logger.error("HTTP error for subscription %s: %s", sub_id, exc.response.status_code)
        except requests.exceptions.RequestException as exc:
            logger.error("Request failed for subscription %s: %s", sub_id, exc)

    if not all_vaults:
        logger.warning("No Key Vaults found.")
        return

    # Save Excel for human review, CSV for downstream scripts.
    df = pd.DataFrame(all_vaults)
    df.to_excel(output_xlsx, index=False)
    df.to_csv(output_csv, index=False, encoding="utf-8")
    logger.info(
        "Exported %d vault(s) to '%s' and '%s'.", len(all_vaults), output_xlsx, output_csv
    )


if __name__ == "__main__":
    main()
