"""
Managed disk encryption inventory.

Retrieves all managed disks for the first accessible subscription (or the
specified subscription when AZURE_SUBSCRIPTION_ID is set) and exports
disk size, encryption type, and CMK/Key Vault key URL details to CSV.

Output: output/disk_inventory.csv

Required permissions:
    Microsoft.Compute/disks/read
"""
import csv
import logging
import os
import sys

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

DISK_API_VERSION = "2024-03-02"


def get_disk_details(subscription_id: str, token: str) -> list:
    """Retrieve all managed disks for a subscription.

    Args:
        subscription_id: Azure subscription ID.
        token: Azure Management API bearer token.

    Returns:
        List of managed disk resource objects.
    """
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/providers/Microsoft.Compute/disks?api-version={DISK_API_VERSION}"
    )
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json().get("value", [])


def extract_disk_records(disks: list) -> list:
    """Flatten managed disk objects into export-ready records.

    Extracts the Key Vault key URL when a Customer-Managed Key (CMK) is
    configured via ``encryptionSettingsCollection``.

    Args:
        disks: List of managed disk objects from the Azure API.

    Returns:
        List of flat dicts with disk metadata.
    """
    records = []
    for disk in disks:
        props = disk.get("properties", {})
        encryption = props.get("encryption", {})
        encryption_settings = props.get("encryptionSettingsCollection", {}).get(
            "encryptionSettings", []
        )
        # Extract CMK Key Vault key URL if present.
        key_vault_key_url = ""
        if encryption_settings:
            kek = encryption_settings[0].get("keyEncryptionKey", {})
            key_vault_key_url = kek.get("keyUrl", "")

        records.append(
            {
                "id": disk.get("id", ""),
                "name": disk.get("name", ""),
                "location": disk.get("location", ""),
                "disk_size_gb": props.get("diskSizeGB", ""),
                "encryption_type": encryption.get("type", ""),
                "key_vault_key_url": key_vault_key_url,
            }
        )
    return records


def save_to_csv(records: list, filepath: str) -> None:
    """Write disk inventory records to a CSV file.

    Args:
        records: List of flat dicts produced by :func:`extract_disk_records`.
        filepath: Destination file path.
    """
    fieldnames = ["id", "name", "location", "disk_size_gb", "encryption_type", "key_vault_key_url"]
    with open(filepath, mode="w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)
    logger.info("Exported %d disk record(s) to '%s'.", len(records), filepath)


def main() -> None:
    """Entry point: collect managed disk data across all accessible subscriptions."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "disk_inventory.csv")

    logger.info("Acquiring Azure Management token...")
    token = get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)

    subscriptions = get_subscriptions(token, subscription_id=SUBSCRIPTION_ID)
    all_records = []

    for sub_id in subscriptions:
        logger.info("Fetching managed disks for subscription: %s", sub_id)
        try:
            disks = get_disk_details(sub_id, token)
            records = extract_disk_records(disks)
            logger.info("  Found %d disk(s).", len(records))
            all_records.extend(records)
        except requests.exceptions.HTTPError as exc:
            logger.error("HTTP error for subscription %s: %s", sub_id, exc.response.status_code)
        except requests.exceptions.RequestException as exc:
            logger.error("Request failed for subscription %s: %s", sub_id, exc)

    save_to_csv(all_records, output_path)


if __name__ == "__main__":
    main()
