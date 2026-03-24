"""
Virtual Machine extension inventory.

For each VM listed in the input CSV, retrieves all installed extensions
(publisher, type handler version, provisioning state) and exports the
results to CSV.

Expected input:  output/vm_inventory.csv  (column: ID)
Output:          output/vm_extensions.csv

Required permissions:
    Microsoft.Compute/virtualMachines/extensions/read
"""
import csv
import logging
import os
import sys

import requests
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.auth import get_token
from shared.arm_parser import parse_vm_arm_id

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(_PROJECT_ROOT, "output")

TENANT_ID = os.environ["AZURE_TENANT_ID"]
CLIENT_ID = os.environ["AZURE_CLIENT_ID"]
CLIENT_SECRET = os.environ["AZURE_CLIENT_SECRET"]

EXTENSIONS_API_VERSION = "2024-11-01"


def get_vm_extensions(
    subscription_id: str, resource_group: str, vm_name: str, token: str
) -> list:
    """Retrieve all extensions installed on a Virtual Machine.

    Args:
        subscription_id: Azure subscription ID.
        resource_group: Resource group containing the VM.
        vm_name: Name of the Virtual Machine.
        token: Azure Management API bearer token.

    Returns:
        List of extension resource objects.
    """
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Compute/virtualMachines/{vm_name}"
        f"/extensions?api-version={EXTENSIONS_API_VERSION}"
    )
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json().get("value", [])


def collect_extensions(input_csv: str, output_csv: str, token: str) -> None:
    """Iterate over VM IDs in the input CSV and collect extension data.

    Args:
        input_csv: Path to the VM inventory CSV (must have an ``ID`` column).
        output_csv: Path for the output CSV file.
        token: Azure Management API bearer token.
    """
    with open(input_csv, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)

    records = []
    for row in rows:
        vm_id = row.get("ID", "")
        sub_id, rg, vm_name = parse_vm_arm_id(vm_id)
        if not sub_id:
            logger.warning("Could not parse VM ARM ID: %s", vm_id)
            continue

        try:
            extensions = get_vm_extensions(sub_id, rg, vm_name, token)
            for ext in extensions:
                ext_props = ext.get("properties", {})
                records.append(
                    {
                        "vm_id": vm_id,
                        "vm_name": vm_name,
                        "extension_name": ext.get("name", ""),
                        "publisher": ext_props.get("publisher", ""),
                        "version": ext_props.get("typeHandlerVersion", ""),
                        "provisioning_state": ext_props.get("provisioningState", ""),
                    }
                )
        except requests.exceptions.HTTPError as exc:
            logger.error("HTTP error fetching extensions for VM '%s': %s", vm_name, exc)

    fieldnames = ["vm_id", "vm_name", "extension_name", "publisher", "version", "provisioning_state"]
    with open(output_csv, mode="w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)
    logger.info("Exported %d extension record(s) to '%s'.", len(records), output_csv)


def main() -> None:
    """Entry point: collect VM extension data from the VM inventory CSV."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    input_csv = os.path.join(OUTPUT_DIR, "vm_inventory.csv")
    output_csv = os.path.join(OUTPUT_DIR, "vm_extensions.csv")

    logger.info("Acquiring Azure Management token...")
    token = get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)

    logger.info("Collecting VM extension data...")
    collect_extensions(input_csv, output_csv, token)


if __name__ == "__main__":
    main()
