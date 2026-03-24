"""
System-Assigned Managed Identity inventory.

For each VM resource ID listed in an input CSV, queries the system-assigned
managed identity endpoint and resolves the associated service principal name
via Microsoft Graph.

Expected input:  output/vm_inventory.csv  (column: ID)
Output:          output/system_assigned_identities.csv

Required permissions:
    Microsoft.ManagedIdentity/identities/read
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
from shared.arm_parser import parse_arm_id
from shared.graph import get_service_principal_display_name

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(_PROJECT_ROOT, "output")

TENANT_ID = os.environ["AZURE_TENANT_ID"]
CLIENT_ID = os.environ["AZURE_CLIENT_ID"]
CLIENT_SECRET = os.environ["AZURE_CLIENT_SECRET"]

API_VERSION = "2024-11-30"


def load_vm_ids(filepath: str) -> list:
    """Read VM resource IDs from a CSV file.

    Args:
        filepath: Path to the CSV file. Must contain an ``ID`` column.

    Returns:
        List of ARM resource ID strings.
    """
    ids = []
    with open(filepath, mode="r", newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            if "ID" in row and row["ID"]:
                ids.append(row["ID"])
    return ids


def get_system_assigned_identity(resource_scope: str, token: str) -> dict | None:
    """Query the system-assigned managed identity for a given resource scope.

    Args:
        resource_scope: Full ARM path of the resource (e.g. ``/subscriptions/.../vms/myvm``).
        token: Azure Management API bearer token.

    Returns:
        Identity resource dict, or ``None`` if not found (404).
    """
    url = (
        f"https://management.azure.com{resource_scope}"
        f"/providers/Microsoft.ManagedIdentity/identities/default"
        f"?api-version={API_VERSION}"
    )
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=30)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return response.json()


def save_to_csv(data: list, filepath: str) -> None:
    """Write system-assigned identity records to a CSV file.

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
    """Entry point: collect system-assigned identity data for all VMs in the input CSV."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # SAFETY FIX: replaced hardcoded absolute OneDrive path with a relative output/ path.
    input_path = os.path.join(OUTPUT_DIR, "vm_inventory.csv")
    output_path = os.path.join(OUTPUT_DIR, "system_assigned_identities.csv")

    logger.info("Acquiring tokens...")
    mgmt_token = get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    graph_token = get_graph_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)

    vm_ids = load_vm_ids(input_path)
    logger.info("Loaded %d VM ID(s).", len(vm_ids))

    records = []
    spn_cache: dict = {}

    for vm_id in vm_ids:
        sub, rg, provider, resource_type, resource_name = parse_arm_id(vm_id)
        if not all([sub, rg, provider, resource_type, resource_name]):
            logger.warning("Could not parse ARM ID: %s", vm_id)
            continue

        scope = f"/subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{resource_type}/{resource_name}"
        logger.info("Fetching system-assigned identity for: %s", resource_name)

        try:
            identity = get_system_assigned_identity(scope, mgmt_token)
            if not identity:
                logger.info("No system-assigned identity found for: %s", resource_name)
                continue

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
            logger.error("API error for resource '%s': %s", resource_name, exc)

    save_to_csv(records, output_path)


if __name__ == "__main__":
    main()
