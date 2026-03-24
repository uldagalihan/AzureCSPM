"""
VM-level RBAC (role-based access control) inventory.

For each Virtual Machine listed in an input CSV, retrieves all role assignments
at the VM resource scope, resolves role definition names and principal display
names via Microsoft Graph, and exports the results to CSV.

Expected input:  output/vm_inventory.csv  (column: ID)
Output:          output/vm_based_rbac.csv

Required permissions:
    Microsoft.Authorization/roleAssignments/read
    Microsoft.Authorization/roleDefinitions/read
    Graph: User.Read.All, Group.Read.All, Application.Read.All (or equivalent)
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
from shared.graph import get_principal_display_name

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(_PROJECT_ROOT, "output")

TENANT_ID = os.environ["AZURE_TENANT_ID"]
CLIENT_ID = os.environ["AZURE_CLIENT_ID"]
CLIENT_SECRET = os.environ["AZURE_CLIENT_SECRET"]

ROLE_ASSIGNMENTS_API_VERSION = "2022-04-01"
ROLE_DEFINITIONS_API_VERSION = "2022-04-01"


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


def get_role_assignments(
    subscription_id: str, rg: str, provider: str, resource_type: str, resource_name: str, token: str
) -> list:
    """Retrieve role assignments scoped to a specific VM resource.

    Args:
        subscription_id: Azure subscription ID.
        rg: Resource group name.
        provider: Resource provider namespace.
        resource_type: Resource type segment.
        resource_name: Name of the VM.
        token: Azure Management API bearer token.

    Returns:
        List of role assignment objects (may be empty if resource not found).
    """
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/resourceGroups/{rg}/providers/{provider}/{resource_type}/{resource_name}"
        f"/providers/Microsoft.Authorization/roleAssignments"
        f"?api-version={ROLE_ASSIGNMENTS_API_VERSION}"
    )
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=30)
    if response.status_code == 404:
        return []
    response.raise_for_status()
    return response.json().get("value", [])


def get_role_definition(role_def_id: str, token: str, cache: dict) -> tuple:
    """Retrieve the human-readable name and description of a role definition.

    Args:
        role_def_id: Full ARM resource ID of the role definition.
        token: Azure Management API bearer token.
        cache: Mutable dict for caching results by role_def_id.

    Returns:
        Tuple of (role_name, description).
    """
    if role_def_id in cache:
        return cache[role_def_id]
    url = f"https://management.azure.com{role_def_id}?disambiguation_dummy&api-version={ROLE_DEFINITIONS_API_VERSION}"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    props = response.json().get("properties", {})
    result = (props.get("roleName", ""), props.get("description", ""))
    cache[role_def_id] = result
    return result


def save_to_csv(data: list, filepath: str) -> None:
    """Write VM RBAC records to a CSV file.

    Args:
        data: List of flat dicts with RBAC fields.
        filepath: Destination file path.
    """
    fieldnames = [
        "vm_id", "role_definition_id", "role_name", "description",
        "principal_id", "principal_type", "display_name",
    ]
    with open(filepath, mode="w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
    logger.info("Exported %d record(s) to '%s'.", len(data), filepath)


def main() -> None:
    """Entry point: collect RBAC assignments for all VMs in the input CSV."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # SAFETY FIX: replaced hardcoded absolute OneDrive path with a relative output/ path.
    input_path = os.path.join(OUTPUT_DIR, "vm_inventory.csv")
    output_path = os.path.join(OUTPUT_DIR, "vm_based_rbac.csv")

    logger.info("Acquiring tokens...")
    mgmt_token = get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    graph_token = get_graph_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)

    vm_ids = load_vm_ids(input_path)
    logger.info("Loaded %d VM ID(s).", len(vm_ids))

    records = []
    role_def_cache: dict = {}
    principal_cache: dict = {}

    for vm_id in vm_ids:
        sub, rg, provider, resource_type, resource_name = parse_arm_id(vm_id)
        if not all([sub, rg, provider, resource_type, resource_name]):
            logger.warning("Could not parse VM ARM ID: %s", vm_id)
            continue

        logger.info("Fetching role assignments for VM: %s", resource_name)
        role_assignments = get_role_assignments(sub, rg, provider, resource_type, resource_name, mgmt_token)

        for ra in role_assignments:
            ra_props = ra.get("properties", {})
            role_def_id = ra_props.get("roleDefinitionId", "")
            principal_id = ra_props.get("principalId", "")
            principal_type = ra_props.get("principalType", "")

            if not role_def_id:
                continue

            try:
                role_name, description = get_role_definition(role_def_id, mgmt_token, role_def_cache)
            except requests.exceptions.RequestException as exc:
                logger.warning("Could not fetch role definition %s: %s", role_def_id, exc)
                continue

            display_name = ""
            if principal_id:
                try:
                    display_name = get_principal_display_name(
                        principal_id, principal_type, graph_token, principal_cache
                    )
                except requests.exceptions.RequestException as exc:
                    display_name = "Lookup Failed"
                    logger.warning("Could not resolve display name for %s: %s", principal_id, exc)

            records.append(
                {
                    "vm_id": vm_id,
                    "role_definition_id": role_def_id,
                    "role_name": role_name,
                    "description": description,
                    "principal_id": principal_id,
                    "principal_type": principal_type,
                    "display_name": display_name,
                }
            )

    save_to_csv(records, output_path)


if __name__ == "__main__":
    main()
