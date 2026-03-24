"""
Key Vault access policy inventory.

For each Key Vault listed in an input CSV, retrieves all access policies
(objects granted permissions to Keys, Secrets, Certificates, and Storage)
and resolves each objectId to a display name via Microsoft Graph.
Also exports network access control settings and private endpoint details.

Expected input:  output/key_vaults.csv  (column: ID)
Output:          output/keyvault_access_policies.csv

Required permissions:
    Microsoft.KeyVault/vaults/read
    Microsoft.KeyVault/vaults/accessPolicies/read
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
from shared.arm_parser import parse_kv_arm_id
from shared.graph import get_display_name_and_type

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(_PROJECT_ROOT, "output")

TENANT_ID = os.environ["AZURE_TENANT_ID"]
CLIENT_ID = os.environ["AZURE_CLIENT_ID"]
CLIENT_SECRET = os.environ["AZURE_CLIENT_SECRET"]

API_VERSION = "2022-07-01"


def load_kv_ids(filepath: str) -> list:
    """Read Key Vault resource IDs from a CSV file.

    Args:
        filepath: Path to the CSV file. Must contain an ``ID`` column.

    Returns:
        List of ARM resource ID strings.
    """
    ids = []
    with open(filepath, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            if "ID" in row and row["ID"]:
                ids.append(row["ID"])
    return ids


def get_vault_details(
    subscription_id: str, resource_group: str, vault_name: str, token: str
) -> dict | None:
    """Retrieve full Key Vault resource details from the Azure Management API.

    Args:
        subscription_id: Azure subscription ID.
        resource_group: Resource group containing the vault.
        vault_name: Name of the Key Vault.
        token: Azure Management API bearer token.

    Returns:
        Vault resource dict, or ``None`` if the vault is not found (404).
    """
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.KeyVault/vaults/{vault_name}"
        f"?api-version={API_VERSION}"
    )
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=30)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return response.json()


def save_to_csv(data: list, filepath: str) -> None:
    """Write Key Vault access policy records to a CSV file.

    Args:
        data: List of flat dicts with access policy fields.
        filepath: Destination file path.
    """
    fieldnames = [
        "keyvault_id", "keyvault_name", "object_id", "principal_type", "display_name",
        "key_permissions", "secret_permissions", "certificate_permissions",
        "storage_permissions", "vault_uri", "public_network_access",
        "network_bypass", "network_default_action", "ip_rules",
        "vnet_rules", "private_endpoint_count", "private_endpoint_ids",
    ]
    with open(filepath, mode="w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
    logger.info("Exported %d record(s) to '%s'.", len(data), filepath)


def main() -> None:
    """Entry point: collect access policy data for all Key Vaults in the input CSV."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    input_path = os.path.join(OUTPUT_DIR, "key_vaults.csv")
    output_path = os.path.join(OUTPUT_DIR, "keyvault_access_policies.csv")

    logger.info("Acquiring tokens...")
    mgmt_token = get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    graph_token = get_graph_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)

    kv_ids = load_kv_ids(input_path)
    logger.info("Loaded %d Key Vault ID(s).", len(kv_ids))

    records = []
    graph_cache: dict = {}

    for kv_id in kv_ids:
        sub, rg, name = parse_kv_arm_id(kv_id)
        if not all([sub, rg, name]):
            logger.warning("Could not parse Key Vault ARM ID: %s", kv_id)
            continue

        logger.info("Fetching vault details: %s", name)
        vault = get_vault_details(sub, rg, name, mgmt_token)
        if not vault:
            logger.warning("Vault not found (404): %s", name)
            continue

        props = vault.get("properties", {})

        # Network access control settings.
        net = props.get("networkAcls", {})
        ip_rules = [rule.get("value", "") for rule in net.get("ipRules", [])]
        vnet_rules = [
            f"{rule.get('id', '')} | ignoreMissing: {rule.get('ignoreMissingVnetServiceEndpoint', False)}"
            for rule in net.get("virtualNetworkRules", [])
        ]
        private_endpoints = props.get("privateEndpointConnections", [])
        private_ids = [pe.get("id", "") for pe in private_endpoints]

        # Access policies (legacy vault permission model).
        for policy in props.get("accessPolicies", []):
            object_id = policy.get("objectId", "")
            perms = policy.get("permissions", {})
            display_name, principal_type = get_display_name_and_type(
                object_id, graph_token, graph_cache
            )
            records.append(
                {
                    "keyvault_id": kv_id,
                    "keyvault_name": name,
                    "object_id": object_id,
                    "principal_type": principal_type,
                    "display_name": display_name,
                    "key_permissions": ", ".join(perms.get("keys", [])),
                    "secret_permissions": ", ".join(perms.get("secrets", [])),
                    "certificate_permissions": ", ".join(perms.get("certificates", [])),
                    "storage_permissions": ", ".join(perms.get("storage", [])),
                    "vault_uri": props.get("vaultUri", ""),
                    "public_network_access": props.get("publicNetworkAccess", ""),
                    "network_bypass": net.get("bypass", ""),
                    "network_default_action": net.get("defaultAction", ""),
                    "ip_rules": ", ".join(ip_rules),
                    "vnet_rules": ", ".join(vnet_rules),
                    "private_endpoint_count": len(private_endpoints),
                    "private_endpoint_ids": ", ".join(private_ids),
                }
            )

    save_to_csv(records, output_path)


if __name__ == "__main__":
    main()
