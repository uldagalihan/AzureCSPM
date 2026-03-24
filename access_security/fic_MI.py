"""
Federated Identity Credentials (FIC) inventory for User-Assigned Managed Identities.

Reads User-Assigned Managed Identity (UAMI) resource IDs from a CSV file,
queries each identity's Federated Identity Credentials via the Azure Management
API, and exports the results to CSV.

Expected input:  output/user_assigned_identities.csv  (column: resource_id)
Output:          output/federated_identity_credentials.csv

Required permissions:
    Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/read
"""
import csv
import logging
import os
import sys

import requests
from dotenv import load_dotenv

# Allow imports from the project root shared package.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.auth import get_token
from shared.arm_parser import parse_uami_arm_id

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(_PROJECT_ROOT, "output")

TENANT_ID = os.environ["AZURE_TENANT_ID"]
CLIENT_ID = os.environ["AZURE_CLIENT_ID"]
CLIENT_SECRET = os.environ["AZURE_CLIENT_SECRET"]

API_VERSION = "2024-11-30"


def load_uami_ids(filepath: str) -> list:
    """Read User-Assigned Managed Identity resource IDs from a CSV file.

    Args:
        filepath: Path to the CSV file. Must contain a ``resource_id`` column.

    Returns:
        List of ARM resource ID strings.
    """
    ids = []
    with open(filepath, mode="r", newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            if "resource_id" in row and row["resource_id"]:
                ids.append(row["resource_id"])
    return ids


def get_federated_credentials(
    subscription_id: str,
    resource_group: str,
    identity_name: str,
    token: str,
) -> list:
    """Retrieve all Federated Identity Credentials for a given UAMI.

    Args:
        subscription_id: Azure subscription ID.
        resource_group: Resource group containing the identity.
        identity_name: Name of the User-Assigned Managed Identity.
        token: Azure Management API bearer token.

    Returns:
        List of Federated Identity Credential objects (may be empty).
    """
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.ManagedIdentity/userAssignedIdentities"
        f"/{identity_name}/federatedIdentityCredentials"
        f"?api-version={API_VERSION}"
    )
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=30)
    if response.status_code == 404:
        return []
    response.raise_for_status()
    return response.json().get("value", [])


def save_to_csv(data: list, filepath: str) -> None:
    """Write Federated Identity Credential records to a CSV file.

    Args:
        data: List of dicts with credential fields.
        filepath: Destination file path.
    """
    with open(filepath, mode="w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["identity_id", "federated_credential_id", "name", "issuer", "subject"],
        )
        writer.writeheader()
        writer.writerows(data)
    logger.info("Exported %d record(s) to '%s'.", len(data), filepath)


def main() -> None:
    """Entry point: collect FIC data for all UAMIs listed in the input CSV."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    input_path = os.path.join(OUTPUT_DIR, "user_assigned_identities.csv")
    output_path = os.path.join(OUTPUT_DIR, "federated_identity_credentials.csv")

    logger.info("Acquiring Azure Management token...")
    token = get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)

    logger.info("Loading UAMI IDs from '%s'...", input_path)
    identity_ids = load_uami_ids(input_path)
    logger.info("Found %d identity ID(s).", len(identity_ids))

    records = []
    for identity_id in identity_ids:
        sub, rg, name = parse_uami_arm_id(identity_id)
        if not all([sub, rg, name]):
            logger.warning("Could not parse ARM ID: %s", identity_id)
            continue

        logger.info("Fetching federated credentials for: %s", name)
        try:
            fic_list = get_federated_credentials(sub, rg, name, token)
            for fic in fic_list:
                props = fic.get("properties", {})
                records.append(
                    {
                        "identity_id": identity_id,
                        "federated_credential_id": fic.get("id", ""),
                        "name": fic.get("name", ""),
                        "issuer": props.get("issuer", ""),
                        "subject": props.get("subject", ""),
                    }
                )
        except requests.exceptions.RequestException as exc:
            logger.error("API error for identity '%s': %s", name, exc)

    save_to_csv(records, output_path)


if __name__ == "__main__":
    main()
