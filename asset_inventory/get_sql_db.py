"""
Azure SQL Database metadata inventory.

Enumerates all SQL Servers and their databases across accessible subscriptions
(or a specific subscription when AZURE_SUBSCRIPTION_ID is set) and exports
the results to an Excel file.

Output: output/sql_databases.xlsx

Required permissions:
    Microsoft.Sql/servers/read
    Microsoft.Sql/servers/databases/read
"""
import logging
import os
import sys

import openpyxl
import requests
from dotenv import load_dotenv
from openpyxl import Workbook

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

SQL_API_VERSION = "2023-08-01"


def get_sql_servers(subscription_id: str, token: str) -> list:
    """Retrieve all SQL Server instances for a subscription.

    Args:
        subscription_id: Azure subscription ID.
        token: Azure Management API bearer token.

    Returns:
        List of SQL Server resource objects.
    """
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/providers/Microsoft.Sql/servers?api-version={SQL_API_VERSION}"
    )
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json().get("value", [])


def get_databases(
    subscription_id: str, resource_group: str, server_name: str, token: str
) -> list:
    """Retrieve all databases for a given SQL Server.

    Args:
        subscription_id: Azure subscription ID.
        resource_group: Resource group containing the SQL Server.
        server_name: SQL Server name.
        token: Azure Management API bearer token.

    Returns:
        List of database resource objects.
    """
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Sql/servers/{server_name}"
        f"/databases?api-version={SQL_API_VERSION}"
    )
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json().get("value", [])


def save_to_excel(databases: list, filepath: str) -> None:
    """Write SQL database records to an Excel workbook.

    Args:
        databases: List of database resource objects from the Azure API.
        filepath: Destination .xlsx file path.
    """
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "SQL Databases"

    headers = [
        "DatabaseName", "Location", "Kind", "Status", "ReadScale", "ZoneRedundant",
        "MaxSizeBytes", "CurrentBackupStorageRedundancy", "RequestedBackupStorageRedundancy",
        "AutoPauseDelay", "AvailabilityZone", "ElasticPoolId", "Collation",
        "CatalogCollation", "CreationDate", "SecondaryLocation", "LicenseType",
        "IsLedgerOn", "EncryptionProtector", "CreateMode", "SkuName", "SkuTier",
        "SkuCapacity", "ID",
    ]
    sheet.append(headers)

    for db in databases:
        props = db.get("properties", {})
        sku = db.get("sku", {})
        sheet.append(
            [
                db.get("name", ""),
                db.get("location", ""),
                db.get("kind", ""),
                props.get("status", ""),
                props.get("readScale", ""),
                props.get("zoneRedundant", ""),
                props.get("maxSizeBytes", ""),
                props.get("currentBackupStorageRedundancy", ""),
                props.get("requestedBackupStorageRedundancy", ""),
                props.get("autoPauseDelay", ""),
                props.get("availabilityZone", ""),
                props.get("elasticPoolId", ""),
                props.get("collation", ""),
                props.get("catalogCollation", ""),
                props.get("creationDate", ""),
                props.get("defaultSecondaryLocation", ""),
                props.get("licenseType", ""),
                props.get("isLedgerOn", ""),
                props.get("encryptionProtector", ""),
                props.get("createMode", ""),
                sku.get("name", ""),
                sku.get("tier", ""),
                sku.get("capacity", ""),
                db.get("id", ""),
            ]
        )

    workbook.save(filepath)
    logger.info("Exported %d database row(s) to '%s'.", len(databases), filepath)


def main() -> None:
    """Entry point: collect SQL database metadata across all accessible subscriptions."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "sql_databases.xlsx")

    logger.info("Acquiring Azure Management token...")
    token = get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)

    subscriptions = get_subscriptions(token, subscription_id=SUBSCRIPTION_ID)
    all_databases = []

    for sub_id in subscriptions:
        logger.info("Fetching SQL Servers for subscription: %s", sub_id)
        try:
            servers = get_sql_servers(sub_id, token)
        except requests.exceptions.RequestException as exc:
            logger.error("Failed to list SQL servers for subscription %s: %s", sub_id, exc)
            continue

        for server in servers:
            server_id = server.get("id", "")
            # Extract resource group from the ARM ID segments.
            resource_group = server_id.split("/")[4] if server_id else ""
            server_name = server.get("name", "")
            logger.info("  Fetching databases for SQL Server: %s", server_name)
            try:
                databases = get_databases(sub_id, resource_group, server_name, token)
                all_databases.extend(databases)
            except requests.exceptions.RequestException as exc:
                logger.error("  Failed to list databases for server '%s': %s", server_name, exc)

    save_to_excel(all_databases, output_path)


if __name__ == "__main__":
    main()
