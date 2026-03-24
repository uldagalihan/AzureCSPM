"""
Virtual Machine inventory.

Enumerates all Virtual Machines across accessible subscriptions (or a specific
subscription when AZURE_SUBSCRIPTION_ID is set), extracts hardware profile,
OS configuration, image reference, patch assessment settings, and VM agent
details, and exports the results to CSV.

Output: output/vm_inventory.csv

This file is the primary input for several downstream scripts:
    access_security/vm_based_rbac.py
    access_security/system_assignedMI.py
    asset_inventory/get_vm_extensions.py
    vulnerability_compliance/vm_patches.py

Required permissions:
    Microsoft.Compute/virtualMachines/read
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

VM_API_VERSION = "2024-11-01"

_CSV_FIELDS = [
    "ID", "Name", "ResourceGroup", "Location", "VMSize", "OSType", "OSDiskSizeGB",
    "ImagePublisher", "ImageOffer", "ImageSKU", "ImageVersion",
    "PatchAssessmentMode", "EnableAutoUpdates", "ProvisionVMAgent",
    "EnableVMAgentUpdates", "DisablePasswordAuth",
]


def get_vm_list(subscription_id: str, token: str) -> list:
    """Retrieve all Virtual Machines for a subscription.

    Args:
        subscription_id: Azure subscription ID.
        token: Azure Management API bearer token.

    Returns:
        List of VM resource objects.
    """
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/providers/Microsoft.Compute/virtualMachines"
        f"?api-version={VM_API_VERSION}"
    )
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json().get("value", [])


def extract_vm_record(vm: dict) -> dict:
    """Flatten a VM resource object into an export-ready dict.

    Handles both Windows and Linux VM profiles. Fields that do not apply
    to a given OS type are left as empty strings.

    Args:
        vm: VM resource object from the Azure API.

    Returns:
        Flat dict with all required CSV fields.
    """
    arm_id = vm.get("id", "")
    # Extract resource group from position [4] in the ARM ID segments.
    resource_group = arm_id.split("/")[4] if arm_id else ""
    props = vm.get("properties", {})
    os_profile = props.get("osProfile", {})
    storage_profile = props.get("storageProfile", {})
    os_disk = storage_profile.get("osDisk", {})
    image_ref = storage_profile.get("imageReference", {})
    os_type = os_disk.get("osType", "")

    # OS-specific configuration fields.
    provision_vm_agent = enable_auto_updates = ""
    assessment_mode = enable_vm_agent_updates = disable_password_auth = ""

    if os_type == "Linux":
        linux_cfg = os_profile.get("linuxConfiguration", {})
        patch_settings = linux_cfg.get("patchSettings", {})
        provision_vm_agent = linux_cfg.get("provisionVMAgent", "")
        enable_vm_agent_updates = linux_cfg.get("enableVMAgentPlatformUpdates", "")
        disable_password_auth = linux_cfg.get("disablePasswordAuthentication", "")
        assessment_mode = patch_settings.get("assessmentMode", "")
    elif os_type == "Windows":
        win_cfg = os_profile.get("windowsConfiguration", {})
        patch_settings = win_cfg.get("patchSettings", {})
        provision_vm_agent = win_cfg.get("provisionVMAgent", "")
        enable_auto_updates = win_cfg.get("enableAutomaticUpdates", "")
        assessment_mode = patch_settings.get("assessmentMode", "")

    return {
        "ID": arm_id,
        "Name": vm.get("name", ""),
        "ResourceGroup": resource_group,
        "Location": vm.get("location", ""),
        "VMSize": props.get("hardwareProfile", {}).get("vmSize", ""),
        "OSType": os_type,
        "OSDiskSizeGB": os_disk.get("diskSizeGB", ""),
        # Fall back to "CustomImage/Unknown" when no marketplace image is attached.
        "ImagePublisher": image_ref.get("publisher", "CustomImage/Unknown"),
        "ImageOffer": image_ref.get("offer", "CustomImage/Unknown"),
        "ImageSKU": image_ref.get("sku", "CustomImage/Unknown"),
        "ImageVersion": image_ref.get("version", "CustomImage/Unknown"),
        "PatchAssessmentMode": assessment_mode,
        "EnableAutoUpdates": enable_auto_updates,
        "ProvisionVMAgent": provision_vm_agent,
        "EnableVMAgentUpdates": enable_vm_agent_updates,
        "DisablePasswordAuth": disable_password_auth,
    }


def save_to_csv(records: list, filepath: str) -> None:
    """Write VM inventory records to a CSV file.

    Args:
        records: List of flat dicts produced by :func:`extract_vm_record`.
        filepath: Destination file path.
    """
    with open(filepath, mode="w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_FIELDS)
        writer.writeheader()
        writer.writerows(records)
    logger.info("Exported %d VM record(s) to '%s'.", len(records), filepath)


def main() -> None:
    """Entry point: collect VM inventory across all accessible subscriptions."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "vm_inventory.csv")

    logger.info("Acquiring Azure Management token...")
    token = get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)

    subscriptions = get_subscriptions(token, subscription_id=SUBSCRIPTION_ID)
    all_records = []

    for sub_id in subscriptions:
        logger.info("Fetching VMs for subscription: %s", sub_id)
        try:
            vms = get_vm_list(sub_id, token)
            records = [extract_vm_record(vm) for vm in vms]
            logger.info("  Found %d VM(s).", len(records))
            all_records.extend(records)
        except requests.exceptions.HTTPError as exc:
            logger.error("HTTP error for subscription %s: %s", sub_id, exc.response.status_code)
        except requests.exceptions.RequestException as exc:
            logger.error("Request failed for subscription %s: %s", sub_id, exc)

    save_to_csv(all_records, output_path)


if __name__ == "__main__":
    main()
