"""
Just-In-Time (JIT) network access policy inventory.

Retrieves JIT network access policies and active access requests from all
accessible subscriptions (or a specific subscription when AZURE_SUBSCRIPTION_ID
is set) and exports them to CSV.

Output: output/jit_access_report.csv

Required permissions:
    Microsoft.Security/jitNetworkAccessPolicies/read
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

API_VERSION = "2020-01-01"


def get_jit_policies(token: str, subscription_id: str) -> list:
    """Retrieve all JIT network access policies for a subscription.

    Args:
        token: Azure Management API bearer token.
        subscription_id: Target subscription ID.

    Returns:
        List of JIT policy objects.
    """
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/providers/Microsoft.Security/jitNetworkAccessPolicies"
        f"?api-version={API_VERSION}"
    )
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json().get("value", [])


def parse_policies(policies: list) -> list:
    """Flatten JIT policy and active request data into individual port records.

    Each JIT policy covers one or more VMs, and each VM defines allowed ports.
    Active access requests are merged into the same output structure with
    requestor and timing details populated.

    Args:
        policies: List of JIT policy objects from the API.

    Returns:
        List of flat dicts ready for CSV export.
    """
    results = []
    for policy in policies:
        policy_id = policy.get("id", "")
        props = policy.get("properties", {})

        # Allowed VM port configurations (policy definition).
        for vm in props.get("virtualMachines", []):
            vm_id = vm.get("id", "")
            for port in vm.get("ports", []):
                results.append(
                    {
                        "policy_id": policy_id,
                        "vm_id": vm_id,
                        "port_number": port.get("number"),
                        "protocol": port.get("protocol"),
                        "allowed_source": port.get("allowedSourceAddressPrefix"),
                        "max_duration": port.get("maxRequestAccessDuration"),
                        "requestor": "",
                        "justification": "",
                        "start_time": "",
                        "end_time": "",
                        "status": "",
                        "status_reason": "",
                    }
                )

        # Active or historical access requests.
        for req in props.get("requests", []):
            requestor = req.get("requestor", "")
            justification = req.get("justification", "")
            start_time = req.get("startTimeUtc", "")
            for vm in req.get("virtualMachines", []):
                vm_id = vm.get("id", "")
                for port in vm.get("ports", []):
                    results.append(
                        {
                            "policy_id": policy_id,
                            "vm_id": vm_id,
                            "port_number": port.get("number"),
                            "protocol": "",
                            "allowed_source": port.get("allowedSourceAddressPrefix"),
                            "max_duration": "",
                            "requestor": requestor,
                            "justification": justification,
                            "start_time": start_time,
                            "end_time": port.get("endTimeUtc", ""),
                            "status": port.get("status", ""),
                            "status_reason": port.get("statusReason", ""),
                        }
                    )
    return results


def save_to_csv(data: list, filepath: str) -> None:
    """Write JIT access records to a CSV file.

    Args:
        data: List of flat dicts produced by :func:`parse_policies`.
        filepath: Destination file path.
    """
    fieldnames = [
        "policy_id", "vm_id", "port_number", "protocol", "allowed_source",
        "max_duration", "requestor", "justification", "start_time",
        "end_time", "status", "status_reason",
    ]
    with open(filepath, mode="w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
    logger.info("Exported %d record(s) to '%s'.", len(data), filepath)


def main() -> None:
    """Entry point: collect JIT policies across all accessible subscriptions."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "jit_access_report.csv")

    logger.info("Acquiring Azure Management token...")
    token = get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)

    subscriptions = get_subscriptions(token, subscription_id=SUBSCRIPTION_ID)
    all_results = []

    for sub_id in subscriptions:
        logger.info("Fetching JIT policies for subscription: %s", sub_id)
        try:
            policies = get_jit_policies(token, sub_id)
            all_results.extend(parse_policies(policies))
        except requests.exceptions.HTTPError as exc:
            logger.error(
                "HTTP error for subscription %s: %s %s",
                sub_id,
                exc.response.status_code,
                exc.response.text,
            )
        except requests.exceptions.RequestException as exc:
            logger.error("Request failed for subscription %s: %s", sub_id, exc)

    save_to_csv(all_results, output_path)


if __name__ == "__main__":
    main()
