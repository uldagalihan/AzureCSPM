"""
NIC, NSG, and Public IP address inventory.

For each accessible subscription, retrieves all Network Interface Cards (NICs),
maps them to their associated Network Security Groups (NSGs) and Public IP
addresses, and writes:

  - output/nic_inventory.xlsx          NIC, NSG, and Public IP mapping table.
  - output/effective_nsg_rules.txt     Effective (user-defined) NSG rules per NIC.

The effective NSG rules endpoint triggers an asynchronous operation; this script
polls the Location header until the result is available or a timeout is reached.

Required permissions:
    Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action
"""
import logging
import os
import sys
import time

import pandas as pd
import requests
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.auth import get_token
from shared.azure_api import get_subscriptions
from shared.arm_parser import parse_public_ip_arm_id, parse_nic_arm_id

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(_PROJECT_ROOT, "output")

TENANT_ID = os.environ["AZURE_TENANT_ID"]
CLIENT_ID = os.environ["AZURE_CLIENT_ID"]
CLIENT_SECRET = os.environ["AZURE_CLIENT_SECRET"]
SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")  # optional

NIC_API_VERSION = "2024-05-01"
POLL_MAX_RETRIES = 30
POLL_INTERVAL_SECONDS = 5


def get_nics(subscription_id: str, token: str) -> list:
    """Retrieve all NICs for a subscription.

    Args:
        subscription_id: Azure subscription ID.
        token: Azure Management API bearer token.

    Returns:
        List of NIC resource objects.
    """
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/providers/Microsoft.Network/networkInterfaces"
        f"?api-version={NIC_API_VERSION}"
    )
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json().get("value", [])


def get_public_ip_details(public_ip_id: str, token: str) -> dict:
    """Retrieve Public IP address details for a given ARM resource ID.

    Args:
        public_ip_id: ARM resource ID of the Public IP Address.
        token: Azure Management API bearer token.

    Returns:
        Dict with public IP metadata, or empty dict if not found.
    """
    sub, rg, ip_name = parse_public_ip_arm_id(public_ip_id)
    if not all([sub, rg, ip_name]):
        return {}

    url = (
        f"https://management.azure.com/subscriptions/{sub}"
        f"/resourceGroups/{rg}"
        f"/providers/Microsoft.Network/publicIPAddresses/{ip_name}"
        f"?api-version={NIC_API_VERSION}"
    )
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=30)
    if response.status_code != 200:
        return {}

    ip_data = response.json()
    ip_props = ip_data.get("properties", {})
    dns = ip_props.get("dnsSettings", {})
    return {
        "public_ip_address": ip_props.get("ipAddress", ""),
        "public_ip_name": ip_data.get("name", ""),
        "public_ip_fqdn": dns.get("fqdn", ""),
        "public_ip_resource_id": ip_data.get("id", ""),
    }


def format_effective_nsg_rules(json_body: dict, nic_name: str) -> str:
    """Format the effective NSG rules response as a human-readable text block.

    Default Azure security rules (names starting with ``defaultSecurityRules/``)
    are excluded to keep output focused on user-defined rules.

    Args:
        json_body: Parsed JSON response from the effectiveNetworkSecurityGroups API.
        nic_name: NIC name, used only in the no-rules message.

    Returns:
        Multi-line string describing all user-defined effective rules.
    """
    lines: list[str] = []
    for item in json_body.get("value", []):
        nsg_id = item.get("networkSecurityGroup", {}).get("id", "")
        for rule in item.get("effectiveSecurityRules", []):
            rule_name = rule.get("name", "")
            # Skip built-in default rules.
            if rule_name.startswith("defaultSecurityRules/"):
                continue
            lines.extend([
                f"NSG: {nsg_id}",
                f"  Rule: {rule_name}",
                f"    Direction:         {rule.get('direction')}",
                f"    Protocol:          {rule.get('protocol')}",
                f"    Source:            {', '.join(rule.get('sourceAddressPrefixes') or [])}",
                f"    Source Ports:      {', '.join(rule.get('sourcePortRanges') or [])}",
                f"    Destination:       {', '.join(rule.get('destinationAddressPrefixes') or [])}",
                f"    Destination Ports: {', '.join(rule.get('destinationPortRanges') or [])}",
                f"    Access:            {rule.get('access')}",
                f"    Priority:          {rule.get('priority')}",
                "",
            ])
    if not lines:
        return f"[OK] NIC '{nic_name}': no user-defined NSG rules found.\n"
    return "\n".join(lines)


def get_effective_nsgs(nic_id: str, token: str) -> str:
    """Trigger and retrieve effective NSG rules for a NIC.

    This endpoint is asynchronous. If the initial POST returns HTTP 202,
    the script polls the Location URL until the result arrives or the
    retry limit is reached.

    Args:
        nic_id: ARM resource ID of the NIC.
        token: Azure Management API bearer token.

    Returns:
        Formatted string with effective NSG rule details.
    """
    sub, rg, nic_name = parse_nic_arm_id(nic_id)
    if not all([sub, rg, nic_name]):
        return f"[ERROR] Could not parse NIC ARM ID: {nic_id}\n"

    url = (
        f"https://management.azure.com/subscriptions/{sub}"
        f"/resourceGroups/{rg}"
        f"/providers/Microsoft.Network/networkInterfaces/{nic_name}"
        f"/effectiveNetworkSecurityGroups?api-version={NIC_API_VERSION}"
    )
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    logger.info("  Requesting effective NSG rules for NIC: %s", nic_name)
    response = requests.post(url, headers=headers, timeout=30)

    if response.status_code == 200:
        try:
            return format_effective_nsg_rules(response.json(), nic_name)
        except Exception:
            return f"[ERROR] JSON parse error for NIC '{nic_name}': {response.text}\n"

    if response.status_code == 202:
        location_url = response.headers.get("Location")
        if not location_url:
            return f"[ERROR] HTTP 202 received but no Location header found for NIC '{nic_name}'.\n"

        for attempt in range(1, POLL_MAX_RETRIES + 1):
            time.sleep(POLL_INTERVAL_SECONDS)
            try:
                poll = requests.get(location_url, headers=headers, timeout=30)
            except requests.exceptions.RequestException as exc:
                return f"[ERROR] Poll request failed for NIC '{nic_name}': {exc}\n"

            logger.debug("  Polling (%d/%d) — HTTP %s", attempt, POLL_MAX_RETRIES, poll.status_code)
            try:
                body = poll.json()
            except Exception:
                body = None

            if poll.status_code == 200 and body:
                return format_effective_nsg_rules(body, nic_name)
            if poll.status_code in (201, 202):
                continue
            return f"[ERROR] Unexpected poll status {poll.status_code} for NIC '{nic_name}'.\n"

        return f"[ERROR] Polling timed out after {POLL_MAX_RETRIES} attempts for NIC '{nic_name}'.\n"

    return f"[ERROR] HTTP {response.status_code} for NIC '{nic_name}': {response.text}\n"


def process_nics(nics: list, token: str) -> list:
    """Extract and flatten NIC, NSG, and Public IP data into a list of records.

    Args:
        nics: List of NIC resource objects from the Azure API.
        token: Azure Management API bearer token.

    Returns:
        List of flat dicts ready for export.
    """
    records = []
    for nic in nics:
        props = nic.get("properties", {})
        for ipconf in props.get("ipConfigurations", []):
            ip_props = ipconf.get("properties", {})
            public_ip_id = ip_props.get("publicIPAddress", {}).get("id", "")
            public_ip_info = get_public_ip_details(public_ip_id, token) if public_ip_id else {}
            records.append(
                {
                    "nic_name": nic.get("name", ""),
                    "nic_id": nic.get("id", ""),
                    "location": nic.get("location", ""),
                    "provisioning_state": props.get("provisioningState", ""),
                    "private_ip_address": ip_props.get("privateIPAddress", ""),
                    "public_ip_id": public_ip_id,
                    "public_ip_address": public_ip_info.get("public_ip_address", ""),
                    "public_ip_name": public_ip_info.get("public_ip_name", ""),
                    "public_ip_fqdn": public_ip_info.get("public_ip_fqdn", ""),
                    "public_ip_resource_id": public_ip_info.get("public_ip_resource_id", ""),
                    "nsg_id": props.get("networkSecurityGroup", {}).get("id", ""),
                }
            )
    return records


def main() -> None:
    """Entry point: collect NIC/NSG/Public IP data across all accessible subscriptions."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_xlsx = os.path.join(OUTPUT_DIR, "nic_inventory.xlsx")
    nsg_txt = os.path.join(OUTPUT_DIR, "effective_nsg_rules.txt")

    logger.info("Acquiring Azure Management token...")
    token = get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)

    subscriptions = get_subscriptions(token, subscription_id=SUBSCRIPTION_ID)
    all_nics: list = []

    # Clear the NSG rules output file before appending.
    with open(nsg_txt, "w", encoding="utf-8") as fh:
        fh.write("=== Effective NSG Rules Report ===\n\n")

    for sub_id in subscriptions:
        logger.info("Fetching NICs for subscription: %s", sub_id)
        try:
            nics = get_nics(sub_id, token)
            processed = process_nics(nics, token)
            all_nics.extend(processed)

            for nic in processed:
                nic_name = nic.get("nic_name", "")
                if not nic.get("nsg_id"):
                    logger.info("  %s: no NSG attached, skipping.", nic_name)
                    continue
                logger.info("  Fetching effective NSG rules for: %s", nic_name)
                nsg_output = get_effective_nsgs(nic["nic_id"], token)
                with open(nsg_txt, "a", encoding="utf-8") as fh:
                    fh.write(f"=== NIC: {nic_name} ===\n")
                    fh.write(nsg_output + "\n\n")
        except Exception as exc:
            logger.error("Error processing subscription %s: %s", sub_id, exc)

    if all_nics:
        pd.DataFrame(all_nics).to_excel(output_xlsx, index=False)
        logger.info("Exported %d NIC record(s) to '%s'.", len(all_nics), output_xlsx)
    logger.info("Effective NSG rules written to '%s'.", nsg_txt)


if __name__ == "__main__":
    main()
