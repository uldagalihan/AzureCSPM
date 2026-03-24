# Azure CSPM

> A lightweight Python toolkit for **Cloud Security Posture Management** on Microsoft Azure.
> Collect RBAC assignments, Key Vault access policies, managed identity inventory, network security data, patch compliance, and Defender for Cloud metrics — all via the Azure REST API.

---

## What Problem This Solves

Azure environments grow complex quickly. Security teams need regular snapshots of:

- Who has which role on which resource (RBAC audit).
- Which Key Vaults use legacy access policies vs. RBAC.
- Which VMs have internet-facing ports open via JIT.
- Which managed identities exist and what they are assigned to.
- Which VMs are missing critical patches or running end-of-life OS versions.
- What the current Defender for Cloud Secure Score and compliance posture is.

Azure Portal is manual and subscription-scoped. This toolkit automates the data collection across all subscriptions accessible to a service principal and exports structured CSV/Excel reports.

---

## Key Features

- **Multi-subscription** — automatically enumerates all accessible subscriptions, or targets one via `AZURE_SUBSCRIPTION_ID`.
- **No SDK dependency** — uses the Azure REST API directly via `requests`.
- **Structured output** — all exports land in a single `output/` directory as CSV or Excel.
- **Shared utilities** — common auth, ARM parsing, and Graph API resolution are centralized in `shared/`.
- **Simple to run** — each script is standalone; configure once via `.env`, run from the project root.

---

## Module Overview

### `access_security/`

| Script | Purpose |
|---|---|
| `vm_based_rbac.py` | Role assignments at the VM resource scope |
| `keyVaults_rbac.py` | Role assignments at the Key Vault resource scope |
| `keyVaults_AccessPolicy.py` | Legacy Key Vault access policies (keys, secrets, certificates) |
| `jit_ports.py` | Just-In-Time (JIT) network access policies and active requests |
| `system_assignedMI.py` | System-Assigned Managed Identity inventory per VM |
| `user_assigned_MI.py` | User-Assigned Managed Identity (UAMI) across subscriptions |
| `fic_MI.py` | Federated Identity Credentials (FIC) attached to UAMIs |

### `asset_inventory/`

| Script | Purpose |
|---|---|
| `get_vms.py` | VM inventory (hardware, OS config, patch settings) |
| `get_storage_info.py` | Managed disk encryption and CMK key URL |
| `get_nic_nsg_pubIP.py` | NIC → NSG → Public IP mapping + effective NSG rules |
| `get_vm_extensions.py` | VM extensions (publisher, version, state) |
| `get_key_vaults.py` | Key Vault metadata across all subscriptions |
| `get_sql_db.py` | SQL Server and database metadata |
| `get_storage_accounts.py` | Storage Account encryption and endpoint inventory |
| `csv_to_excel.py` | Utility: convert all CSVs in `output/` to `.xlsx` |

### `vulnerability_compliance/`

| Script | Purpose |
|---|---|
| `get_secure_scores.py` | Defender for Cloud Secure Score per subscription |
| `defender_for_cloudPlan.py` | Defender plan (pricing tier) and extension status |
| `regulatory_compliance_scores.py` | PCI-DSS, ISO 27001, CIS compliance scores |
| `eol_os_vms.py` | Security assessments (filterable for EOL OS findings) |
| `vm_patches.py` | OS patch assessment: pending critical and security patches |
| `tvm_cveList.py` | TVM CVE sub-assessments (CVSS score, fix availability) |

---

## Architecture

```
.env  ──►  shared/auth.py  ──►  Azure AD (token)
                   │
                   ▼
         shared/azure_api.py  ──►  Azure Management API  ──►  Subscriptions
                   │
         ┌─────────┴──────────┐
         │                    │
   access_security/      asset_inventory/       vulnerability_compliance/
         │                    │                          │
         └────────────────────┴──────────────────────────┘
                                      │
                              output/*.csv / *.xlsx
```

Scripts read credentials from `.env`, acquire OAuth 2.0 tokens, call the Azure
Management API (and Microsoft Graph for principal resolution), and write results
to `output/`.

---

## Prerequisites

- Python 3.10 or higher
- An **Azure AD App Registration** with a client secret
- The service principal must have **Reader** (or the specific permissions listed per script) on the target subscriptions

### Required Azure Permissions

**Azure RBAC (ARM):**
```
Microsoft.Authorization/roleAssignments/read
Microsoft.Authorization/roleDefinitions/read
Microsoft.KeyVault/vaults/read
Microsoft.KeyVault/vaults/accessPolicies/read
Microsoft.Security/jitNetworkAccessPolicies/read
Microsoft.ManagedIdentity/identities/read
Microsoft.ManagedIdentity/userAssignedIdentities/read
Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/read
Microsoft.Compute/virtualMachines/read
Microsoft.Compute/virtualMachines/assessPatches/action
Microsoft.Compute/disks/read
Microsoft.Network/networkInterfaces/read
Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action
Microsoft.Network/publicIPAddresses/read
Microsoft.Sql/servers/read
Microsoft.Sql/servers/databases/read
Microsoft.Storage/storageAccounts/read
Microsoft.Security/pricings/read
Microsoft.Security/secureScores/read
Microsoft.Security/assessments/read
Microsoft.Security/assessments/subAssessments/read
Microsoft.Security/regulatoryComplianceStandards/read
```

**Microsoft Graph (Application permissions):**
```
User.Read.All
Group.Read.All
Application.Read.All    (resolves service principal display names)
```

---

## Installation

```bash
git clone https://github.com/<your-org>/azure-cspm.git
cd azure-cspm
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## Configuration

```bash
cp .env.example .env
```

Edit `.env`:

```env
AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_SECRET=your-secret-here

# Optional: leave blank to process ALL accessible subscriptions
AZURE_SUBSCRIPTION_ID=
```

> **Never commit `.env` to version control.** It is listed in `.gitignore`.

---

## Usage

Run scripts from the **project root directory**. All outputs are written to `output/`.

### Recommended run order

```bash
# Step 1 — Build the base inventory (most other scripts depend on this)
python asset_inventory/get_vms.py
python asset_inventory/get_key_vaults.py    # produces output/key_vaults.csv + .xlsx

# Step 2 — Asset details
python asset_inventory/get_storage_info.py
python asset_inventory/get_storage_accounts.py
python asset_inventory/get_sql_db.py
python asset_inventory/get_vm_extensions.py
python asset_inventory/get_nic_nsg_pubIP.py

# Step 3 — Access security (depends on vm_inventory.csv and key_vaults.csv)
python access_security/vm_based_rbac.py
python access_security/keyVaults_rbac.py
python access_security/keyVaults_AccessPolicy.py
python access_security/jit_ports.py
python access_security/user_assigned_MI.py  # produces output/user_assigned_identities.csv
python access_security/system_assignedMI.py
python access_security/fic_MI.py            # depends on user_assigned_identities.csv

# Step 4 — Vulnerability & compliance
python vulnerability_compliance/get_secure_scores.py
python vulnerability_compliance/defender_for_cloudPlan.py
python vulnerability_compliance/regulatory_compliance_scores.py
python vulnerability_compliance/eol_os_vms.py
python vulnerability_compliance/vm_patches.py
python vulnerability_compliance/tvm_cveList.py

# Optional: convert all CSVs in output/ to Excel
python asset_inventory/csv_to_excel.py
```

### Example output (vm_inventory.csv)

```
ID,Name,ResourceGroup,Location,VMSize,OSType,OSDiskSizeGB,...
/subscriptions/.../virtualMachines/myvm,myvm,my-rg,westeurope,Standard_D2s_v3,Linux,128,...
```

---

## Security Notes

- Credentials are loaded exclusively from environment variables — no secrets in source code.
- `output/` is excluded from git via `.gitignore` — exported data stays local.
- The `AZURE_SUBSCRIPTION_ID` variable is optional. When omitted, all subscriptions are enumerated via the management API.
- This toolkit is **read-only** with the exception of `vm_patches.py`, which triggers the `assessPatches` action on VMs. This action does not modify VMs; it only initiates an assessment.

---

## Limitations and Assumptions

- Scripts target the **Azure Management REST API** directly with no retry logic beyond the async polling in `get_nic_nsg_pubIP.py` and `vm_patches.py`. Transient errors will surface as exceptions.
- `tvm_cveList.py` exports raw sub-assessments. You will need to filter the output by `display_name` or `category` to isolate CVE findings from other assessment types.
- `eol_os_vms.py` exports all security assessments — filter by `display_name` (e.g. "Machines should have vulnerability findings resolved") to isolate EOL OS VMs.
- The `vm_patches.py` script may take several minutes per VM due to the asynchronous assessment flow.
- Only the first `keyVaults.csv` `ID` column format produced by `get_key_vaults.py` is supported as input for access security scripts.

---

## Roadmap / Future Improvements

- [ ] Add retry logic with exponential backoff for transient API errors.
- [ ] Add `--output-dir` CLI argument to all scripts.
- [ ] Add pagination to scripts that may miss resources in large environments.
- [ ] Add a master runner script to execute all collection steps in order.
- [ ] Add basic unit tests with mocked API responses.
- [ ] Support Azure workload identity / managed identity authentication (in addition to client secret).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions and contribution guidelines.

---

## Acknowledgements

Built using the [Azure Management REST API](https://learn.microsoft.com/en-us/rest/api/azure/)
and [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/overview).
