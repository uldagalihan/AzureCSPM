# Contributing to Azure CSPM

Thank you for your interest in contributing! This project is a lightweight collection
of Python scripts for Azure Cloud Security Posture Management data collection.

## Getting Started

1. **Fork** the repository and clone your fork.
2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Copy `.env.example` to `.env` and fill in your Azure AD credentials.
4. Run the script you want to work on from the project root:
   ```bash
   python asset_inventory/get_vms.py
   ```

## Project Structure

```
.
├── shared/                    # Shared utilities (auth, ARM parsing, Graph API)
├── access_security/           # RBAC, Key Vault access, JIT, Managed Identities
├── asset_inventory/           # VM, disk, NIC, SQL, storage, Key Vault metadata
├── vulnerability_compliance/  # Defender plans, Secure Scores, patches, CVEs
├── output/                    # All script outputs go here (git-ignored)
├── .env.example               # Environment variable template
└── requirements.txt
```

## Contribution Guidelines

- **Keep scripts self-contained and simple.** Each script should do one thing well and be runnable on its own.
- **No credentials in code.** All credentials must be read from environment variables via `.env`.
- **English only.** All comments, docstrings, log messages, and documentation must be in English.
- **Follow existing style.** Use `logging` instead of `print`, `output/` for all file output, and `if __name__ == "__main__": main()` entry points.
- **Add or update docstrings** for any function you create or significantly modify.
- **Test your changes** against a real Azure environment before opening a PR. Include a brief description of what you verified.

## Reporting Issues

Please open a GitHub Issue with:
- A clear description of the problem.
- The script name and the Azure API endpoint involved.
- The error message or unexpected behavior.
- (Optional) Anonymized output showing the issue.

## Required Azure Permissions

See the `Required permissions` section in each script's module docstring for the
specific RBAC actions needed. A consolidated list is maintained in the `README.md`.
