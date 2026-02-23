<p align="center"><img src="https://raw.githubusercontent.com/talder/xyOps-AD-Groups/refs/heads/main/logo.svg" height="108" alt="xyOps AD Groups Logo"/></p>
<h1 align="center">xyOps AD Groups</h1>

# xyOps Active Directory Groups Event Plugin

[![Version](https://img.shields.io/badge/version-1.0.1-blue.svg)](https://github.com/xyOps/xyOps-AD-Groups)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.md)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)]()

A comprehensive **toolset** for Active Directory group management. Includes **10 dedicated tools** across 3 categories — group lifecycle, membership management, and organisation. Destructive tools default to **dry-run mode** for safety. This is an **event plugin** — use it as a step in an xyOps workflow.

## Disclaimer

**USE AT YOUR OWN RISK.** This software is provided "as is", without warranty of any kind, express or implied. The author and contributors are not responsible for any damages, data loss, or other issues that may arise from the use of this software. Always test in non-production environments first.

---

## Tools (10)

### Group Lifecycle (4)
| Tool | Description |
|------|-------------|
| **Create Group** | Create a new AD security or distribution group with scope/category options |
| **Delete Group** | Permanently delete groups (dry-run by default) |
| **Rename Group** | Rename a group's CN, SAM account, or display name (dry-run by default) |
| **Copy Group** | Create a new group by copying memberships and settings from a template |

### Membership (3)
| Tool | Description |
|------|-------------|
| **Add Members** | Add users, computers, or groups as members — pre-validates groups, warns on member failures |
| **Remove Members** | Remove members from groups — pre-validates groups, warns on member failures (dry-run by default) |
| **List Members** | List all members with type, status, and optional recursive expansion |

### Organisation (3)
| Tool | Description |
|------|-------------|
| **Move Group** | Move groups to a different OU (dry-run by default) |
| **Set Group Scope** | Change scope: Global, Universal, or DomainLocal (dry-run by default) |
| **Set Group Category** | Toggle between Security and Distribution (dry-run by default) |

## Features

### Safety — Dry-Run Mode
All destructive tools default to **dry-run mode** (`dryRun = true`). In dry-run mode, the tool shows exactly what would happen without making any changes. Disable dry-run to execute the actual operation.

Dry-run enabled by default on: Delete Group, Rename Group, Remove Members, Move Group, Set Group Scope, Set Group Category.

### Group Pre-Validation
The **Add Members** and **Remove Members** tools resolve all target groups **before** processing any members. If any target group cannot be found, the job **fails immediately** with a clear error listing the missing group(s) — no partial work is done.

### Warning on Member Failures
If all target groups exist but individual members cannot be added or removed (e.g. member not found, permission denied), the job completes with a **warning** status (yellow) instead of success. This provides a clear distinction between:
- **Error** (red) — target group not found (job fails immediately)
- **Warning** (yellow) — group exists but one or more members could not be processed
- **Success** (green) — all operations completed without issues

### Multi-Target Support
Most tools accept comma-separated lists, processing each one individually with per-item success/failure tracking.

### Multi-Object-Type Members
The Add/Remove Members tools automatically resolve member identity as user, computer, or group — no need to specify the object type.

### Audit Trail
Every action emits structured results including the tool name, success/failure status, and counts — ideal for workflow logging and compliance.

## Prerequisites

> **Important:** The machine running this plugin must meet the following requirements.

### 1. ActiveDirectory PowerShell Module (RSAT)

**Windows 10/11:**
```powershell
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

**Windows Server:**
```powershell
Install-WindowsFeature RSAT-AD-PowerShell
```

### 2. Domain Connectivity

The machine must be **domain-joined** or have network connectivity to a domain controller.

### 3. Account Permissions

The account under which xyOps runs must have **Write access** to the relevant AD objects.

| Scenario | Required Permission |
|----------|-------------------|
| Create/delete groups | Account Operators or delegated OU permissions |
| Modify group membership | Group owner or Account Operators |
| Move objects between OUs | Write permission on both source and target OUs |
| Change group scope/category | Write permission on group objects |

## Installation

1. Clone or download this repository to your xyOps plugins directory
2. The plugin will verify that the ActiveDirectory module is installed on first run
3. If the module is missing, a detailed error message with installation instructions is displayed

## Configuration

The plugin uses a **toolset** architecture — select a tool from the dropdown, and only the relevant parameters for that tool are shown.

### Common Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `targetGroups` | Text | — | Group name(s) — comma-separated for multiple |
| `dryRun` | Checkbox | `true` | Preview changes without executing (destructive tools only) |

### Tool-Specific Parameters

| Parameter | Tool(s) | Type | Description |
|-----------|---------|------|-------------|
| `groupName` | Create Group | Text | Name of the new group |
| `groupScope` | Create Group | Select | Global, Universal, or DomainLocal |
| `groupCategory` | Create Group | Select | Security or Distribution |
| `managedBy` | Create Group | Text | Manager SamAccountName or DN |
| `sourceGroup` | Copy Group | Text | Template group to copy from |
| `copyMembers` | Copy Group | Checkbox | Copy all members to new group |
| `members` | Add/Remove Members | Text | Member name(s) — comma-separated |
| `recursive` | List Members | Checkbox | Include members of nested groups |
| `targetOU` | Create/Copy/Move Group | Text | Target OU distinguished name |
| `newScope` | Set Group Scope | Select | New scope value |
| `newCategory` | Set Group Category | Select | New category value |

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0.1 | 2026-02-23 | Group pre-validation, warning status for member failures |
| 1.0.0 | 2026-02-22 | Initial release with 10 tools |

---

For changelog details, see [CHANGELOG.md](CHANGELOG.md).
