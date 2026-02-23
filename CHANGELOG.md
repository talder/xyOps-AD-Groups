# Changelog

All notable changes to the xyOps AD Groups Plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-02-23

### Added
- `Write-XYWarning` — New output helper that emits `code: "warning"` for the xyOps warning state (yellow badge/banner)
- **Group pre-validation** on Add Members and Remove Members — all target groups are resolved upfront before any member operations begin
- `warning` flag on Add Members and Remove Members result objects
- Plugin logo (`logo.svg`)

### Changed
- **Add Members** — If any target group is not found, the job now **fails immediately** with a clear error (e.g. `Target group(s) not found: 'xyops_test'`) instead of silently reporting per-member failures as success
- **Add Members** — If groups exist but individual members cannot be added, the job completes with **warning** status instead of success
- **Remove Members** — Same pre-validation and warning behavior as Add Members
- Main entry point now checks the `warning` flag and uses `Write-XYWarning` instead of `Write-XYSuccess` when member-level failures occurred

### Fixed
- Job incorrectly reported as "Success" (green) when all member operations failed due to missing groups — now correctly fails with error

---

## [1.0.0] - 2026-02-22

### Added

#### 10 Tools across 3 categories

**Group Lifecycle (4):**
- **Create Group** — Create a new AD security or distribution group with scope (Global/Universal/DomainLocal), category, description, and managed-by support
- **Delete Group** — Permanently delete group(s) from AD with member count preview (dry-run by default)
- **Rename Group** — Rename a group's CN, SamAccountName, or DisplayName (dry-run by default)
- **Copy Group** — Create a new group by copying memberships, scope, category, description, and managed-by from a template

**Membership (3):**
- **Add Members** — Add users, computers, or groups as members to one or more groups (auto-detects AD object type)
- **Remove Members** — Remove members from one or more groups (dry-run by default)
- **List Members** — List all members with type (User/Computer/Group), enabled status, and optional recursive expansion

**Organisation (3):**
- **Move Group** — Move group(s) to a different Organizational Unit (dry-run by default)
- **Set Group Scope** — Change group scope between Global, Universal, and DomainLocal (dry-run by default)
- **Set Group Category** — Toggle between Security and Distribution group types (dry-run by default)

#### Safety Features
- **Dry-run mode** defaults to true on all destructive operations
- Per-item success/failure tracking with structured audit output
- Multi-target support (comma-separated group names)
- Auto-detection of member object type (user, computer, or group)

#### Shared Helpers
- `Write-XY`, `Write-XYProgress`, `Write-XYSuccess`, `Write-XYError` — xyOps I/O contract
- `Read-JobFromStdin`, `Get-Param` — Job input handling
- `Assert-ActiveDirectoryModule` — RSAT module check with installation instructions
- `Format-ADValue` — Human-readable value formatting
- `Get-MultipleInputs` — Parse comma/semicolon/newline-separated input
- `Get-DryRunFlag`, `Get-DryRunLabel` — Dry-run mode helpers
- `Resolve-ADGroups` — Batch group resolution with progress tracking

### Technical Details
- **Script Size**: ~965 lines
- **Tools**: 10
- **Functions**: 20+ (helpers + tool functions + entry point)
- **Dependencies**: ActiveDirectory PowerShell module (RSAT)
- **PowerShell Version**: 7.0+
- **Exit Codes**: 0 (success/warning), 1 (error)

### Prerequisites
- Windows machine with RSAT ActiveDirectory PowerShell module installed
- Domain-joined machine or connectivity to a domain controller
- Account with Write access to relevant AD objects
- PowerShell 7.0 or later

---

## Version History Summary

| Version | Date | Description |
|---------|------|-------------|
| 1.0.1 | 2026-02-23 | Group pre-validation, warning status for member failures |
| 1.0.0 | 2026-02-22 | Initial release — 10 tools across 3 categories |
