# Changelog

All notable changes to the ASA-WG standards will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-05-06

### Added — Cloud App & Configuration Profile
- 76 new Azure CIS Level 1 checks from Azure Foundations v5.0.0, Compute v2.0.0, and Database v2.0.0 benchmarks
- New Azure services: Databricks, Batch, Container Instances, Redis, Cosmos DB, Data Factory, App Service Environment, Virtual Machines
- 21 Entra ID checks implemented via Microsoft Graph API (previously INCONCLUSIVE stubs)
- 2 new AWS monitoring checks for full CIS L1 coverage: security group changes (CIS 5.10), NACL changes (CIS 5.11)
- 8 new GCP checks for full CIS L1 coverage: Shielded VM, no public IP, App Engine HTTPS, OS updates, Bucket Lock retention, uniform bucket access, PostgreSQL log_error_verbosity and log_statement flags
- Coverage Notes section documenting Azure CIS L1 gaps planned for future release
- DOCX report templates updated with all new requirements (282 entries)
- 21 new DOCX report generation tests

### Changed — Cloud App & Configuration Profile
- Updated CIS benchmark references: AWS v2.0.0 → v7.0.0, GCP v2.0.0 → v4.0.0, Azure Foundations → v5.0.0, Azure Compute → v2.0.0, Azure Database → v2.0.0
- Fixed Azure registry spec ID renumbering (~40 checks aligned to specification)
- Fixed DOMAINS dict: domain 5 "Data Protection" → "Storage"
- Standardized all REMOVED entries to consistent stub format
- Fixed 21 broken TOC links, duplicate TOC entries, and copy-paste artifacts in Test Guide
- Fixed GCP 6.6.3 CIS reference (was 6.3.7, corrected to 6.3.3)
- Python requirement updated to >=3.12

### Removed — Cloud App & Configuration Profile
- Marked 18 requirements as REMOVED (retired or reclassified to L2 in updated CIS benchmarks)

## [2.0.0] April 3, 2026

### Changed
- Rebranding Mobile App Profile from ASA to MASA v2 (#212)
- Rebranding Web App Profile from ASA to CASA v2 (#213)
- Updated submission form processes
- Added issue and PR templates for standards management workflow

### Added
- `CONTRIBUTING.md` — Standards management lifecycle documentation
- `CHANGELOG.md` — Version history tracking
- `LICENSE` — CC BY-SA 4.0 licensing terms
- GitHub Issue template for new requirements
- GitHub Pull Request template

## [1.0] - 2024-10-11

### Added
- Initial release of ASA-WG standards
- Mobile App Security Assessment (MASA) Profile v1.0
- Web App Security Assessment (CASA) Profile v1.0
- Cloud App & Configuration Profile v1.0
