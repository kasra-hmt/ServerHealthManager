# Server Health Manager

A PowerShell-based Windows Server health-check tool with a simple Windows Forms interface and Read-only Windows health checks.

## Features

- Windows Server operating-system version checks
- Windows Update status and pending-restart detection
- Date, time, timezone, and synchronization checks
- CPU and memory usage monitoring
- Computer-name and domain-membership checks
- Local-user policy checks
- Windows activation status
- VMware Tools detection
- Volume Shadow Copy Service (VSS) and shadow-copy checks
- Optional Zabbix and Splunk Forwarder checks
- Optional TLS configuration checks
- Installed-software inventory
- Optional endpoint security / EDR checks
- Reports and logs for troubleshooting and review

## Configurable Checks

Checks should be configurable so administrators can enable only the components relevant to their environment.

For example, an organization may use Zabbix without Splunk, or use a different endpoint security product instead of Elastic Agent.

Disabled checks should be reported as skipped or disabled, rather than incorrectly reported as failed.

## Safety

- Automatic remediation should be disabled by default.
- No automatic restart or operating-system reset.
- No automatic domain changes or computer renaming.
- No automatic software removal.
- No automatic changes to TLS settings.
- No automatic installation of monitoring or security agents.
- Remediation should require explicit configuration and user confirmation.

Always review the script and configuration before running it.

## Requirements

- Windows PowerShell 5.1
- Windows with Windows Forms support
- Administrator privileges for checks that require elevated access

Some checks may require additional Windows components, permissions, or environment-specific configuration.

## Usage

1. Download or clone the repository.
2. Review the configuration and enabled checks.
3. Open PowerShell as Administrator when required.
4. Run the script according to the instructions in this repository.
5. Review the results and generated reports.

Test in a lab environment before using the tool on production servers.

## Limitations

Results depend on local permissions, installed components, operating-system version, and the configuration supplied by the administrator. A detected service or registry value does not necessarily prove that a product is fully healthy or compliant.

## Disclaimer

This project is provided for learning, testing, and administrative assistance. It is not a substitute for an organization's approved security policies, change-management procedures, or validation process.
