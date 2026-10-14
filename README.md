# ServerHealthManager

A PowerShell-based Windows Server health-check tool with a graphical user interface (GUI).

ServerHealthManager helps administrators review selected system health indicators, identify potential issues, and generate reports for troubleshooting and documentation.

## Features

- Graphical user interface for running health checks.
- Configurable checks through the script's configuration settings.
- System health information and service status checks.
- Windows activation status reporting.
- TLS configuration inspection.
- Monitoring-agent and security-software detection where configured.
- Health-check reports for later review.
- Read-only checks by default.

## Safety and Scope

**The public version is intended for inspection and reporting, not automatic remediation.**

The tool does not intentionally modify system settings, activate Windows, change the system time zone, disable TLS protocols, or restart the computer.

Some checks may require administrator privileges or may return incomplete results when permissions, required components, or system information are unavailable.

A reported issue does not always mean the system is unhealthy. Administrators should review the result and verify the underlying condition before taking action.

This project is provided for learning, testing, and administrative assistance. Review the source code before running it in any environment, and test it on a personal or disposable test machine before considering production use.

## Requirements

- Windows with Windows PowerShell 5.1.
- Appropriate permissions for the checks being performed.
- Optional system components or monitoring agents for checks that depend on them.

Some checks may behave differently across Windows versions, system configurations, and display languages. Non-English Windows environments should be tested before relying on the results.

## Download

1. Open the [ServerHealthManager repository](https://github.com/kasra-hmt/ServerHealthManager).
2. Select **Code**.
3. Select **Download ZIP**.
4. Extract the downloaded archive to a folder on your computer.

## Run

Open Windows PowerShell in the extracted project folder.

Check your PowerShell version:

```powershell
$PSVersionTable.PSVersion
```

For Windows PowerShell 5.1, the major version should be `5` and the minor version should be `1`.

If Windows has marked the downloaded script as coming from the internet, review the source before unblocking it. If you trust the script, you can unblock the script file:

```powershell
Unblock-File .\ServerHealthManager.ps1
```

To allow script execution only in the current PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process RemoteSigned
```

Then launch the application:

```powershell
.\ServerHealthManager.ps1
```

Execution-policy settings may also be controlled by organizational policy. Do not attempt to override your organization's security restrictions.

Alternatively, review `Run-ServerHealthManager.bat` before using it.

## Configuration

The script contains configuration options for enabling or disabling selected checks. Review the `$EnabledChecks` configuration and any related policy settings in the source code before running the application.

Only enable checks that you understand and need. A check being disabled does not necessarily mean the related system component is missing or broken.

## Reports and Troubleshooting

Review the generated reports for check results, warnings, errors, and checks that require manual verification.

Results may depend on permissions, available Windows components, monitoring-agent installation, system language, and configuration. A failed check may indicate a genuine issue or a limitation in how that check obtains information.

Do not publish reports containing sensitive information such as internal hostnames, domain names, IP addresses, usernames, or other environment-specific details.

## Limitations

- The tool has not been validated on every Windows version or language.
- Some checks may depend on localized Windows performance-counter names or command output.
- Detection of third-party monitoring and security software depends on the configured detection rules.
- The tool is not a replacement for a full monitoring platform, security audit, or administrator review.
- No claim of production readiness is made without appropriate testing.

## Future Development

Potential improvements include more robust multilingual support, expanded test coverage, configurable health-check profiles, and a separate, explicitly approved remediation workflow.

Any future remediation feature should clearly explain the proposed change, require explicit user approval, record the outcome, and remain disabled by default.

## License

See [LICENSE](LICENSE) for the project's license terms.

## Disclaimer

This project is provided for learning, testing, and administrative assistance. It is not a substitute for an organization's approved security policies, change-management procedures, or validation process.
