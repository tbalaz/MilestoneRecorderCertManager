# Milestone XProtect Encryption Manager

PowerShell tools to turn Milestone XProtect server encryption ON and OFF across the
Management Server, a standalone Event Server and the Recording Servers. They issue the
certificates, import them, and drive Milestone's ServerConfigurator.

Each script is a single self-contained file: copy it and run it. Windows PowerShell 5.1,
run as Administrator.

## Which script?

| Script | Use it for | Run it on |
| --- | --- | --- |
| **`Mrc-Guided.ps1`** | **Start here.** A 4-step wizard for everyday use: Connect, Check, Turn encryption ON / OFF, Result. It handles the whole system in the right order. | The Management Server |
| `Mrc-Ms-Gui.ps1` | Management Server only (advanced). | The Management Server |
| `Mrc-Es-Gui.ps1` | A standalone Event Server only (advanced). | The Event Server |
| `Mrc-Rec-Gui.ps1` | Recording Servers only, discovered from the VMS and handled in parallel (advanced). | The Management Server or a workstation |

## Quick start (guided)

```powershell
# On the Management Server, in Windows PowerShell started "as Administrator":
powershell -ExecutionPolicy Bypass -STA -File .\Mrc-Guided.ps1
```

1. **Connect**: enter the Event Server name (or tick "There is no separate Event Server"), an
   admin account, and the signing CA. Recording Servers are found automatically.
2. **Check**: see every server and whether it is encrypted now.
3. **Action**: click **Turn encryption ON** or **Turn encryption OFF**.
4. **Result**: the final state of every server, and a saved report.

## The order matters

Milestone only accepts encryption changes in a specific order. The guided script applies
it for you. The role GUIs block wrong-order runs.

- **ON:** Event Server, then Management Server, then Recording Servers.
- **OFF:** Management Server, then Recording Servers, then Event Server.

The Event Server can only change while the Management Server is **not** encrypted.
Recording Servers can only move to the state the Management Server is already in. In the
wrong order, ServerConfigurator quits without changing anything and logs no reason.

## What the guided script does for you

- It checks the **real** state after every step: certificate bindings on the Management
  Server and Recording Servers, and the Event Server's own configuration. It does not trust
  a success message alone.
- It skips servers that are already in the wanted state, so running it twice is safe.
- It recovers automatically when a Milestone service will not stop or restart (a known
  cause of ServerConfigurator exit codes 10000 and 20000), with up to 3 attempts.
- It stops at the first real failure and explains in plain language what failed, the current
  state of every server, and what to do next.
- It writes a CSV and TXT report to `%TEMP%\MilestoneRecorderCertManager-runs\`.

## Requirements

- Windows PowerShell 5.1 (not PowerShell 7). WinForms needs the Windows PowerShell host.
- Run as Administrator.
- WinRM from the Management Server to the Event Server and the Recording Servers. Servers
  addressed by IP are added to WinRM TrustedHosts automatically.
- An admin account that is a local administrator on those servers and in the Milestone
  Administrators role.
- A signing CA with its private key in the Management Server's certificate store. All
  certificates must chain to the same CA. Use "Create signing CA" only if encryption was
  never set up in the system.

## Optional defaults file

To pre-fill the fields for one environment, put a `mrc.defaults.psd1` next to the script.
See the comment block near the top of each script for the keys. Keep it out of anything you
share: it is listed in `.gitignore`.

## Headless use

```powershell
.\Mrc-Guided.ps1 -Action status|on|off -EsHost <event-server> -AdminUser <DOMAIN\user> `
    -AdminPwFile <path-to-password-file> -RootSubject '<signing-CA-subject>'
```

Exit code 0 means every server ended in the wanted state. Passwords are read from a file,
never passed on the command line.

## Disclaimer

Provided as-is, with no warranty. Test in a lab first, and take a backup or snapshot before
changing encryption on a production system.
