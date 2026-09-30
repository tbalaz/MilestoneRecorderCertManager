# Milestone XProtect Encryption Manager

PowerShell tools to turn Milestone XProtect server encryption ON and OFF across the
Management Server, the Event Server and the Recording Servers, including a Management
Server and/or Event Server running as a Windows Server Failover Cluster role. They issue the
certificates, import them, and drive Milestone's ServerConfigurator.

Each script is a single self-contained file: copy it and run it. Windows PowerShell 5.1,
run as Administrator.

## Which script?

| Script | Use it for | Run it on |
| --- | --- | --- |
| **`Mrc-Guided.ps1`** | **Start here - this is all you need.** A 4-step wizard: Connect, Check, Turn encryption ON / OFF, Result. It handles the whole system in the right order: the Event Server, the Management Server and **all Recording Servers** (found automatically from the VMS and handled in parallel), failover clusters included, and it can undo a run. | The Management Server (any node of a cluster) |
| **`Mrc-Doctor.ps1`** | **Health check (read-only).** Checks every server and writes an HTML report of PASS / WARN / FAIL findings, each with a "how to fix" line. It never changes anything. Run it before a change and whenever something looks wrong. | The Management Server (any node of a cluster) |
| `Mrc-Ms-Gui.ps1` | Advanced / troubleshooting: the Management Server alone. | The Management Server |
| `Mrc-Es-Gui.ps1` | Advanced / troubleshooting: a standalone Event Server alone. | The Event Server |
| `Mrc-Rec-Gui.ps1` | Advanced / troubleshooting: Recording Servers alone (the guided script already includes them). | The Management Server or a workstation |

The three role scripts change one role at a time and leave the order to you. Use them only when
support asks for it or for a special case; for normal use, `Mrc-Guided.ps1` covers every role.

## Quick start (guided)

```powershell
# On the Management Server, in Windows PowerShell started "as Administrator":
powershell -ExecutionPolicy Bypass -STA -File .\Mrc-Guided.ps1
```

1. **Connect**: enter the Event Server name (or tick "The Event Server is on this computer, or
   not installed"), an admin account, and the signing CA. Recording Servers are found
   automatically from the VMS (needs MilestonePSTools on the Management Server); add any
   missing ones in "Extra recording servers". Tick "Recording servers use a different account"
   if they need their own login. If something on this page fails, click **Open log**: it shows
   every address and account that was tried and the exact reason.
2. **Check**: see every server (every cluster node) and whether it is encrypted now.
3. **Action**: click **Turn encryption ON** or **Turn encryption OFF**.
4. **Result**: the final state of every server, and a saved report. If something failed:
   **Undo this run (roll back)**.

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

## Health check: Mrc-Doctor.ps1

```powershell
# On the Management Server, in Windows PowerShell started "as Administrator":
powershell -ExecutionPolicy Bypass -STA -File .\Mrc-Doctor.ps1
```

Fill in the same details as step 1 of the wizard, then click **Run checks**. When the checks
finish, click **Open report**. It is **read-only**: it never changes anything on any server,
including the WinRM TrustedHosts list. It checks every server with one connection each; recording
servers are checked 32 at a time.

| Area | What it checks |
| --- | --- |
| Inventory | Management Server (single or cluster), Event Server, all recording servers; the Milestone version on every server |
| Reachability | WinRM (with the exact reason and fix), DNS forward and reverse, Milestone ports, clock differences |
| Services | Milestone services, start type, state, accounts; ServerConfigurator can be found |
| Registration | The management-server address that each component (Data Collector, Event Server, Log Server, Incident Manager, API Gateway, recording servers) is registered to |
| Encryption | Real state per server, valid combinations, certificate expiry / names / trust / private-key access |
| Cluster | Role and node health, resources, which Management Server node can take over after a failover |
| IIS | Milestone applications, application pools and their identity, 80/443 bindings and the 443 certificate |
| Config | Milestone config files that do not parse, database connection strings (server and database name only, never passwords), differences between cluster nodes |
| Environment | SQL reachability and response time, free disk and memory, recent Milestone errors in the event log |

The report is saved as HTML, CSV and TXT in `%TEMP%\MilestoneRecorderCertManager-runs\`.
Headless: `.\Mrc-Doctor.ps1 -Run -Domain <domain> -EsHost <event-server> -AdminUser <DOMAIN\user>
-AdminPwFile <path>` (exit code 0 = no FAIL, 1 = at least one FAIL, 2 = error, 3 = refused).

## Before any change: the pre-flight check

Nothing is changed until every check passes:

- every server is reachable and its current state can be read;
- ServerConfigurator can be found on every server (see "Milestone installed in another folder");
- the signing CA is present (when certificates must be issued);
- on a cluster: every node of the role is Up, and the role is healthy;
- every server is registered to the same management-server address the wizard works with.
  A server registered to another address (for example one cluster node's own name instead
  of the cluster name) fails later changes. The wizard offers to fix it with Milestone's
  ServerConfigurator Register (headless: `-FixRegistration`).

## Failover clusters (WSFC)

The Management Server and/or the Event Server may run as a Windows Server Failover Cluster
role (generic services). Run the wizard on any Management Server node.

- One certificate per cluster: the cluster name plus every node that can own the role. It is
  installed on every such node.
- ServerConfigurator runs node by node while the cluster nodes are paused. The node that
  owns the role runs last, so the role ends where it was. Every node has a short outage.
- **Known Milestone limitation:** in a Management Server cluster only the node that ran
  ServerConfigurator last can start the Management Server. The Result page names the nodes
  that cannot take over. After a failover to such a node, open the wizard **on that node** and
  click **Re-register this node** (headless: `-Action register`). This also works when the
  other node is paused or down.
- Optional failover self-test (headless: `-TestFailover`): each role is moved to every other
  node and back, and must come up there. Management Server nodes that cannot take over
  (see above) are skipped and named.

## Undo (rollback)

Before every run the wizard saves the current state of every server as a JSON snapshot next to
the report. If a run fails, click **Undo this run (roll back)**. It reverses only what that run
changed, in the correct order, and moves cluster roles back. **Undo an earlier run...** on the
Action page takes any older snapshot (headless: `-Action rollback -Snapshot <file>`).

Limits: undoing an OFF run issues new certificates from the signing CA; it does not bring back
the original certificates. A Recording Server cannot be put back into a state that the
Management Server does not allow (Recording Servers follow the Management Server); it is
skipped with a message.

## Requirements

- Windows PowerShell 5.1 (not PowerShell 7). WinForms needs the Windows PowerShell host.
- Run as Administrator.
- WinRM from the Management Server to the Event Server and the Recording Servers. Servers
  addressed by IP are added to WinRM TrustedHosts automatically. When Kerberos cannot be used
  for a name (workgroup servers, cluster names), the wizard connects by IP address instead.
- On a failover cluster: the "Failover Cluster Module for Windows PowerShell" on every node
  (Windows feature RSAT-Clustering-PowerShell). Without it the wizard refuses to change
  anything, rather than treating a cluster node as a single server.
- An admin account that is a local administrator on those servers and in the Milestone
  Administrators role. A domain account (`DOMAIN\user`) or a local Windows account works. Type a
  local account as `COMPUTERNAME\user` or just `user` (both are tried). A local account must
  exist with the same name and password on every server. If it is not the built-in
  Administrator, set `LocalAccountTokenFilterPolicy=1` on the remote servers, otherwise
  Windows blocks its admin rights over WinRM.
- A signing CA with its private key in the Management Server's certificate store. All
  certificates must chain to the same CA. Use "Create signing CA" only if encryption was
  never set up in the system.

## Milestone installed in another folder

All scripts find `ServerConfigurator.exe` on each server by themselves. They look in the folder of
the Milestone services that are installed on that server, then in
`%ProgramFiles%\Milestone\Server Configurator`. If Milestone is installed somewhere unusual, give
extra folders: **Search folders...** on the Connect page (one folder per line, for example
`D:\Milestone`), or `-SearchPaths 'D:\Milestone;E:\Apps'` headless, or the `SearchPaths` key in
the defaults file. Each folder is also searched below (4 levels), and MilestonePSTools found there
is loaded as well. If ServerConfigurator still cannot be found, the pre-flight check says so for
that server and lists every place it looked; nothing is changed.

## Optional defaults file

To pre-fill the fields for one environment, put a `mrc.defaults.psd1` next to the script.
See the comment block near the top of each script for the keys. Keep it out of anything you
share: it is listed in `.gitignore`.

## Headless use

```powershell
.\Mrc-Guided.ps1 -Action status|on|off -EsHost <event-server> -AdminUser <DOMAIN\user> `
    -AdminPwFile <path-to-password-file> -RootSubject '<signing-CA-subject>' `
    [-TestFailover] [-FixRegistration] [-SearchPaths 'D:\Milestone']
.\Mrc-Guided.ps1 -Action register -AdminUser <DOMAIN\user> -AdminPwFile <path>   # this cluster node
.\Mrc-Guided.ps1 -Action rollback -Snapshot <run-...-snapshot.json> -AdminUser ... -AdminPwFile ...
```

Passwords are read from a file, never passed on the command line. Delete the file afterwards.

| Exit code | Meaning |
| --- | --- |
| 0 | Every server ended in the wanted state (status: every server was reachable) |
| 1 | Not complete: see the report; nothing after the failed step was changed |
| 2 | Fatal error |
| 3 | Refused: not a Management Server, not elevated, or missing input |
| 4 | Encryption succeeded everywhere, but the `-TestFailover` self-test failed |

## Disclaimer

Provided as-is, with no warranty. Test in a lab first, and take a backup or snapshot before
changing encryption on a production system.
