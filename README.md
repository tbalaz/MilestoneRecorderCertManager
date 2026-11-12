# Milestone XProtect Encryption Manager

PowerShell tools to turn Milestone XProtect server encryption ON and OFF across the
Management Server, the Event Server and the Recording Servers, including a Management
Server and/or Event Server running as a Windows Server Failover Cluster role. They issue the
certificates (or install certificate files from your own CA), import them, and drive Milestone's
ServerConfigurator.

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
| `Mrc-ClusterIisReset.ps1` | Cluster helper: restarts IIS on the Management Server node the role comes online on (see [Failover clusters](#failover-clusters-wsfc)). | A WSFC Generic Application resource in the Management Server role |
| `Mrc-EsListenerUrl.ps1` | Cluster helper: keeps the Event Server's registered services on the Event Server cluster listener (see [Failover clusters](#failover-clusters-wsfc)). | A WSFC Generic Application resource in the Event Server role |

The three role scripts change one role at a time and leave the order to you. Use them only when
support asks for it or for a special case; for normal use, `Mrc-Guided.ps1` covers every role.

## Quick start (guided)

```powershell
# On the Management Server, in Windows PowerShell started "as Administrator":
powershell -ExecutionPolicy Bypass -STA -File .\Mrc-Guided.ps1
```

1. **Connect**: enter the Event Server name (or tick "The Event Server is on this computer, or
   not installed"), an admin account, and the signing CA - or click **Certificate files...** to use
   certificates from your own CA instead (see below). Recording Servers are found
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

- **ON:** Event Server ("Event server and add-ons"), then Management Server, then "Server
  certificate" on the Event Server computer, then Recording Servers.
- **OFF:** Management Server, then "Server certificate" on the Event Server computer, then
  Recording Servers, then Event Server ("Event server and add-ons").

On an Event Server computer, Server Configurator has two sections. **Server certificate**
(Data Collector) must always match the Management Server: with the Management Server
encrypted and this section off, the Event Server refuses sign-in tokens (the alarms route
answers 401). The wizard turns it on and off with the Management Server, on every Event
Server node (on a cluster: passive nodes first, no role move). **Event server and add-ons**
is optional: untick "Change the 'Event server and add-ons' section" on the Action page
(headless: `-NoEventServerSection`) to leave it as it is.

The "Event server and add-ons" section can only change while the Management Server is **not**
encrypted and "Server certificate" is off. Recording Servers and "Server certificate" can
only move to the state the Management Server is already in. In the wrong order,
ServerConfigurator quits without changing anything and logs no reason.

## What the guided script does for you

- It checks the **real** state after every step: certificate bindings on the Management
  Server and Recording Servers, and the Event Server's own configuration. It does not trust
  a success message alone.
- It skips servers that are already in the wanted state, so running it twice is safe.
- It recovers automatically when a Milestone service will not stop or restart (a known
  cause of ServerConfigurator exit codes 10000 and 20000), with up to 3 attempts.
- When ServerConfigurator applied the change but could not reach the Management Server afterwards
  (a short network drop) and the services did not come back, it runs ServerConfigurator once
  more by itself.
- On a Management Server it lowers the IIS stop wait of the 'VideoOS ApiGateway AppPool' to 30
  seconds while ServerConfigurator runs and puts the old value back afterwards (saves about 1-2
  minutes per Management Server when turning encryption ON).
- It stops at the first real failure and explains in plain language what failed, the current
  state of every server, and what to do next.

## Certificate files from your own CA

Instead of a signing CA, every server can get a certificate prepared by your own CA. Put the
files in one folder:

| File | Certificate must carry |
| --- | --- |
| `<recording-server-fqdn>.p12` (one per Recording Server) | that server's name |
| `<management-server-address>.p12` | the address the Management Server is registered under (on a cluster: the cluster name; every node's name is recommended) |
| `<event-server-address>.p12` | the Event Server name entered on the Connect page, or on a cluster the cluster name. **On a cluster it must also carry the name of every Event Server node**: each node registers the Event Server with the Management Server under its own name, and the API Gateway checks the certificate against that name. A certificate with only the cluster name breaks the alarms route (HTTP 502), so the pre-flight check refuses it. |

One certificate may serve both the Management Server and the Event Server: give it the Management
Server cluster name, the Event Server cluster name and every Event Server node name, and put the same
file into the folder under both file names.

Every file can have its own password. Put them in a plain text file, one line per certificate:

```
rec01.company.local.p12;Secret1
rec02.company.local.p12;Secret2
```

The first `;`, TAB or `,` after the file name ends the name, so a list pasted from Excel or a CSV
works and a password may contain those characters. Pick this file in the **Certificate files...**
dialog. The dialog's password box is the password for any file without a line of its own, and a
text file with one line holding only a password counts for all files. The wizard reads the text file
when you click OK and never writes a password to its logs, so delete the file right after.

`.pfx` works as well. Each file needs its private key, the Server Authentication purpose and valid
dates, and must be issued by your root CA (put an intermediate CA certificate into the file). Give
the root CA file (`.cer`) too: it is added to the trusted root store of every server that gets a
certificate. The pre-flight check opens and checks every file before anything is changed and names
each missing or wrong one. Smart Client computers need your root CA as well (for example by Group
Policy), and your CA's revocation list must be reachable.
- It writes a CSV and TXT report to `%TEMP%\MilestoneRecorderCertManager-runs\`. The TXT report has one
  block per server with the full status and error text; the CSV adds a `Step` and an `ExitCode` column.
- `run-<start>-log.txt` in the same folder is written while the run works (every 3 seconds), so a run
  that hangs or is closed still leaves its log. Each step starts with the state it read and the facts it
  used (account, ServerConfigurator folders, cluster role owner and nodes); a server's ServerConfigurator
  log is in the log one line per line.
- When a step fails, `run-<start>-diag-<SERVER>.txt` holds that server's Milestone services, cluster
  state, Windows Application and System errors and warnings, and the full ServerConfigurator log of that
  step. It is collected read-only. Send the report, the log and any diagnostics file to support.

## Health check: Mrc-Doctor.ps1

```powershell
# On the Management Server, in Windows PowerShell started "as Administrator":
powershell -ExecutionPolicy Bypass -STA -File .\Mrc-Doctor.ps1
```

Fill in the same details as step 1 of the wizard, then click **Run checks**. When the checks
finish, click **Open report**. It is **read-only**: it never changes anything on any server,
including the WinRM TrustedHosts list. It checks every server with one connection each; recording
servers are checked 32 at a time, and their names, WinRM ports and DNS records are checked all at once,
so a few hundred recording servers take minutes. A recording server whose WinRM port (5985) does not
answer within 5 seconds is reported as not reachable.

| Area | What it checks |
| --- | --- |
| Inventory | Management Server (single or cluster), Event Server, all recording servers; the Milestone version on every server |
| Reachability | WinRM (with the exact reason and fix), DNS forward and reverse, Milestone ports, clock differences |
| Services | Milestone services, start type, state, accounts; ServerConfigurator can be found; a Recording Server installed on a Management Server computer (stopped or not set to Automatic = WARN, disabled = note) |
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
- the signing CA is present (when certificates must be issued), or every certificate file is
  present and correct (when you use your own files);
- a separate recording-server account is accepted by the Management Server (see Requirements);
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
- **Management Server cluster: every node can take over.** Milestone itself lets only the node
  that ran ServerConfigurator last start the Management Server: each node keeps its own copy of
  the Management Server's identity secrets. After every ServerConfigurator run on a Management
  Server node, the wizard copies that node's secrets to the other nodes (with Milestone's own
  encryption library on each node; Milestone does not document this step), so any node can start
  the Management Server after a failover, automatic ones included (a crash, a reboot for Windows
  updates). This needs the Management Server services to run as NETWORK SERVICE (the default).
  A node that did not get the copy (paused, down, or another service account) is named on the
  Result page. After a failover to such a node, open the wizard **on that node** and click
  **Re-register this node** (headless: `-Action register`); the wizard then copies that node's
  secrets to the other nodes.
- Optional failover self-test (headless: `-TestFailover`): each role is moved to every other
  node and back, and must come up there. Management Server nodes that cannot take over
  (see above) are skipped and named.
- **Optional: IIS restart on failover (`Mrc-ClusterIisReset.ps1`).** For this case, reported
  from the field: after a failover the Management Server service is running, but logins fail,
  and an IIS restart on the node that took the role over fixes it. This Generic Application
  resource (PowerShell, runs as SYSTEM) depends on the Management Server service resource and
  runs `iisreset /restart` on that node every time the role comes online, then stays running.
  It never fails the role. The result goes to the Application event log (source
  `MRC IIS restart`: event 101 on success, 100 on failure). Install and remove steps are in the
  file header. It does **not** help when the Management Server service itself does not start
  on that node (`invalid_client` in its log, the limitation above). Then use
  **Re-register this node**.
- **Event Server cluster: registered URLs on the listener (`Mrc-EsListenerUrl.ps1`).**
  ServerConfigurator registers a clustered Event Server's "Event Server service" and "Alarms
  Service" under the node it ran on, and the Event Server re-registers "Alarms Service" with its
  node name every time it starts. After a role move, clients and the API Gateway can then go to
  the wrong node. This script sets both registered URLs to the Event Server cluster listener (the
  same change as Management Client > Tools > Registered Services > Edit). As a Generic Application
  resource in the Event Server role it runs `-Watch` as SYSTEM and re-checks every 60 seconds, so
  a role move or a ServerConfigurator run is corrected within a minute. It needs MilestonePSTools
  for all users on every Event Server node; the node computer accounts must be Milestone
  administrators (they already are when the Milestone services run as NETWORK SERVICE). When
  "Event server and add-ons" is encrypted, the Event Server certificate must contain the listener.
  Setup steps are in the file header.

## Recording Servers in waves (canary first)

To turn encryption ON for a few Recording Servers before all of them, tick Recording Server rows
on the Check page: **Canary** (the first one or two) and **Canary group** (the next batch). On the
Action page choose the wave, then click ON:

- **Canary only**: the Management Server, the Event Server and the canary Recording Servers.
- **Canary + canary group**: also the canary group. Refused until the canary is encrypted.
- **All recording servers** (the default): every Recording Server. Refused while a ticked canary
  or canary group Recording Server is not encrypted yet: finish that wave first, or untick it.

Recording Servers outside the wave are left as they are, and the result page says so. OFF always
covers every Recording Server. The ticks are saved next to the run reports
(`recorder-waves.json`). Headless: `-Wave canary|group|all` with `-CanaryRecorders` and
`-CanaryGroupRecorders` (comma lists of names or addresses; they replace the saved ticks).

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
- Recording Servers outside the domain (workgroup) with their own account: tick "Recording servers
  use a different account" and use one local account with the same name and password on every
  Recording Server (a local administrator there). When their encryption changes they log on to the
  Management Server with it, so every Management Server node needs a local account with the same
  name and password in Management Client > Security > Roles > Administrators (each node's account
  is a separate entry; the local Administrators group only helps when that role contains it). The
  wizard reaches workgroup servers by IP address.
- Alternative for Recording Servers outside the domain, without that account on the Management
  Server nodes: also tick "Recording servers register with the Management Server as the admin
  account above" (headless `-RecRegisterAsAdmin`, needs `-RecUser`). The Recording Servers are
  still reached with their local account, but when their encryption changes they log on to the
  Management Server as the admin account, which must then be a domain account (`DOMAIN\user` or
  `user@domain`). **Security note:** with this option the admin account's password travels to
  every Recording Server for the run (encrypted in the script text that runs there; the key comes
  from the local account's password), so an administrator of a Recording Server can recover it.
  Use it only where those administrators may hold the admin account.
- A Recording Server that Milestone knows by a computer name without a domain is reached by its
  full name only when that name resolves from the Management Server; otherwise by the name
  Milestone has. If neither resolves, the log says so: add the server under "Extra recording
  servers" as `NAME=<its IP address>`. An address you type there wins over the discovered one.
- A signing CA with its private key in the Management Server's certificate store, or certificate
  files from your own CA (see above). All certificates must chain to the same CA. Use "Create
  signing CA" only if encryption was never set up in the system.

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
    [-TestFailover] [-FixRegistration] [-SearchPaths 'D:\Milestone'] `
    [-RecTargets '<rec1-fqdn>,<REC2>=<rec2-ip>'] [-RecUser <user> -RecPwFile <path> [-RecRegisterAsAdmin]] `
    [-CertFolder <folder> -CertPwFile <path> -RootCaFile <root-ca.cer>]   # own CA: -RootSubject not needed
    [-Wave canary|group|all -CanaryRecorders '<rec1>' -CanaryGroupRecorders '<rec2>,<rec3>']   # ON in waves
    [-NoEventServerSection]   # leave the Event Server's "Event server and add-ons" section as it is
.\Mrc-Guided.ps1 -Action register -AdminUser <DOMAIN\user> -AdminPwFile <path>   # this cluster node
.\Mrc-Guided.ps1 -Action rollback -Snapshot <run-...-snapshot.json> -AdminUser ... -AdminPwFile ...
```

Passwords are read from a file, never passed on the command line. Delete the file afterwards.

| Exit code | Meaning |
| --- | --- |
| 0 | Every server ended in the wanted state (status: every server was reachable; an ON wave: Recording Servers outside the wave are not counted) |
| 1 | Not complete: see the report; nothing after the failed step was changed |
| 2 | Fatal error |
| 3 | Refused: not a Management Server, not elevated, or missing input |
| 4 | Encryption succeeded everywhere, but the `-TestFailover` self-test failed |

## Disclaimer

Provided as-is, with no warranty. Test in a lab first, and take a backup or snapshot before
changing encryption on a production system.
