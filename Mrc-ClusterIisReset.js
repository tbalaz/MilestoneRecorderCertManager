// Mrc-ClusterIisReset.js
// WSFC Generic Script resource for a clustered Milestone XProtect Management Server.
//
// What it does: every time the Management Server role comes online on a node (failover, move, start), this
// resource restarts IIS on that node (iisreset /restart) right after the Management Server service resource is
// online - the manual fix for a node that took the role over with stale IDP secrets.
// It never fails the role: an iisreset error is logged (cluster log + Application event log, source
// 'MRC IIS restart', event 100), and the resource still reports success.
//
// Install (administrator, once):
//  1. On EVERY Management Server cluster node, copy this file to the same local path, for example
//       C:\Program Files\MilestoneRecorderCertManager\Mrc-ClusterIisReset.js
//     Use a folder only administrators can write (the cluster runs this script as SYSTEM), and a local disk, not a
//     cluster disk.
//  2. On one node, in an elevated Windows PowerShell (take the two names from Failover Cluster Manager):
//       $role = '<Management Server role name>'
//       $ms   = '<Management Server service resource name in that role>'
//       $js   = 'C:\Program Files\MilestoneRecorderCertManager\Mrc-ClusterIisReset.js'
//       Add-ClusterResource -Name 'MRC IIS restart' -ResourceType 'Generic Script' -Group $role
//       Get-ClusterResource 'MRC IIS restart' | Set-ClusterParameter -Name ScriptFilepath -Value $js
//       Add-ClusterResourceDependency -Resource 'MRC IIS restart' -Provider $ms
//       Start-ClusterResource 'MRC IIS restart'   # restarts IIS once on the node that runs the role now
//     Or in Failover Cluster Manager: Roles > the role > Add Resource > More Resources > Generic Script, script
//     path as above; the new resource > Properties > Dependencies > the Management Server service resource;
//     Bring Online.
// Check: the resource is Online; Get-ClusterLog has "MRC IIS restart: iisreset /restart exit code 0" per online.
// Remove: Remove-ClusterResource 'MRC IIS restart' (nothing depends on it), then delete the file on every node.
//
// JScript, not VBScript (Windows is removing VBScript). The cluster script host has no WScript object, so
// WScript.Shell comes from ActiveXObject. Entry points: 0 / true = success, nonzero / false = failure.

var IISRESET = "%windir%\\System32\\iisreset.exe";
var EVENTCREATE = "%windir%\\System32\\eventcreate.exe";

function Open() { return 0; }

function Online() {
    var sh = new ActiveXObject("WScript.Shell");
    var rc = sh.Run("\"" + sh.ExpandEnvironmentStrings(IISRESET) + "\" /restart", 0, true);
    var msg = "MRC IIS restart: iisreset /restart exit code " + rc;
    Resource.LogInformation(msg);
    if (rc != 0) {
        sh.Run("\"" + sh.ExpandEnvironmentStrings(EVENTCREATE) + "\" /T WARNING /ID 100 /L APPLICATION /SO \"MRC IIS restart\" /D \"" + msg + " - the Management Server role stays online; restart IIS on this node by hand.\"", 0, true);
    }
    return 0;
}

function Offline() { return 0; }
function LooksAlive() { return true; }
function IsAlive() { return true; }
function Close() { return 0; }
function Terminate() { return 0; }
