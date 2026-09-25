
1. Is 5145 DC-specific, and can MDE show it on endpoints?

No. 5145 is logged by whichever Windows machine hosts the share, for every access check on a file, folder or named pipe, as long as that machine audits "Detailed File Share". DCs are just where it's loudest: Microsoft rates the volume as high on domain controllers because Group Policy needs network access to SYSVOL. Failure events only fire when access is denied at the share level; a denial at the NTFS level produces no event. 
Microsoft Learn
Microsoft Learn

This means the 5145s on your DCs describe the clients. Endpoints show up in them as sources, in the IpAddress and SubjectUserName fields, and that's the more useful angle (step 4 below). A workstation only logs 5145 for inbound access to its own shares (C$, ADMIN$, IPC$), and only if its audit policy enables the subcategory, which is off by default. So a spike driven by Group Policy or SYSVOL would never appear on endpoints, while something sweeping machines over SMB would.

MDE does have an equivalent: DeviceEvents with ActionType NetworkShareObjectAccessChecked, which records a request to access a network-shared file or folder where the share permissions were evaluated. It mirrors the Windows audit event, so expect it only on devices that audit the subcategory. Treat it as a trend rather than an exact count, since MDE throttles some high-volume telemetry. If your DCs are onboarded to MDE, it also gives you a second, independent pipeline to compare against Sentinel: 
XDR table schema

kql
// Defender XDR advanced hunting
let deviceType = DeviceInfo
    | where Timestamp > ago(7d)
    | summarize arg_max(Timestamp, DeviceType) by DeviceId
    | project DeviceId, DeviceType;
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "NetworkShareObjectAccessChecked"
| lookup kind=leftouter deviceType on DeviceId
| summarize Events = count() by bin(Timestamp, 1d), DeviceType
| render timechart

If there are no workstation rows, that most likely means "not audited" rather than "no spike". Change the ActionType to AuditPolicyModification, which captures changes to the Windows audit policy, to see whether audit settings changed anywhere around the same date. 
XDR table schema

2. Anything public that explains it?

I couldn't find any advisory, release-health entry or community thread linking a 5145 surge to a recent change. These things did change in the same window and are worth lining up against your curve:

September updates. The September 8 cumulative updates were followed by an out-of-band update on September 14 that fixed Remote Desktop instability introduced by the September release. If your broad ring installs about a week after Patch Tuesday, a fleet-wide client change landing around the 15th–17th fits your timing. 
Microsoft Learn
Machine Identity Isolation known issue, opened September 16. The update makes Windows start honoring any existing or policy-provisioned Machine Identity Isolation enforcement settings. The feature is only supported with DCs at Windows Server 2025 domain functional level, and elsewhere Credential Guard-protected machine accounts can lose their secure channel. It comes with KB5124008 on 24H2/25H2 and KB5124012 on 26H1. I'd expect this to show up as machine-account authentication failures rather than share access checks, so treat it as something to rule out (the query in #3 covers it). 
Microsoft Learn
Bleeping Computer
Defender Antivirus platform update. Version 4.18.26080.4 was released on September 17 for both client and server Windows. There's no known link to SMB auditing; I mention it only because it's a fleet-wide change on the exact day. 
Microsoft Learn
Azure Monitor Agent (AMA) rollout. Windows version 1.45 began rolling out on August 13, and rollouts take 4–6 weeks to reach all regions, so your DCs may have auto-upgraded recently. Nothing in its release notes suggests a volume change, but Heartbeat | where Category == "Azure Monitor Agent" | summarize min(TimeGenerated) by Computer, Version rules it out in seconds. 
Microsoft Learn
3. Can the RC4 phase-out cause this?

Not directly. 5145 is written after the SMB session is already authenticated, so whether the Kerberos ticket used AES or RC4 doesn't change whether or how often share access is audited.

The timing doesn't fit either. Audit events arrived with the January 13 updates. On April 14 the default flipped to AES only, with a registry rollback available. On July 14 the rollback was removed and enforcement became permanent. It would only line up if your DCs received a July-or-later cumulative update last week, or if someone changed Kerberos encryption types last week. Even then, a GPO edit by itself only causes a one-off burst of SYSVOL re-reads, not a week of sustained volume. 
Hypergate

There are two indirect paths worth a minute:

Authentication fallout. Clients failing Kerberos and falling back to NTLM or retrying can raise 5145 for the affected hosts, but that wouldn't produce a uniform jump across the whole domain.
Procedural side effect (the more plausible link). RC4 readiness guidance tells admins to enable Kerberos auditing on all DCs through Group Policy. If someone did that last week using a broad audit template, Detailed File Share success auditing may have been switched on along with it. The 4719 check in step 2 will show this. 
Microsoft Community Hub

To test the authentication side, and the Machine Identity Isolation issue at the same time:

kql
SecurityEvent
| where TimeGenerated > ago(21d)
| where EventID in (5145, 4625, 4771, 4776)
    or (EventID in (4768, 4769) and Status != "0x0")
| extend Series = iff(EventID in (4768, 4769), strcat(EventID, " status ", Status), tostring(EventID))
| summarize Events = count() by bin(TimeGenerated, 1d), Series
| render timechart with (yaxis=log)

How to read it:

Status 0xE on 4768/4769 (KDC_ERR_ETYPE_NOSUPP) is what encryption-type mismatches look like. The Kdcsvc 201–209 events are in the System log, so they're only in Sentinel if your DCR collects them.
A same-day jump in 4771/4776 failures for computer accounts (names ending in $) points to Machine Identity Isolation instead.
If these lines stay flat while 5145 steps up, drop both theories.
4. Pinpointing the cause

The even spread across DCs is itself a clue. It means either a change applied to every DC (audit policy, DCR, agent) or a large client population reaching DCs through the DC locator. A single noisy host normally sticks to its site DC unless it's deliberately sweeping all of them.

Also zoom the chart to hourly around the start and look at the shape:

A clean step at one moment on all DCs points to configuration. DCs refresh Group Policy every 5 minutes, so an audit-policy change lands almost simultaneously.
A ramp over several days points to a rollout (patches, an agent, software).
A business-hours rhythm points to user activity.
A flat 24/7 line points to servers or services.

Step 1: Is the growth real, or just ingested twice? AMA 1.29 added EventRecordId and Keywords columns to SecurityEvent, which makes duplicate ingestion easy to spot: 
Microsoft Learn

kql
SecurityEvent
| where TimeGenerated > ago(2h) and EventID == 5145
| summarize Copies = count() by Computer, EventRecordId
| summarize Rows = sum(Copies), UniqueEvents = count() by Computer
| extend RowsPerEvent = round(todouble(Rows) / UniqueEvents, 2)

A ratio near 2 means the DC is associated with two DCRs collecting the same events. Three more pipeline checks:

Did everything grow? Chart iff(EventID == 5145, "5145", "everything else") by day. If everything grew by the same factor, it's the pipeline.
Did a DCR change? Search AzureActivity for OperationNameValue containing dataCollectionRule around the start date. A DCR that was edited or re-created and lost an XPath filter would explain a clean step.
Does MDE agree? If the DCs are in MDE, compare with their rows from the first query.

Step 2: Did the audit policy change?

kql
SecurityEvent
| where TimeGenerated > ago(30d) and EventID == 4719
| where SubcategoryGuid contains "0CCE9244"   // Detailed File Share
| project TimeGenerated, Computer, SubjectUserName, AuditPolicyChanges
| order by TimeGenerated asc

And on a DC:

powershell
auditpol /get /subcategory:"Detailed File Share"
gpresult /scope computer /h "$env:TEMP\gpresult.html"    # shows which GPO sets it
Get-GPO -All | Sort-Object ModificationTime -Descending |
    Select-Object -First 15 DisplayName, Id, ModificationTime

CIS only recommends including Failure for this subcategory, so "Success and Failure" on DCs is a red flag. Also look for the legacy "Audit object access" setting in any GPO that applies to DCs. If it's in effect (meaning "Audit: Force audit policy subcategory settings … to override audit policy category settings" isn't), it turns on every Object Access subcategory, 5145 included. 
Tenable

Step 3: Which dimension grew?

kql
let spikeStart = datetime(2026-09-17 00:00);   // hour the step starts, UTC
SecurityEvent
| where TimeGenerated between ((spikeStart - 7d) .. (spikeStart + 7d))
| where EventID == 5145
| extend Period = iff(TimeGenerated < spikeStart, "1-before", "2-after")
| summarize Events = count(), Sources = dcount(IpAddress), Accounts = dcount(SubjectUserName),
            PctMachineAccts = round(100.0 * countif(SubjectUserName endswith "$") / count(), 1)
    by Period, Keywords
| extend EventsPerSource = round(1.0 * Events / Sources, 1)
| order by Period asc

This shows whether new sources appeared or the same sources got chattier, whether it's machine or user accounts, and success versus failure. Next, see what the sources are touching:

kql
let spikeStart = datetime(2026-09-17 00:00);
SecurityEvent
| where TimeGenerated between ((spikeStart - 7d) .. (spikeStart + 7d))
| where EventID == 5145
| extend Share = replace_string(ShareName, @"\\*\", "")
| extend Target = case(
    Share =~ "SYSVOL", coalesce(extract(@"\{[0-9A-Fa-f\-]{36}\}", 0, RelativeTargetName),  // GPO GUID
                                tostring(split(RelativeTargetName, @"\")[1])),
    Share =~ "IPC$",   RelativeTargetName,                                                 // named pipe
    tostring(split(RelativeTargetName, @"\")[0]))
| summarize Before = countif(TimeGenerated < spikeStart), After = countif(TimeGenerated >= spikeStart)
    by Share, Target
| extend Growth = After - Before
| top 20 by Growth desc

Swap by Share, Target for by IpAddress or by SubjectUserName to rank sources the same way. How to read the top rows:

SYSVOL with a GPO GUID. A normal Group Policy read shows up as a SYSVOL path under Policies{GUID} with read access mask 0x120089. Run Get-GPO -Guid on the top GUID and check what changed: a lowered refresh interval, "Process even if the Group Policy objects have not changed" enabled, or a new Preferences file copy or scheduled task. 
Ultimate Windows Security
NETLOGON. Usually a logon script, or a scheduled task running a script from there. DeviceProcessEvents | where ProcessCommandLine has_any ("NETLOGON","SYSVOL") | summarize FirstSeen=min(Timestamp), Devices=dcount(DeviceId) by FileName, ProcessCommandLine will show one that first appeared at the spike.
IPC$ (named pipes). This is RPC over SMB: lsarpc (SID/name lookups), samr (account and group enumeration), srvsvc (share and session enumeration), netlogon, winreg, spoolss.
From many workstation machine accounts, it's something deployed fleet-wide.
From a handful of hosts, it's a scanner, an inventory or identity-security tool, or reconnaissance (BloodHound-style collection looks a lot like this), so confirm with the owner.
If you run Defender for Identity, IdentityQueryEvents names the source of SAMR queries directly.

Step 4: Tie the sources to devices with MDE. In the Defender portal, with the Sentinel workspace onboarded, you can join both sides in one query. Otherwise, export the top IPs from Sentinel and paste them in as a datatable:

kql
let spikeStart = datetime(2026-09-17 00:00);
let talkers = SecurityEvent
    | where TimeGenerated >= spikeStart and EventID == 5145
    | extend IpAddress = replace_string(IpAddress, "::ffff:", "")
    | summarize Events = count() by IpAddress
    | top 500 by Events;
let ipToDevice = DeviceNetworkInfo
    | where Timestamp >= spikeStart
    | mv-expand ip = parse_json(IPAddresses)
    | extend IpAddress = tostring(ip.IPAddress)
    | summarize arg_max(Timestamp, DeviceId) by IpAddress;
let os = DeviceInfo
    | where Timestamp > ago(7d)
    | summarize arg_max(Timestamp, DeviceName, DeviceType, OSPlatform, OSVersionInfo, OsBuildRevision) by DeviceId;
talkers
| join kind=leftouter ipToDevice on IpAddress
| join kind=leftouter os on DeviceId
| extend OSPlatform = iff(isempty(DeviceName), "(no MDE device for this IP)", OSPlatform)
| summarize IPs = count(), Events = sum(Events) by DeviceType, OSPlatform, OSVersionInfo, OsBuildRevision
| order by Events desc

How to read it:

Concentration on one OS version or build revision that went out around September 14–17 points at the patch or its side effects.
"No MDE device" at the top means servers without MDE, Linux or NAS boxes, VPN pools or appliances.
Next step: drop the last summarize to get per-device rows, then open the top devices' timelines around the spike start and look for new scheduled tasks, services or software.

Once you know the cause, if it turns out to be benign Group Policy traffic, the cheapest fix is to put DCs back to Failure-only for this subcategory. Alternatively, drop successful SYSVOL reads by computer accounts in the DCR, since they carry very little detection value.



#2 
1. When exactly did it start?

kql
SecurityEvent
| where TimeGenerated between (datetime(2026-09-15) .. datetime(2026-09-19))
| where EventID == 5145
| where RelativeTargetName has_any ("FEF166EC-DD2C-4398-AFB4-EDFD99828835", "3C8BADF5-6CCB-4A47-8FAF-12E3155464F8")
| extend Gpo = toupper(extract(@"\{([0-9A-Fa-f\-]{36})\}", 1, RelativeTargetName))
| summarize Events = count() by bin(TimeGenerated, 15m), Gpo
| render timechart

This gives you the 15-minute slot where the jump happened. Look for a change around that time in the next queries.

2. What are these GPOs called, and who changed them? Defender for Identity records GPO creations, setting changes and renames, including the GPO's name and the settings that changed: 
kqlsearch
kqlsearch

kql
let gpos = dynamic(["FEF166EC-DD2C-4398-AFB4-EDFD99828835", "3C8BADF5-6CCB-4A47-8FAF-12E3155464F8"]);
IdentityDirectoryEvents
| where Timestamp > ago(30d)
| where ActionType startswith "Group Policy"
| where tostring(AdditionalFields) has_any (gpos)
| extend Info = parse_json(AdditionalFields)
| project Timestamp, ActionType, GroupPolicyName = tostring(Info.GroupPolicyName),
          AccountName, AccountUpn, MachinePolicies = tostring(Info.MachinePolicies),
          UserPolicies = tostring(Info.UserPolicies)
| order by Timestamp asc

If that comes back empty, the same history is in the DCs' own logs, as long as your DCR collects event 5136:

kql
let gpos = dynamic(["FEF166EC-DD2C-4398-AFB4-EDFD99828835", "3C8BADF5-6CCB-4A47-8FAF-12E3155464F8"]);
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID in (5136, 5137)
| where EventData has_any (gpos)
| extend Attribute = extract(@"Name=""AttributeLDAPDisplayName"">([^<]*)<", 1, EventData),
         Value     = extract(@"Name=""AttributeValue"">([^<]*)<", 1, EventData)
| project TimeGenerated, SubjectUserName, EventID, Attribute, Value
| order by TimeGenerated asc

How to read it:

versionNumber changing every few minutes or hours: something keeps rewriting the GPO, so every client re-downloads all of it at every refresh.
gPCMachineExtensionNames changed: a new type of setting was added. {AADCED64-746C-4633-A97C-D61349046527} is scheduled tasks; {7150F9BF-48AD-4DA4-A49C-29EF4A8369BA} is files.

3. What was written into the GPO folders? This only returns data if your DCs, or the admin machine that edited the GPO, run MDE:

kql
let gpos = dynamic(["FEF166EC-DD2C-4398-AFB4-EDFD99828835", "3C8BADF5-6CCB-4A47-8FAF-12E3155464F8"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any (gpos)
| summarize Writes = count(), First = min(Timestamp), Last = max(Timestamp),
            Accounts = make_set(coalesce(RequestAccountName, InitiatingProcessAccountName), 5),
            Processes = make_set(InitiatingProcessFileName, 5), Devices = make_set(DeviceName, 5)
    by FileName, ActionType
| order by Last desc

How to read it:

gpt.ini rewritten over and over: confirms the GPO keeps being rewritten.
A file first seen around the 17th (ScheduledTasks.xml, Files.xml, a script or executable): that's the change itself, and Accounts shows who made it.
Rows from DFSRs.exe: just replication between DCs.

After these, run the file-breakdown query and the two MDE queries from my last message. They show which files clients are reading and which process on the clients is reading them.

Quick check in the query you already ran: add | where Target =~ "{31B2F340-016D-11D2-945F-00C04FB984F9}" right after the extend Target line. That's the Default Domain Policy, which every machine reads on every refresh. If its count is flat, clients aren't refreshing more often, and the problem is inside these two GPOs.

If none of the history queries return anything, you don't need DC access to get the GPO names. Any domain user can read them in GPMC, so your AD team can tell you in seconds.





What the two results show

The two GPOs belong to Tenable Identity Exposure (formerly Tenable.ad), its Indicators of Attack (IoA) module. The folders contain ScheduledTasks.xml, a Register-TenableA… file, and files that look like they're named after your DCs, which dfsrs.exe keeps replicating. That matches how Tenable IoA works: the GPO pushes a scheduled task to the DCs, and that task launches Register-TenableADEventsListener.exe from the GPO's \Machine\IOA\ folder in SYSVOL. Each DC then periodically writes the events it collects to its own file in SYSVOL, and DFS replicates that file to the other DCs.
Why two GPOs: the IoA install script is run once per AD domain, so you probably have one per domain (or an old and a new deployment).
The GPOs predate the spike. Their files first appear Aug 26 and the visible edits are Aug 27, three weeks before it started. Scroll to rows 9–16 of the 5136 result: if nothing there is dated around Sept 16–17, nobody edited the GPO when the spike began.

Bottom line: your clients and normal Group Policy processing aren't the cause. Tenable's IoA mechanism has been hitting SYSVOL on your DCs about 12× harder since the 17th. The steps below find what changed on the Tenable side that day.

Step 1: Who is hitting the Tenable folders, and which files?

kql
let spikeStart = datetime(2026-09-17 00:00);
let gpos = dynamic(["FEF166EC-DD2C-4398-AFB4-EDFD99828835", "3C8BADF5-6CCB-4A47-8FAF-12E3155464F8"]);
SecurityEvent
| where TimeGenerated between ((spikeStart - 7d) .. (spikeStart + 7d))
| where EventID == 5145 and RelativeTargetName has_any (gpos)
| extend File = extract(@"\}(.*)$", 1, RelativeTargetName)
| summarize Before = countif(TimeGenerated < spikeStart), After = countif(TimeGenerated >= spikeStart)
    by SubjectUserName, IpAddress, File
| extend Growth = After - Before
| top 20 by Growth desc

How to read the top rows:

Accounts ending in $, with your DCs' IPs: the Tenable listeners on the DCs are generating the traffic. Go to step 2.
The Tenable service account, from one or two IPs: Tenable's own platform is reading much more than before. Go to step 3, then to whoever owns Tenable.
The .exe or the .json config file at the top: something is being relaunched or re-read constantly.
The per-DC event files at the top: far more event data is being written and collected.

Step 2: Is the listener restarting over and over? Your DCs are onboarded to MDE (the dfsrs.exe rows in your file query came from them), so you can check directly:

kql
let gpos = dynamic(["FEF166EC-DD2C-4398-AFB4-EDFD99828835", "3C8BADF5-6CCB-4A47-8FAF-12E3155464F8"]);
DeviceProcessEvents
| where Timestamp > ago(21d)
| where FileName startswith "Register-TenableAD" or ProcessCommandLine has_any (gpos)
| summarize Launches = count(), DCs = dcount(DeviceId) by Day = bin(Timestamp, 1d), FileName
| extend PerDC = round(1.0 * Launches / DCs, 1)
| order by FileName asc, Day asc

Tenable says the listener should run only once per DC, so PerDC should stay roughly flat. If it jumps starting on the 17th, the listener is in a restart loop.

Tenable's troubleshooting guide lists EDR or antivirus blocking the listener as a known problem. One candidate that lines up with the date: the Defender Antivirus platform update 4.18.26080.4 was released on September 17. To see whether MDE has been acting on Tenable's files or processes:

kql
let gpos = dynamic(["FEF166EC-DD2C-4398-AFB4-EDFD99828835", "3C8BADF5-6CCB-4A47-8FAF-12E3155464F8"]);
DeviceEvents
| where Timestamp > datetime(2026-09-14)
| where ActionType matches regex "^(Antivirus|Asr|AppControl|ExploitGuard|Tampering)"
| extend Blob = strcat(FileName, " ", FolderPath, " ", InitiatingProcessCommandLine, " ", ProcessCommandLine)
| where Blob contains "Tenable" or Blob has_any (gpos)
| summarize Events = count(), DCs = dcount(DeviceId), First = min(Timestamp) by ActionType, FileName
| order by First asc

Step 3: Did Tenable's config, version or audit settings change around the 17th?

kql
let gpos = dynamic(["FEF166EC-DD2C-4398-AFB4-EDFD99828835", "3C8BADF5-6CCB-4A47-8FAF-12E3155464F8"]);
DeviceFileEvents
| where Timestamp between (datetime(2026-09-14) .. datetime(2026-09-19))
| where FolderPath has_any (gpos)
| where FileName has_any (".json", ".exe", ".ps1", ".xml", ".csv", ".inf")
| summarize Events = count(), Who = make_set(coalesce(RequestAccountName, InitiatingProcessAccountName), 5),
            Processes = make_set(InitiatingProcessFileName, 5)
    by Day = bin(Timestamp, 1d), FileName, ActionType
| order by Day asc

What changes to look for:

TenableADEventsListenerConfiguration.json changed: the set of collected events changed. Tenable can enable or disable IoAs from its console without redeploying the GPO, so someone may have switched more on.
New .exe or .ps1 files: Tenable was upgraded.
audit.csv or GptTmpl.inf changed: this GPO also sets your DCs' audit and security policy. Ask the Tenable owner whether it's what turned on Detailed File Share auditing in the first place.

Then: take the results of steps 1–3 to whoever owns Tenable. They point to the fix: an EDR exclusion for the listener, reverting the IoA config change, or a Tenable support case. If it turns out to be expected volume, drop 5145 events for these two GPO paths with a DCR transformation so you stop paying to ingest Tenable's own traffic.






What's causing it

Since September 16, every domain controller has been reading the Tenable Identity Exposure IoA GPO folders in its own SYSVOL about 5 times per second, per path, nonstop. That accounts for the whole spike: roughly 25+ events per second per DC, across 22 DCs, is the ~300M extra events a week.

It started the same day the Tenable IoA listener was relaunched on all 22 DCs. It's not clients, not Tenable's platform account, not RC4, and MDE isn't interfering.

The evidence from your screenshots

Who is reading: every top row is a DC's own computer account (ALPDUDCSP002$, ALPPRGADS1VP$, ALPAWSADS2VP$, ALPOLTADS8VP$ and so on). Most come from ::1, which means the DC is reading its own SYSVOL. None of the top rows are svc_tenablead or workstations.
When it started: with Sep 16 as the cutoff, those DCs had zero reads of these paths the week before, apart from normal Group Policy touching ScheduledTasks.xml about 90 times a week. The week after, they had about 3 million reads per path. The earlier "×12" understated this because Sep 16 fell into the "before" week.
What it looks like: \MACHINE, \USER, Preferences\Groups, ScheduledTasks.xml and GptTmpl.inf all have the same count. Something is walking the entire GPO folder tree in a loop. Normal Group Policy processing doesn't do that, and it would hit the Default Domain Controllers Policy just as hard, which isn't among your top growers.
The trigger: Register-TenableADEventsListener.exe was launched on 22 DCs on Sep 16, compared with 3 on Sep 9. Tenable runs this listener from the IOA folder inside that same GPO in SYSVOL, and it's meant to run only once per DC. Two days earlier, on Sep 14, svc_tenablead wrote a TenableADEventsListener… file into that GPO folder. It's most likely the listener's configuration file, which Tenable's service account has write access to.
What's ruled out:
There are no AV, ASR or AppControl events against the listener. The hits in Image 1 are Nessus agents and the Tenable relay, which are unrelated to this. The ASR LSASS event on Tenable.Relay.exe is worth a separate look, though.
The Semperis processes in Image 4 are its Forest Recovery agent taking its usual ~24-a-day GPO backups, which were already running before the 16th.

One query to confirm it per DC

kql
let gpos = dynamic(["FEF166EC-DD2C-4398-AFB4-EDFD99828835", "3C8BADF5-6CCB-4A47-8FAF-12E3155464F8"]);
let t1 = datetime(2026-09-15); let t2 = datetime(2026-09-18);
let flood = SecurityEvent
    | where TimeGenerated between (t1 .. t2)
    | where EventID == 5145 and RelativeTargetName has_any (gpos)
    | summarize Events = count() by DC = toupper(trim_end(@"\$", SubjectUserName)), Slot = bin(TimeGenerated, 5m)
    | where Events > 500
    | summarize FloodStart = min(Slot) by DC;
let listener = DeviceProcessEvents
    | where Timestamp between (t1 .. t2) and FileName startswith "Register-TenableAD"
    | summarize ListenerStart = min(Timestamp) by DC = toupper(tostring(split(DeviceName, ".")[0]));
let boots = SecurityEvent
    | where TimeGenerated between (t1 .. t2) and EventID == 4608
    | summarize BootedAt = min(TimeGenerated) by DC = toupper(tostring(split(Computer, ".")[0]));
flood
| join kind=leftouter listener on DC
| join kind=leftouter boots on DC
| project DC, BootedAt, ListenerStart, FloodStart
| order by FloodStart asc

How to read it:

ListenerStart and FloodStart within minutes of each other on every DC: the listener restart started the loop.
BootedAt at the same time as well: the DCs rebooted, probably for patching. The listener is still the prime suspect, but Tenable needs to know it misbehaves after that reboot or update.

Who does what

Tenable team (the owner): find out what changed on Sep 14–16 (config push, IoA enablement, listener version), and why the listener's GPO folder is being rescanned about 5 times a second on every DC. They should open a case with Tenable using this data.
AD team (proof on the box): on one DC, stop the TenableADTask_* listener for 10 minutes, or run Process Monitor filtered on the GPO path. If that DC's 5145 rate drops to near zero, it's proven. You can watch the rate from your side with this:
kql
SecurityEvent
| where TimeGenerated > ago(2h) and EventID == 5145
| where RelativeTargetName has_any ("FEF166EC-DD2C-4398-AFB4-EDFD99828835", "3C8BADF5-6CCB-4A47-8FAF-12E3155464F8")
| where SubjectUserName =~ "ALPDUDCSP002$"   // the DC being tested
| summarize count() by bin(TimeGenerated, 1m)
| render timechart
You: once it's proven, drop 5145 events for those two GPO paths with a DCR transformation until Tenable ships a fix.




Timing check: when did each DC start flooding, and did it reboot? This one uses Sentinel data only.

kql
let gpos = dynamic(["FEF166EC-DD2C-4398-AFB4-EDFD99828835", "3C8BADF5-6CCB-4A47-8FAF-12E3155464F8"]);
let flood = SecurityEvent
    | where TimeGenerated between (datetime(2026-09-15) .. datetime(2026-09-18))
    | where EventID == 5145 and RelativeTargetName has_any (gpos)
    | summarize Events = count() by DC = toupper(SubjectUserName), Slot = bin(TimeGenerated, 15m)
    | where Events > 1000
    | summarize FloodStart = min(Slot) by DC;
let boots = SecurityEvent
    | where TimeGenerated between (datetime(2026-09-15) .. datetime(2026-09-18)) and EventID == 4608
    | summarize BootedAt = min(TimeGenerated) by DC = strcat(toupper(tostring(split(Computer, ".")[0])), "$");
flood
| join kind=leftouter boots on DC
| project DC, BootedAt, FloodStart
| order by FloodStart asc

Then, in Defender data only, find when the Tenable listener started on each DC and what launched it:

kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-09-15) .. datetime(2026-09-18))
| where FileName startswith "Register-TenableAD"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc

How to read them together:

Listener start and FloodStart within about 15 minutes of each other on each DC: the restart kicked off the flood.
A BootedAt at the same time: the DCs were rebooted, for example for patching.
No BootedAt: the restart came from a Tenable redeploy or a task restart, not a reboot.

2. Which GPOs are affected. Sep 16 is the split point.

kql
let spike = datetime(2026-09-16);
SecurityEvent
| where TimeGenerated between (datetime(2026-09-09) .. datetime(2026-09-23))
| where EventID == 5145 and ShareName endswith "SYSVOL"
| extend Gpo = toupper(extract(@"\{([0-9A-Fa-f\-]{36})\}", 1, RelativeTargetName))
| where isnotempty(Gpo)
| summarize BeforePerDay = round(countif(TimeGenerated < spike) / 7.0),
            AfterPerDay  = round(countif(TimeGenerated >= spike) / 7.0),
            ReadersAfter = dcountif(SubjectUserName, TimeGenerated >= spike)
    by Gpo
| extend Increase = AfterPerDay - BeforePerDay
| top 10 by Increase desc

ReadersAfter is the number of distinct accounts reading each GPO. Normal GPOs are read by thousands of computers. The two Tenable GPOs should show only about 22 readers, your DCs.

3. Proof that these two GPOs are Tenable's. This uses Defender data. It shows Tenable's listener program running from inside each GPO folder, and the Tenable files stored there.

kql
let gpos = dynamic(["FEF166EC-DD2C-4398-AFB4-EDFD99828835", "3C8BADF5-6CCB-4A47-8FAF-12E3155464F8"]);
union
    (DeviceProcessEvents
     | where Timestamp > ago(30d) and FolderPath has_any (gpos)
     | extend Evidence = "Program running from inside the GPO folder"),
    (DeviceFileEvents
     | where Timestamp > ago(30d) and FolderPath has_any (gpos) and FileName contains "Tenable"
     | extend Evidence = "Tenable file stored in the GPO folder")
| extend Gpo = toupper(extract(@"\{([0-9A-Fa-f\-]{36})\}", 1, FolderPath))
| summarize Devices = dcount(DeviceId), First = min(Timestamp), Last = max(Timestamp),
            SamplePath = take_any(FolderPath)
    by Gpo, Evidence, FileName
| order by Gpo asc, Evidence asc

You should see Register-TenableADEventsListener.exe and TenableADEventsListener… files under both GUIDs, on your DCs.

What happened, in plain terms

Aug 26–27, Tenable was deployed. Whoever runs Tenable Identity Exposure installed its "Indicators of Attack" module. That created these two GPOs, probably one per domain, linked to your Domain Controllers. Each GPO puts a scheduled task on every DC. The task starts Tenable's listener program directly from the GPO's folder in SYSVOL. The listener collects security events on each DC and writes them into a file in that same folder, where Tenable picks them up.
Sep 14, Tenable changed something. Tenable's service account (svc_tenablead) wrote a new listener file into that folder, most likely a new configuration or an update pushed from the Tenable side.
Sep 16, the listener restarted on all 22 DCs. From then on, every DC has been re-reading the Tenable GPO folder in its own SYSVOL about 5 times per second, nonstop.
Why it shows up in Sentinel: your DCs audit every file-share access. Each of those reads becomes event 5145, and the Azure Monitor Agent ships them all to Sentinel. That's hundreds of millions of extra events a week.
Why it loops: the logs can't show the internal reason. The likely explanation is that the new listener version or configuration rescans its folder whenever the folder changes. That folder changes constantly, because every DC keeps writing its event file into it. Only Tenable can confirm this.

Who's not responsible: your clients, attackers, RC4, MDE, and Semperis, which is only taking its normal daily backups.

Also ask Tenable: the Tenable GPO carries audit settings of its own (audit.csv), so ask whether it's also what turned on file-share auditing on your DCs in the first place.









The two Tenable IoA GPO folders in SYSVOL, including everything under them:

\\<yourdomain>\SYSVOL\<yourdomain>\Policies\{FEF166EC-DD2C-4398-AFB4-EDFD99828835}\
\\<yourdomain>\SYSVOL\<yourdomain>\Policies\{3C8BADF5-6CCB-4A47-8FAF-12E3155464F8}\

In a 5145 event, that means ShareName is \\*\SYSVOL and RelativeTargetName contains one of those two GUIDs. It covers every subpath you saw: \MACHINE, \USER, Preferences\Groups, ScheduledTasks.xml, GptTmpl.inf and so on.

Only drop the flood itself: reads by DC computer accounts (names ending in $). Keep anything else that touches those folders, such as svc_tenablead or any user account. Someone other than a DC modifying the Tenable GPO is exactly what you'd still want to see.

1. Preview what the filter would remove (run in Sentinel first):

kql
SecurityEvent
| where TimeGenerated > ago(1d) and EventID == 5145
| extend Drop = SubjectUserName endswith "$"
    and RelativeTargetName has_any ("FEF166EC-DD2C-4398-AFB4-EDFD99828835", "3C8BADF5-6CCB-4A47-8FAF-12E3155464F8")
| summarize Events = count() by Drop

2. The transformation. Add this to the DCR that collects Security events from your DCs:

kql
source
| where EventID != 5145
    or SubjectUserName !endswith '$'
    or (RelativeTargetName !contains 'FEF166EC-DD2C-4398-AFB4-EDFD99828835'
        and RelativeTargetName !contains '3C8BADF5-6CCB-4A47-8FAF-12E3155464F8')

It keeps every row except 5145 events from DC computer accounts on those two GUIDs.

How to add it

Where it goes: transformations sit in the transformKql property of the DCR's dataFlows section, on the Microsoft-SecurityEvent stream.
How to edit it: GET the DCR JSON through the REST API, add the property, and PUT it back with api-version 2022-06-01.
Formatting: in the JSON, the query must be on a single line:
json
"transformKql": "source | where EventID != 5145 or SubjectUserName !endswith '$' or (RelativeTargetName !contains 'FEF166EC-DD2C-4398-AFB4-EDFD99828835' and RelativeTargetName !contains '3C8BADF5-6CCB-4A47-8FAF-12E3155464F8')"
If the dataFlow already has a transformKql: add this as an extra | where rather than replacing it.
Cost: you won't pay a data-processing charge for filtering. That charge applies only in workspaces without Sentinel.
Nothing else changes: this only affects what lands in Sentinel. The DCs' local Security logs and Tenable's listener are untouched.

A day after deploying, re-run the preview query. The Drop = true count should be close to zero, while the rest of your 5145 events keep flowing.


1. Defender for Identity (best chance). It logs GPO changes together with the GPO's name. The edits you saw on Aug 27 are just inside its 30-day window, so run this today, before they age out:

kql
let gpos = dynamic(["FEF166EC-DD2C-4398-AFB4-EDFD99828835", "3C8BADF5-6CCB-4A47-8FAF-12E3155464F8"]);
IdentityDirectoryEvents
| where Timestamp > ago(30d)
| where ActionType startswith "Group Policy"
| where tostring(AdditionalFields) has_any (gpos)
| extend Info = parse_json(AdditionalFields)
| summarize LastSeen = max(Timestamp)
    by GroupPolicyName = tostring(Info.GroupPolicyName), GroupPolicyId = tostring(Info.GroupPolicyId), ActionType

If you also stream IdentityDirectoryEvents into Sentinel, you can raise ago(30d) to match your workspace retention.

2. DC security logs in Sentinel (full retention). The name is written into AD when a GPO is created or renamed, and that shows up as a 5136 event on the displayName attribute. If that happened within your workspace retention, this finds it:

kql
let gpos = dynamic(["FEF166EC-DD2C-4398-AFB4-EDFD99828835", "3C8BADF5-6CCB-4A47-8FAF-12E3155464F8"]);
SecurityEvent
| where TimeGenerated > ago(365d)
| where EventID == 5136 and EventData has_any (gpos)
| extend Attribute = extract(@"Name=""AttributeLDAPDisplayName"">([^<]*)<", 1, EventData),
         GpoName   = extract(@"Name=""AttributeValue"">([^<]*)<", 1, EventData),
         Gpo       = toupper(extract(@"Name=""ObjectDN"">CN=\{([0-9A-Fa-f\-]{36})\}", 1, EventData))
| where Attribute == "displayName"
| project TimeGenerated, Gpo, GpoName, SubjectUserName

This also tells you who set the name, and when.

3. Long shot: the Exposure Management graph. It may hold GPOs if Defender for Identity feeds it. The query is quick, and if it returns nothing you've lost nothing:

kql
ExposureGraphNodes
| where tostring(NodeProperties) has_any ("FEF166EC-DD2C-4398-AFB4-EDFD99828835", "3C8BADF5-6CCB-4A47-8FAF-12E3155464F8")
| project NodeLabel, NodeName

If all three come back empty, the GPOs were created and last renamed before your retention and haven't been edited in the last 30 days. In that case the AD team's one-minute lookup in Group Policy Management is the only way to get the names.


let daily = materialize(
    SecurityEvent
    | where TimeGenerated > ago(14d)
    | where EventID == 5145 and AccountType == "Machine" and ShareName == @"\\*\SYSVOL"
    | extend Gpo = coalesce(toupper(extract(@"\{([0-9A-Fa-f\-]{36})\}", 1, RelativeTargetName)), "(other SYSVOL paths)")
    | summarize Events = count() by Day = bin(TimeGenerated, 1d), Gpo);
let top10 = daily | summarize Total = sum(Events) by Gpo | top 10 by Total | project Gpo;
daily
| where Gpo in (top10)
| render timechart



Your 5145 events already hold the answer: each one records which account asked and from which IP. Both queries below run in Advanced Hunting.

1. The main check, run on the 5145 events themselves. It sorts every reader of the two Tenable GPO folders into domain controllers, other computers, or user accounts. The Azure Monitor Agent only runs on your DCs, so any machine sending SecurityEvent is a DC:

kql
let gpos = dynamic(["FEF166EC-DD2C-4398-AFB4-EDFD99828835", "3C8BADF5-6CCB-4A47-8FAF-12E3155464F8"]);
let dcAccounts = SecurityEvent
    | where TimeGenerated > ago(1h)
    | distinct Account = strcat(toupper(tostring(split(Computer, ".")[0])), "$");
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 5145 and RelativeTargetName has_any (gpos)
| extend Reader = toupper(SubjectUserName)
| extend ReaderType = case(Reader in (dcAccounts), "Domain controller",
                           Reader endswith "$", "Other computer (client/server)",
                           "User account")
| summarize Events = count(), Readers = dcount(Reader),
            FromLoopbackPct = round(100.0 * countif(IpAddress in ("::1", "127.0.0.1")) / count(), 1),
            SampleReaders = make_set(Reader, 10)
    by ReaderType

2. Cross-check using MDE data only. MDE keeps its own copy of these events (ActionType NetworkShareObjectAccessChecked). This query looks up each source IP and labels it as the same DC, another DC, or a non-DC device. It uses the machines running Tenable's listener as the list of DCs:

kql
let gpos = dynamic(["FEF166EC-DD2C-4398-AFB4-EDFD99828835", "3C8BADF5-6CCB-4A47-8FAF-12E3155464F8"]);
let dcs = DeviceProcessEvents
    | where Timestamp > ago(30d) and FileName startswith "Register-TenableAD"
    | distinct DeviceId;
let ipMap = DeviceNetworkInfo
    | where Timestamp > ago(1d)
    | mv-expand ip = parse_json(IPAddresses)
    | extend IP = tostring(ip.IPAddress)
    | summarize arg_max(Timestamp, DeviceId, DeviceName) by IP
    | join kind=leftouter (DeviceInfo | where Timestamp > ago(7d) | summarize arg_max(Timestamp, DeviceType) by DeviceId) on DeviceId
    | extend SourceRole = iff(DeviceId in (dcs), "Domain controller", strcat("Non-DC ", DeviceType))
    | project IP, SourceDevice = DeviceName, SourceRole;
DeviceEvents
| where Timestamp > ago(6h)
| where ActionType == "NetworkShareObjectAccessChecked"
| where tostring(AdditionalFields) has_any (gpos) or FolderPath has_any (gpos)
| extend IP = coalesce(RemoteIP, tostring(parse_json(AdditionalFields).IpAddress))
| lookup kind=leftouter ipMap on IP
| extend SourceRole = case(IP in ("::1", "127.0.0.1"), "Same DC (loopback)",
                           isempty(SourceRole), "Unknown (not in MDE)", SourceRole)
| summarize Events = count(), Sources = dcount(IP), SampleSources = make_set(coalesce(SourceDevice, IP), 10) by SourceRole
| order by Events desc

MDE may sample these events, so use this one to see who is reading, not to count how much.

How to read the results

Nearly 100% "Domain controller" or "Same DC (loopback)": the reads come from the DCs themselves, not from clients. That matches everything we've seen so far.
"Other computer", "User account" or "Non-DC" rows with real volume: clients are involved, and SampleReaders or SampleSources names them.
A few "Other computer" rows: before counting them as clients, check whether they're DCs without the Azure Monitor Agent.


Then MDE doesn't record that event in your tenant. It's in the schema, but not every listed event is actually collected. You don't need it, though. The DCs' own 5145 events in Sentinel are the authoritative record of who read what, and you can query them from Advanced Hunting.

The proof: list every reader of those folders that isn't a DC. No rows means no clients.

kql
let gpos = dynamic(["FEF166EC-DD2C-4398-AFB4-EDFD99828835", "3C8BADF5-6CCB-4A47-8FAF-12E3155464F8"]);
let dcAccounts = SecurityEvent
    | where TimeGenerated > ago(1h)
    | distinct Account = strcat(toupper(tostring(split(Computer, ".")[0])), "$");
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 5145 and RelativeTargetName has_any (gpos)
| where toupper(SubjectUserName) !in (dcAccounts)
| summarize Events = count() by SubjectUserName, IpAddress
| order by Events desc
Empty, or only a handful of events: every read comes from the DCs themselves, so clients aren't the cause.
Rows with real volume: those accounts and IPs are the clients involved. Check first whether any of them is a DC that simply doesn't run the Azure Monitor Agent.

Supporting check using MDE data only: did clients' file-share traffic to the DCs change on Sep 16? Port 445 is file sharing. This uses the machines running Tenable's listener as the DC list:

kql
let dcs = DeviceProcessEvents
    | where Timestamp > ago(30d) and FileName startswith "Register-TenableAD"
    | distinct DeviceId;
let dcIPs = DeviceNetworkInfo
    | where Timestamp > ago(7d) and DeviceId in (dcs)
    | mv-expand ip = parse_json(IPAddresses)
    | distinct IP = tostring(ip.IPAddress);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemotePort == 445 and RemoteIP in (dcIPs)
| where DeviceId !in (dcs)
| summarize Connections = count(), ClientDevices = dcount(DeviceId) by Day = bin(Timestamp, 1d)
| render timechart

A flat line across Sep 16 means client behavior toward the DCs didn't change while the events exploded. Treat this only as supporting evidence: one file-share connection can carry millions of reads. The account check above is the actual proof.
