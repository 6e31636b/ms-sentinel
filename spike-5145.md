
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
