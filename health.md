# Sentinel health assessment — query pack

Companion to `sentinel-health-assessment-template.pptx`. Every query is keyed to the slide it fills.

Run order: **slide 13 first** (is health monitoring even on?), then 7 → 8 → 9 → 10 → 11 → 12, then fill slides 4, 5, 6, 14.

Record the run timestamp (UTC) for each query — it is the evidence column on every findings slide.

| Marker | Meaning |
|---|---|
| ✅ | Query taken verbatim from current Microsoft documentation |
| ⚠️ | Adapted — sanity-check the columns against your workspace before quoting the numbers |

---

## Slide 2 — Scope and as-of

**Portal**: Azure portal → Log Analytics workspaces → *ws* → Overview (ID, region, RG) · Usage and estimated costs (tier, daily cap) · Tables (default retention). Defender portal → System → Settings → Microsoft Sentinel (portal and onboarding state).

⚠️ Workspace inventory — Azure Resource Graph Explorer:

```kusto
Resources
| where type =~ 'microsoft.operationalinsights/workspaces'
| project name, location, resourceGroup, subscriptionId,
          sku = tostring(properties.sku.name),
          retentionInDays = toint(properties.retentionInDays)
| order by name asc
```

```bash
az monitor log-analytics workspace show -g <rg> -n <ws> -o jsonc
```

---

## Slide 7 — Platform and service health

**Portal**: LA workspace → Resource health (30-day history; the only check Azure runs is *are there ingestion delays*) · Azure portal → [Service Health](https://portal.azure.com/#view/Microsoft_Azure_Health/AzureHealthBrowseBlade/~/serviceIssues) (tick **both** Tenant and Subscription scope; 90-day retention) · Service Health → Health alerts · workspace → Metrics.

**Metrics to chart**: `AvailabilityRate_Query`, `Ingestion Time` (split by Table Name), `Ingestion Volume`, `Query failure count`, `Export Failures`.

**Resource health status meanings**: Available = average latency, no query issues · Unavailable = higher-than-average latency · Degraded = query failures · Unknown = no recent data or queries.

✅ All active Service Health events — *Azure Resource Graph Explorer*:

```kusto
ServiceHealthResources
| where type =~ 'Microsoft.ResourceHealth/events'
| extend eventType = properties.EventType, status = properties.Status, description = properties.Title,
         trackingId = properties.TrackingId, impactStartTime = properties.ImpactStartTime,
         impactMitigationTime = properties.ImpactMitigationTime
| where (eventType in ('HealthAdvisory','SecurityAdvisory','PlannedMaintenance') and impactMitigationTime > now())
     or (eventType == 'ServiceIssue' and status == 'Active')
```

✅ Upcoming retirements — *ARG*:

```kusto
ServiceHealthResources
| where type =~ 'Microsoft.ResourceHealth/events'
| extend eventType = properties.EventType, eventSubType = properties.EventSubType
| where eventType == "HealthAdvisory" and eventSubType == "Retirement"
| extend status = properties.Status, description = properties.Title,
         impactStartTime = todatetime(tolong(properties.ImpactStartTime)),
         impactMitigationTime = todatetime(tolong(properties.ImpactMitigationTime))
| where impactMitigationTime > now()
| project subscriptionId, status, description, impactStartTime, impactMitigationTime
```

✅ Confirmed impacted resources — *ARG*:

```kusto
ServiceHealthResources
| where type == "microsoft.resourcehealth/events/impactedresources"
| extend TrackingId = split(split(id, "/events/", 1)[0], "/impactedResources", 0)[0]
| extend p = parse_json(properties)
| project subscriptionId, TrackingId, resourceName = p.resourceName, resourceGroup = p.resourceGroup,
          resourceType = p.targetResourceType, id
```

> No Service Health alert rules = amber at minimum, even when nothing is broken. Deploy at scale with the built-in policy *Configure subscriptions to enable Service Health Monitoring Alert Rules*.

---

## Slide 8 — Data ingestion health

**Portal**: Content hub → install *Data collection health monitoring* → Workbooks → Templates (tabs: Overview / Data collection anomalies / Agent info) · Defender → Microsoft Sentinel → Configuration → **Tables → Table insights** (last data received, volume anomaly, est. daily cost) · Monitor → Workbooks → *AMA Health* · each DCR → Metrics and Diagnostic settings.

> **Coverage limit to state out loud**: `SentinelHealth` covers only AWS (CloudTrail and S3), Dynamics 365, Office 365, Defender for Endpoint, Threat Intelligence TAXII, Threat Intelligence Platforms, and Codeless Connector Framework connectors. Everything else must be checked by volume (Q3).

✅ Q1 — latest failure per connector:

```kusto
SentinelHealth
| where TimeGenerated > ago(3d)
| where OperationName == 'Data fetch status change'
| where Status in ('Success', 'Failure')
| summarize TimeGenerated = arg_max(TimeGenerated,*) by SentinelResourceName, SentinelResourceId
| where Status == 'Failure'
```

✅ Q2 — connectors that flipped success → failure in the last 12 h (also the best alert-rule condition):

```kusto
let latestStatus = SentinelHealth
| where TimeGenerated > ago(12h)
| where OperationName == 'Data fetch status change'
| where Status in ('Success', 'Failure')
| project TimeGenerated, SentinelResourceName, SentinelResourceId, LastStatus = Status
| summarize TimeGenerated = arg_max(TimeGenerated,*) by SentinelResourceName, SentinelResourceId;
let nextTolatestStatus = SentinelHealth
| where TimeGenerated > ago(12h)
| where OperationName == 'Data fetch status change'
| where Status in ('Success', 'Failure')
| join kind = leftanti (latestStatus) on SentinelResourceName, SentinelResourceId, TimeGenerated
| project TimeGenerated, SentinelResourceName, SentinelResourceId, NextToLastStatus = Status
| summarize TimeGenerated = arg_max(TimeGenerated,*) by SentinelResourceName, SentinelResourceId;
latestStatus
| join kind=inner (nextTolatestStatus) on SentinelResourceName, SentinelResourceId
| where NextToLastStatus == 'Success' and LastStatus == 'Failure'
```

⚠️ Q3 — tables gone quiet or dropping:

```kusto
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize LastData = max(EndTime),
            Last24hMB = sumif(Quantity, TimeGenerated > ago(1d)),
            Prev7dAvgMB = sumif(Quantity, TimeGenerated between (ago(8d) .. ago(1d))) / 7
  by DataType
| order by LastData asc
```

✅ Q4 — end-to-end vs agent latency:

```kusto
Heartbeat
| where TimeGenerated > ago(8h)
| extend E2EIngestionLatency = ingestion_time() - TimeGenerated
| extend AgentLatency = _TimeReceived - TimeGenerated
| summarize percentiles(E2EIngestionLatency,50,95), percentiles(AgentLatency,50,95) by Computer
| top 20 by percentile_E2EIngestionLatency_95 desc
```

✅ Q5 — machines that stopped reporting:

```kusto
Heartbeat
| where TimeGenerated > ago(1d)
| summarize NoHeartbeatPeriod = now() - max(TimeGenerated) by Computer
| top 20 by NoHeartbeatPeriod desc
```

✅ Q6 — daily cap and ingestion rate limit:

```kusto
_LogOperation | where TimeGenerated >= ago(7d) | where Category == "Ingestion" | where Detail has "Data collection"
```
```kusto
_LogOperation | where TimeGenerated >= ago(7d) | where Category == "Ingestion" | where Operation has "Ingestion rate"
```

✅ Q7 — DCR pipeline errors (needs a diagnostic setting per DCR, category **Log Errors**):

```kusto
DCRLogErrors | where TimeGenerated > ago(7d) | summarize count() by _ResourceId, InputStreamId
```

DCR metrics to chart: `Logs Rows Dropped per Min`, `Logs Transformation Errors per Min`, `Logs Ingestion Requests per Min` (service limit 12,000/min per DCR).

---

## Slide 9 — Detection health

**Portal**: Content hub → *Analytics Health & Audit* workbook (Overview / Health / Audit) · Analytics → select rule → **Insights** tab · Analytics → **Rule runs (Preview)** to replay failed windows up to 7 days back · Threat management → MITRE ATT&CK · SOC optimization.

> **Retry behaviour**: a failed scheduled rule is retried 5 more times on the *same* window, so one failure only means delay. Only 6/6 failures = a genuinely skipped window. NRT rules instead carry the failed window into the next run, for up to 60 failures (one hour).

✅ Q1 — failures grouped by reason:

```kusto
_SentinelHealth()
| where SentinelResourceType =~ "Analytics Rule"
| summarize Occurrence = count(), Unique_rule = dcount(SentinelResourceId) by Status, Reason
```

✅ Q2 — auto-disabled rules:

```kusto
_SentinelHealth()
| where SentinelResourceType =~ "Analytics Rule"
| where Reason == "The analytics rule is disabled and was not executed."
```

✅ Q3 — skipped windows (the real detection gaps):

```kusto
_SentinelHealth()
| where SentinelResourceType =~ "Analytics Rule"
| where SentinelResourceKind == "Scheduled"
| where Status != "Success"
| extend startTime = tostring(ExtendedProperties["QueryStartTimeUTC"])
| summarize failuresByStartTime = count() by startTime, SentinelResourceId
| where failuresByStartTime == 6
| summarize count() by SentinelResourceId
```

✅ Q4 — scheduled rule execution delay:

```kusto
_SentinelHealth()
| where SentinelResourceType =~ "Analytics Rule"
| where SentinelResourceKind == "Scheduled"
| extend startTime = todatetime(ExtendedProperties["QueryStartTimeUTC"]),
         executionStart = todatetime(ExtendedProperties["executionStart"])
| extend delay = datetime_diff('minute', startTime, executionStart)
```

✅ Q5 — NRT delay over time:

```kusto
_SentinelHealth()
| where SentinelResourceKind == "NRT"
| extend startTime = todatetime(ExtendedProperties["QueryStartTimeUTC"]),
         endTime = todatetime(ExtendedProperties["QueryEndTimeUTC"]),
         alertsCreated = toint(ExtendedProperties["AlertsGeneratedAmount"])
| where alertsCreated == 0
| extend ruleDelay = datetime_diff('minute', endTime, startTime)
| project TimeGenerated, ruleDelay, SentinelResourceId
| render timechart
```

⚠️ Q6 — rules that never alert:

```kusto
_SentinelHealth()
| where TimeGenerated > ago(30d)
| where SentinelResourceType =~ "Analytics Rule"
| where Status == "Success"
| extend Alerts = toint(ExtendedProperties["AlertsGeneratedAmount"])
| summarize Runs = count(), Alerts = sum(Alerts) by SentinelResourceName
| where Alerts == 0
```

**SOC optimization coverage grade** (quote this rather than your own opinion): High = over 75% of recommended rules active · Medium = 30–74% · Low = under 30%.

---

## Slide 10 — Automation and response

**Portal**: Workbooks → Templates → *Automation health* · Azure portal → **API connections** (anything not *Connected*) · each playbook → Diagnostic settings → send to the Sentinel workspace.

⚠️ Q1 — automation rules not fully succeeding (statuses: Success / Partial success / Failure):

```kusto
SentinelHealth
| where OperationName == "Automation rule run"
| where Status != "Success"
| summarize count() by SentinelResourceName, Status, Description
```

⚠️ Q2 — playbook trigger failures:

```kusto
SentinelHealth
| where OperationName == "Playbook was triggered"
| where Status == "Failure"
| summarize count() by SentinelResourceName, Description
```

✅ Q3 — the complete picture (trigger health joined to the actual Logic Apps run result):

```kusto
SentinelHealth
| where SentinelResourceType == "Automation rule"
| mv-expand TriggeredPlaybooks = ExtendedProperties.TriggeredPlaybooks
| extend runId = tostring(TriggeredPlaybooks.RunId)
| join (AzureDiagnostics
    | where OperationName == "Microsoft.Logic/workflows/workflowRunCompleted"
    | project resource_runId_s, playbookName = resource_workflowName_s, playbookRunStatus = status_s)
    on $left.runId == $right.resource_runId_s
| project RecordId, TimeGenerated, AutomationRuleName = SentinelResourceName,
          AutomationRuleStatus = Status, Description, workflowRunId = runId,
          playbookName, playbookRunStatus
```

> **Trap**: *Success* on a playbook trigger means only that it was launched. What the playbook did lives in `AzureDiagnostics`. No Logic Apps diagnostics = amber even when every trigger succeeds.

**Documented failure causes** in the Description column: playbook disabled · Sentinel missing permission to run it · playbook not migrated to the new permissions model · subscription or RG locked · Logic Apps IP access-control restriction · invalid credentials in a connection · managed identity missing a role assignment · throttling / too many waiting runs.

---

## Slide 11 — SOC performance

**Portal**: Workbooks → Templates → *Security operations efficiency* (incidents over time; by classification, severity, owner, status; MTTT; MTTC; percentiles; MTTT per owner).

> Every incident update writes a **new row**. De-duplicate before counting anything.

✅ De-duplication pattern:

```kusto
SecurityIncident
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
```

✅ Q1 — closure time by percentile:

```kusto
SecurityIncident
| summarize arg_max(TimeGenerated,*) by IncidentNumber
| extend TimeToClosure = (ClosedTime - CreatedTime)/1h
| summarize 5th_Percentile=percentile(TimeToClosure, 5), 50th_Percentile=percentile(TimeToClosure, 50),
            90th_Percentile=percentile(TimeToClosure, 90), 99th_Percentile=percentile(TimeToClosure, 99)
```

✅ Q2 — triage time by percentile:

```kusto
SecurityIncident
| summarize arg_max(TimeGenerated,*) by IncidentNumber
| extend TimeToTriage = (FirstModifiedTime - CreatedTime)/1h
| summarize 5th_Percentile=max_of(percentile(TimeToTriage, 5),0), 50th_Percentile=percentile(TimeToTriage, 50),
            90th_Percentile=percentile(TimeToTriage, 90), 99th_Percentile=percentile(TimeToTriage, 99)
```

✅ Q3 — state of the queue:

```kusto
let startTime = ago(14d);
let endTime = now();
SecurityIncident
| where TimeGenerated >= startTime
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where LastModifiedTime between (startTime .. endTime)
| where Status in ('New', 'Active', 'Closed')
| where Severity in ('High','Medium','Low', 'Informational')
```

---

## Slide 12 — Cost, retention and data tiers

**Portal**: Workbooks → Templates → *Workspace Usage Report* · workspace → Usage and estimated costs (tier, daily cap, reset hour) · Cost Management + Billing → Cost analysis → filter **Service name** = *Sentinel*, *Log Analytics*, *Azure Monitor* · Defender → Microsoft Sentinel → **Cost management** (data lake meters) · Defender → Configuration → Tables.

✅ Q1 — billable volume by table, 31 days:

```kusto
Usage
| where TimeGenerated > ago(32d)
| where StartTime >= startofday(ago(31d)) and EndTime < startofday(now())
| where IsBillable == true
| summarize BillableDataGB = sum(Quantity) / 1000. by bin(StartTime, 1d), DataType
| render columnchart
```

✅ Q2 — by solution, Sentinel share made explicit:

```kusto
Usage
| where StartTime >= startofday(ago(31d)) and EndTime < startofday(now())
| where IsBillable == true
| summarize BillableDataGB = sum(Quantity) / 1000. by bin(StartTime, 1d), Solution
| extend Solution = iff(Solution == "SecurityInsights", "AzureSentinel", Solution)
| render columnchart
```

✅ Q3 — by table plan (Analytics / Basic / Auxiliary). The `Plan` column was added to `Usage` in mid-May 2026; earlier rows are blank:

```kusto
Usage
| where TimeGenerated > ago(32d)
| where StartTime >= startofday(ago(31d)) and EndTime < startofday(now())
| where IsBillable == true
| summarize BillableDataGB = sum(Quantity) / 1000. by bin(StartTime, 1d), Plan
| render columnchart
```

✅ Q4 — volume between daily-cap resets (set the reset hour from the Daily Cap page):

```kusto
let DailyCapResetHour = 14;
Usage
| where TimeGenerated > ago(32d)
| extend StartTime = datetime_add("hour", -1*DailyCapResetHour, StartTime)
| where StartTime > startofday(ago(31d))
| where IsBillable
| summarize IngestedGbBetweenDailyCapResets = sum(Quantity)/1000. by day = bin(StartTime, 1d)
| render areachart
```

Retention per table:

```bash
az monitor log-analytics workspace table show -g <rg> --workspace-name <ws> --name <table>
```
```powershell
Get-AzOperationalInsightsTable -ResourceGroupName <rg> -WorkspaceName <ws> -TableName <table>
```

**Data lake cost management roles**: Security Reader to view usage and limits; Billing Administrator or Security Administrator to set limits and alerts. Threshold enforcement is not real time — up to **4 hours** to take effect, after which queries and jobs fail with *Limit exceeded*.

> **Never present a tier move as a pure cost saving.** Moving a table from Analytics to the Data Lake tier stops alerting, advanced hunting, analytics rules and custom detection rules from working on it.

---

## Slide 13 — Governance and access

**Run this first.** If health monitoring is off, slides 8–10 are empty and must be scored grey, not green.

✅ Verify the feature is on:

```kusto
_SentinelHealth() | take 20
```
```kusto
_SentinelAudit() | take 20
```

Turn on at: Defender portal → System → Settings → Microsoft Sentinel → **Auditing and health monitoring** → Enable (or *Configure diagnostic settings* → allLogs → send to the Sentinel workspace).

- `SentinelHealth` is **not** billable. `SentinelAudit` **is** billable.
- Health covers analytics rules, data connectors, automation rules and playbooks. **Auditing currently supports only the analytics rule resource type.**

✅ Q1 — rule deletions:

```kusto
_SentinelAudit()
| where SentinelResourceType == "Analytic Rule"
| where Description == "Analytics rule deleted"
```

✅ Q2 — who is changing rules:

```kusto
_SentinelAudit()
| where SentinelResourceType == "Analytic Rule"
| extend Caller = tostring(ExtendedProperties.CallerName)
| summarize Count = count() by Caller, Activity = Description
```

✅ Q3 — activity per rule:

```kusto
_SentinelAudit()
| where SentinelResourceType == "Analytic Rule"
| summarize Count = count() by RuleName = SentinelResourceName, Activity = Description
```

⚠️ Q4 — query audit (requires the Audit diagnostic setting on the workspace):

```kusto
LAQueryLogs
| where TimeGenerated > ago(7d)
| summarize Queries = count(), AvgMs = avg(ResponseDurationMs) by AADEmail, ResponseCode
```

**Deadline for the roadmap**: after **31 March 2027**, Microsoft Sentinel is no longer supported in the Azure portal — Defender portal only.

---

## Slide 15 — Monitoring to stand up

| Alert | Condition |
|---|---|
| Workspace errors | `_LogOperation \| where Level == "Error"` — 5 min period, 5 min frequency, threshold 0 |
| Workspace warnings | `_LogOperation \| where Level == "Warning"` — 1440 min period and frequency, threshold 0 |
| Daily cap reached | `_LogOperation \| where Category =~ "Ingestion" \| where Detail contains "OverQuota"` — Table rows, threshold 0, every 5 min |
| Volume anomaly | `Usage \| where IsBillable \| summarize DataGB = sum(Quantity / 1000)` — measure DataGB, Total, 1-day granularity, threshold to taste |
| Connector drift | Azure Monitor alert rule, scope = the Sentinel workspace, **Custom log search**, using slide 8 Q2 |
| DCR errors | Log query alert on `DCRLogErrors`, Table rows, threshold 1 |
| Rows dropped | Metric alert with a **dynamic** threshold on `Logs Rows Dropped per Min` |

Each log search alert rule is billed. Say so before someone finds it on the invoice.

**Operating cadence** (from the Microsoft Sentinel operational guide):

- **Daily** — triage incidents; review connector health; verify agent connectivity; check playbook failures; review and enable new analytics rules
- **Weekly** — content hub updates; review Sentinel audit activity
- **Monthly** — user access review; confirm retention still matches organisational policy
- **Quarterly** — re-run this assessment as the next milestone and compare against the baseline

---

## Source documentation

| Topic | Link |
|---|---|
| Deployment guide + post-deployment checklist | https://learn.microsoft.com/azure/sentinel/deploy-overview |
| Operational guide (daily/weekly/monthly) | https://learn.microsoft.com/azure/sentinel/ops-guide |
| Auditing and health monitoring | https://learn.microsoft.com/azure/sentinel/health-audit |
| Turn on health and audit | https://learn.microsoft.com/azure/sentinel/enable-monitoring |
| Data connector health | https://learn.microsoft.com/azure/sentinel/monitor-data-connector-health |
| Analytics rule health and integrity | https://learn.microsoft.com/azure/sentinel/monitor-analytics-rule-integrity |
| Rule execution insights and rerun | https://learn.microsoft.com/azure/sentinel/monitor-optimize-analytics-rule-execution |
| Automation health | https://learn.microsoft.com/azure/sentinel/monitor-automation-health |
| Incident metrics | https://learn.microsoft.com/azure/sentinel/manage-soc-with-incident-metrics |
| Cost monitoring | https://learn.microsoft.com/azure/sentinel/billing-monitor-costs |
| Table tiers and retention | https://learn.microsoft.com/azure/sentinel/manage-table-tiers-retention |
| SOC optimization | https://learn.microsoft.com/azure/sentinel/soc-optimization/soc-optimization-access |
| Sentinel in the Defender portal | https://learn.microsoft.com/azure/sentinel/microsoft-sentinel-defender-portal |
| LA workspace health | https://learn.microsoft.com/azure/azure-monitor/logs/log-analytics-workspace-health |
| Workspace operational issues (`_LogOperation`) | https://learn.microsoft.com/azure/azure-monitor/logs/monitor-workspace |
| Ingestion latency | https://learn.microsoft.com/azure/azure-monitor/logs/data-ingestion-time |
| Analyze usage | https://learn.microsoft.com/azure/azure-monitor/logs/analyze-usage |
| Daily cap | https://learn.microsoft.com/azure/azure-monitor/logs/daily-cap |
| DCR collection monitoring | https://learn.microsoft.com/azure/azure-monitor/data-collection/data-collection-monitor |
| AMA health workbook | https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-health |
| Service Health portal | https://learn.microsoft.com/azure/service-health/service-health-portal-update |
| Service Health ARG samples | https://learn.microsoft.com/azure/service-health/resource-graph-samples |
| Service Health alerts at scale | https://learn.microsoft.com/azure/service-health/service-health-alert-deploy-policy |
| Well-Architected Review (milestones, CSV export) | https://learn.microsoft.com/azure/well-architected/design-guides/implementing-recommendations |
