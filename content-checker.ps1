param(
    [Parameter(Mandatory, Position=0)][string]$Keyword,
    [string]$Subscription  = "",
    [string]$ResourceGroup = "",
    [string]$Workspace     = "",
    [string]$OutCsv        = "$HOME/content-impact.csv"
)

$ErrorActionPreference = 'Continue'
if ($Subscription) { Set-AzContext -Subscription $Subscription | Out-Null }
$sub = (Get-AzContext).Subscription.Id

# --- resolve workspace -------------------------------------------------
if (-not $Workspace) {
    $all = Get-AzOperationalInsightsWorkspace
    if ($all.Count -eq 1) {
        $Workspace = $all[0].Name; $ResourceGroup = $all[0].ResourceGroupName
    } else {
        Write-Host "Pick one and re-run with -ResourceGroup / -Workspace:" -ForegroundColor Yellow
        $all | Select-Object Name, ResourceGroupName, Location | Format-Table -AutoSize
        return
    }
}
Write-Host "Sub: $sub`nWorkspace: $Workspace (rg: $ResourceGroup)`nKeyword: $Keyword`n" -ForegroundColor Cyan

$base = "/subscriptions/$sub/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$Workspace"
$rx   = [regex]::Escape($Keyword)
$hits = New-Object System.Collections.Generic.List[object]

function Get-Arm {
    param([string]$Path)
    $out = @()
    while ($Path) {
        $r = Invoke-AzRestMethod -Method GET -Path $Path
        if ($r.StatusCode -ne 200) { throw "HTTP $($r.StatusCode) - $($r.Content)" }
        $b = $r.Content | ConvertFrom-Json
        $out += $b.value
        $Path = if ($b.nextLink) { ([uri]$b.nextLink).PathAndQuery } else { $null }
    }
    ,$out
}

function Add-Hit {
    param($Obj, [string]$Type, [string]$Name, [string]$Detail = "")
    $json = $Obj | ConvertTo-Json -Depth 50 -Compress
    if ($json -match $rx) {
        $tbl = ([regex]::Matches($json, "$rx[A-Za-z0-9_]*_CL") |
                ForEach-Object { $_.Value } | Sort-Object -Unique) -join ', '
        $hits.Add([pscustomobject]@{ Type=$Type; Name=$Name; Detail=$Detail; Tables=$tbl })
    }
}

function Scan {
    param([string]$Label, [scriptblock]$Body)
    try   { $n = & $Body; Write-Host ("  {0,-22} scanned {1}" -f $Label, $n) }
    catch { Write-Host ("  {0,-22} FAILED: {1}" -f $Label, $_.Exception.Message) -ForegroundColor Red }
}

Write-Host "Scanning..." -ForegroundColor Cyan

Scan "analytics rules" {
    $i = Get-Arm "$base/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-09-01"
    $i | ForEach-Object { Add-Hit $_ "AnalyticsRule" $_.properties.displayName "$($_.kind) / enabled=$($_.properties.enabled)" }
    $i.Count
}

Scan "automation rules" {
    $i = Get-Arm "$base/providers/Microsoft.SecurityInsights/automationRules?api-version=2024-09-01"
    $i | ForEach-Object { Add-Hit $_ "AutomationRule" $_.properties.displayName "" }
    $i.Count
}

Scan "watchlists" {
    $i = Get-Arm "$base/providers/Microsoft.SecurityInsights/watchlists?api-version=2024-09-01"
    $i | ForEach-Object { Add-Hit $_ "Watchlist" $_.properties.displayName $_.properties.watchlistAlias }
    $i.Count
}

Scan "saved searches/funcs" {
    $i = Get-Arm "$base/savedSearches?api-version=2020-08-01"
    $i | ForEach-Object { Add-Hit $_ "SavedSearch" $_.properties.displayName "cat=$($_.properties.category) alias=$($_.properties.functionAlias)" }
    $i.Count
}

Scan "workbooks" {
    $w = Get-AzResource -ResourceType 'microsoft.insights/workbooks'
    foreach ($x in $w) {
        $full = Get-AzResource -ResourceId $x.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
        Add-Hit $full "Workbook" $full.Properties.displayName $x.ResourceGroupName
    }
    $w.Count
}

Scan "playbooks" {
    $l = Get-AzResource -ResourceType 'Microsoft.Logic/workflows'
    foreach ($x in $l) {
        $full = Get-AzResource -ResourceId $x.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
        Add-Hit $full "Playbook" $x.Name $x.ResourceGroupName
    }
    $l.Count
}

Scan "scheduled query rules" {
    $s = Get-AzResource -ResourceType 'Microsoft.Insights/scheduledQueryRules' -ExpandProperties
    $s | ForEach-Object { Add-Hit $_ "ScheduledQueryRule" $_.Name $_.ResourceGroupName }
    $s.Count
}

Scan "data collection rules" {
    $d = Get-AzResource -ResourceType 'Microsoft.Insights/dataCollectionRules' -ExpandProperties
    $d | ForEach-Object { Add-Hit $_ "DCR" $_.Name $_.ResourceGroupName }
    $d.Count
}

Write-Host "`nMatches: $($hits.Count)" -ForegroundColor $(if($hits.Count){'Green'}else{'Yellow'})
$hits | Sort-Object Type, Name | Format-Table -AutoSize
if ($hits.Count) { $hits | Export-Csv -NoTypeInformation $OutCsv; Write-Host "CSV: $OutCsv" }
