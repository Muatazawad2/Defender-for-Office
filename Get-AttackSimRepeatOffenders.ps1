<#
.SYNOPSIS
    Attack Simulator Repeat Offenders - builds a repeat-offender list using a
    custom rule that the built-in Defender setting cannot express.

.DESCRIPTION
    THE PROBLEM THIS SOLVES
    -----------------------
    Microsoft Defender for Office 365 has a built-in "Repeat offender threshold"
    setting (Attack simulation training > Settings). Its definition is fixed:

        "A repeat offender is someone who gives up their credentials in
         multiple CONSECUTIVE simulations."

    You can change the number of simulations, but you cannot change:
      * the TRIGGER    - it only counts CREDENTIAL COMPROMISE, not link clicks
      * the SEQUENCE   - the simulations must be CONSECUTIVE
      * the WINDOW     - there is no rolling time period at all

    Many organisations define a repeat offender differently, for example:

        "Anyone who clicked a phishing link 2 or more times in the last
         12 months, whether or not those clicks were consecutive, and
         whether or not they went on to enter credentials."

    That definition cannot be produced in the portal. This script produces it
    from the Microsoft Graph attack simulation API, where the raw per-user
    events are available.

    WHY THE TWO DEFINITIONS DISAGREE
    --------------------------------
    A user can click a phishing link and then stop - they never type their
    password. Defender records the click but does not mark them compromised,
    so the built-in repeat-offender list ignores them completely. Yet that
    user demonstrably fell for the lure and is exactly who awareness training
    is meant to reach.

    This script counts CLICKS (EmailLinkClicked), so those users are caught.
    Section 5 prints the built-in result alongside, so the difference is
    visible every run.

    WHAT IT PRODUCES
    ----------------
    Three files, because they serve three different audiences:

      1. _SUMMARY.csv    One row per flagged user. Click counts, dates, click
                         rate, training completion. For review and reporting.

      2. _EVIDENCE.csv   One row per individual click, with timestamp to the
                         second, IP address, browser and device. This is the
                         answer to "I never clicked that" disputes.

      3. _TARGETLIST.csv Bare email addresses, one per line, no header.
                         This is the ONLY format the Defender portal "Import"
                         control accepts on the Target users page.

    File names encode the rule that produced them, so a file found months
    later still explains itself.

.PARAMETER Window
    Rolling look-back period. Accepts a number with an optional unit suffix:
        90d / 90 days      12m / 12 months
        6w  / 6 weeks      2y  / 2 years
    A bare number is treated as MONTHS (so "12" means 12 months).
    Case and spaces are ignored. Maximum look-back is 10 years.
    If omitted, the script prompts for it.

.PARAMETER ClickThreshold
    How many clicks qualify a user as a repeat offender. Range 1-50.
    If omitted, the script prompts for it (default 2).

.PARAMETER TenantId
    Entra tenant GUID. STRONGLY RECOMMENDED. Without it, the script will reuse
    whatever Graph session already exists, which on a machine signed into
    multiple tenants can silently query the wrong one.

.PARAMETER OutFolder
    Where to write the three CSV files. Defaults to the user's Downloads folder.

.PARAMETER IncludeExcludedSims
    By default, simulations marked "excluded from reporting" in the portal are
    skipped, because those are usually tests that should not affect real
    statistics. Use this switch to include them anyway.

.EXAMPLE
    .\Get-AttackSimRepeatOffenders.ps1
    Prompts for the window and threshold, then runs.

.EXAMPLE
    .\Get-AttackSimRepeatOffenders.ps1 -Window 12m -ClickThreshold 2 -TenantId <guid>
    Fully unattended - no prompts. Suitable for a scheduled task.

.EXAMPLE
    .\Get-AttackSimRepeatOffenders.ps1 -Window 90d
    Last 90 days; prompts only for the click threshold.

.NOTES
    Author      : Muataz Awad
    Role        : Cloud Solution Architect - Security, Microsoft
    Created     : September 2026

    REQUIREMENTS
      Licensing : Microsoft Defender for Office 365 Plan 2, or Microsoft 365 E5
      Module    : Microsoft.Graph.Authentication
                  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
      Graph     : AttackSimulation.Read.All (delegated)
                  This is an admin-consent permission. The first person to run
                  it in a tenant must be an admin, and should tick "Consent on
                  behalf of your organization" so that ordinary readers can run
                  it afterwards without needing an admin each time.
      Entra role: Any ONE of - Global Reader, Security Reader, Security Operator,
                  Security Administrator, Attack Simulation Administrator,
                  Global Administrator.
                  Global Reader or Security Reader is sufficient and is the
                  least-privilege choice: this script only reads.

    NOTE ON PERMISSIONS
      Consent and role do different jobs. Consent lets the app ASK Graph for
      the data. The Entra role decides HOW MUCH of it comes back. A user with
      consent but no role gets nothing, so consenting is not a backdoor.

    LIMITATIONS
      * There are no PowerShell cmdlets for Attack simulation training. Graph
        is the only programmatic route.
      * Defender XDR Unified RBAC does not currently apply to attack simulation
        training; the Entra roles above are what matter.
      * Simulation data is retained by the service; this script can only report
        on simulations still present in the tenant.
#>

[CmdletBinding()]
param(
    # Rolling look-back window. Accepts 90d / 6w / 12m / 2y. Bare number = months.
    [string] $Window,

    # Number of clicks that qualifies a user as a repeat offender.
    [int]    $ClickThreshold,

    # Entra tenant GUID. Strongly recommended - see .PARAMETER notes above.
    [string] $TenantId,

    # Destination folder for the three output CSV files.
    [string] $OutFolder = "$HOME\Downloads",

    # Include simulations that were marked "excluded from reporting" in the portal.
    [switch] $IncludeExcludedSims
)

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop


#region ----- HELPER: parse a human-friendly window string --------------------
<#
    Turns "90d", "6 weeks", "12m", "2y" or a bare "12" into:
        Cutoff : the DateTime to compare events against
        Label  : short form for file names, e.g. "12m"
        Words  : readable form for console output, e.g. "12 months"

    Returns $null for anything unparseable, which makes the caller re-prompt
    rather than silently defaulting to something the user did not intend.
#>
function ConvertFrom-WindowString {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    # Normalise: lower-case and strip all whitespace so "3 Months" == "3months"
    $t = $Text.Trim().ToLower() -replace '\s',''

    # One or more digits, then an optional unit. Unit spellings are generous
    # because this is typed by a human under time pressure.
    if ($t -notmatch '^(\d+)\s*(d|day|days|w|wk|week|weeks|m|mo|month|months|y|yr|year|years)?$') {
        return $null
    }

    $n    = [int]$Matches[1]
    $unit = if ($Matches[2]) { $Matches[2] } else { 'm' }   # bare number = months
    if ($n -lt 1) { return $null }                          # "0d" is meaningless

    $now = Get-Date
    switch -Regex ($unit) {
        '^(d|day|days)$'        { $cutoff = $now.AddDays(-$n);     $label = "${n}d"; $words = "$n day$(if($n -ne 1){'s'})" }
        '^(w|wk|week|weeks)$'   { $cutoff = $now.AddDays(-$n * 7); $label = "${n}w"; $words = "$n week$(if($n -ne 1){'s'})" }
        '^(m|mo|month|months)$' { $cutoff = $now.AddMonths(-$n);   $label = "${n}m"; $words = "$n month$(if($n -ne 1){'s'})" }
        '^(y|yr|year|years)$'   { $cutoff = $now.AddYears(-$n);    $label = "${n}y"; $words = "$n year$(if($n -ne 1){'s'})" }
    }

    # Sanity ceiling. Attack simulation history beyond a decade is not a real
    # scenario and usually means a typo such as "200y".
    if ($cutoff -lt $now.AddYears(-10)) { return $null }

    @{ Cutoff = $cutoff; Label = $label; Words = $words }
}
#endregion


#region ----- HELPER: follow Graph paging ------------------------------------
<#
    Graph returns large collections in pages with an @odata.nextLink pointing
    at the next one. A dev tenant may fit in a single page, but a real tenant
    with hundreds of simulations or thousands of targeted users will not.
    Failing to follow nextLink is the classic cause of a report that is
    quietly incomplete, so every collection call goes through here.
#>
function Get-AllPages {
    param([string]$Uri)

    $out = @()
    while ($Uri) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
        $out += $response.value
        $Uri = $response.'@odata.nextLink'   # $null when there are no more pages
    }
    $out
}
#endregion


#region ----- 1. Gather the rule (prompt only for what was not supplied) ------
# Prompting only for missing parameters keeps the script friendly when run by
# hand, while remaining fully unattended when both values are passed in - which
# is what a scheduled task needs.

$showBanner = $false
if (-not $PSBoundParameters.ContainsKey('Window') -or -not $PSBoundParameters.ContainsKey('ClickThreshold')) {
    $showBanner = $true
    Write-Host "`n=============================================================" -ForegroundColor Cyan
    Write-Host " Attack Simulator Repeat Offenders - define your rule"           -ForegroundColor Cyan
    Write-Host "=============================================================" -ForegroundColor Cyan
    # Restating both definitions on every run means anyone who inherits this
    # script understands what it does without reading the source.
    Write-Host " Built-in Defender rule : N CONSECUTIVE sims, CREDENTIALS SUPPLIED"      -ForegroundColor DarkGray
    Write-Host " This report            : N LINK CLICKS in a rolling window, any order" -ForegroundColor DarkGray
    Write-Host ""
}

# Keep asking until we get something parseable. An invalid window silently
# defaulting to 12 months would produce a wrong list that looks right.
$win = ConvertFrom-WindowString $Window
while (-not $win) {
    if ($Window) {
        Write-Host "  '$Window' isn't a valid window. Try 90d, 6w, 12m, 2y." -ForegroundColor DarkYellow
    }
    $Window = Read-Host "How far back? (e.g. 90d, 6w, 12m, 2y)  [default: 12m]"
    if ([string]::IsNullOrWhiteSpace($Window)) { $Window = '12m' }
    $win = ConvertFrom-WindowString $Window
}

# Same idea for the threshold. Enter accepts the default of 2, which matches
# the most common organisational definition.
while ($ClickThreshold -lt 1 -or $ClickThreshold -gt 50) {
    $raw = Read-Host "How many clicks qualify a user?  [default: 2]"
    if ([string]::IsNullOrWhiteSpace($raw)) { $ClickThreshold = 2; break }

    $parsed = 0
    if ([int]::TryParse($raw.Trim(), [ref]$parsed) -and $parsed -ge 1 -and $parsed -le 50) {
        $ClickThreshold = $parsed
    } else {
        Write-Host "  Enter a whole number 1-50, or press Enter for 2." -ForegroundColor DarkYellow
    }
}

if ($showBanner) {
    Write-Host "`n  Rule: $ClickThreshold or more clicks in the last $($win.Words)" -ForegroundColor Yellow
    Write-Host ""
}
#endregion


#region ----- 2. Connect to Microsoft Graph (safely) --------------------------
<#
    An existing Graph session is only reused if it is genuinely usable.

    Two failure modes this guards against:

      1. WRONG TENANT. On a machine signed into a corporate tenant and a lab
         tenant, a stale session means the script happily returns results from
         whichever one it happens to be connected to. The numbers look
         plausible and nobody notices. Passing -TenantId prevents this.

      2. MISSING SCOPE. A session may exist but lack AttackSimulation.Read.All,
         producing a confusing 403 deep into the run rather than a clear
         message up front.
#>
$requiredScope = 'AttackSimulation.Read.All'
$ctx = Get-MgContext
$needConnect = $false

if (-not $ctx) {
    $needConnect = $true
}
elseif ($TenantId -and $ctx.TenantId -ne $TenantId) {
    Write-Host "Connected to tenant $($ctx.TenantId) but $TenantId was requested - reconnecting." -ForegroundColor Yellow
    $needConnect = $true
}
elseif ($ctx.Scopes -notcontains $requiredScope) {
    Write-Host "Current session lacks $requiredScope - reconnecting." -ForegroundColor Yellow
    $needConnect = $true
}

if ($needConnect) {
    if ($ctx) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null }

    $connectParams = @{ Scopes = $requiredScope; NoWelcome = $true }
    if ($TenantId) { $connectParams.TenantId = $TenantId }

    Connect-MgGraph @connectParams -ErrorAction Stop
    $ctx = Get-MgContext
}

if (-not $ctx) { throw "Not connected to Microsoft Graph." }

# Consent can be declined at the sign-in prompt, in which case we are connected
# but without the permission. Fail here with an actionable message rather than
# letting the first API call return an opaque error.
if ($ctx.Scopes -notcontains $requiredScope) {
    throw "Connected as $($ctx.Account) but consent for $requiredScope was not granted. A Global Administrator or Security Administrator may need to approve it."
}

Write-Host "Connected: $($ctx.Account)  |  Tenant: $($ctx.TenantId)" -ForegroundColor Green
if (-not $TenantId) {
    Write-Host "  (tip: pass -TenantId <guid> to guarantee you are querying the intended tenant)" -ForegroundColor DarkGray
}
#endregion


#region ----- 3. Read every simulation and every per-user event ---------------
Write-Host "`nReading simulations..." -ForegroundColor Cyan

try {
    $sims = Get-AllPages 'https://graph.microsoft.com/v1.0/security/attackSimulation/simulations'
}
catch {
    # Translate the two most common HTTP failures into something actionable.
    $statusCode = $_.Exception.Response.StatusCode.value__
    switch ($statusCode) {
        403 { throw "Access denied (403). The signed-in account needs an Attack Simulation role (Global Reader, Security Reader, Security Administrator, or Attack Simulation Administrator) and the tenant needs Defender for Office 365 Plan 2 / M365 E5." }
        401 { throw "Unauthorized (401). Token was rejected - run Disconnect-MgGraph and try again." }
        default { throw "Failed to read simulations: $($_.Exception.Message)" }
    }
}

if (-not $sims) {
    Write-Host "  No simulations found in this tenant. Nothing to report." -ForegroundColor DarkYellow
    return
}

# Simulations marked "excluded from reporting" in the portal are normally test
# runs. Including them would inflate click counts with admin self-tests, so
# they are dropped unless the caller explicitly asks for them.
if (-not $IncludeExcludedSims) {
    $excludedCount = @($sims | Where-Object status -eq 'excluded').Count
    $sims = $sims | Where-Object status -ne 'excluded'
    if ($excludedCount) {
        Write-Host "  (skipping $excludedCount simulation(s) excluded from reporting)" -ForegroundColor DarkGray
    }
}
Write-Host "  $($sims.Count) simulation(s) in scope"

<#
    Flatten everything into one list of events.

    Graph nests the data three levels deep:
        simulation -> simulationUsers -> simulationEvents

    A flat table is far easier to filter, group and export, and it lets the
    same collected data answer several different questions later without
    re-querying the API.

    Event names seen in practice:
        SuccessfullyDeliveredEmail          simulation arrived
        MessageRead                         user opened it
        EmailLinkClicked                    user clicked the link   <-- our trigger
        CredSupplied                        user entered credentials <-- built-in trigger
        TrainingAssignmentMessageDelivered  training was assigned
#>
$events = New-Object System.Collections.Generic.List[object]

foreach ($sim in $sims) {
    Write-Host ("  - {0,-32} {1}" -f $sim.displayName, ([datetime]$sim.launchDateTime).ToString('yyyy-MM-dd'))

    $simUsers = Get-AllPages "https://graph.microsoft.com/v1.0/security/attackSimulation/simulations/$($sim.id)/report/simulationUsers"

    foreach ($user in $simUsers) {
        # Training data is held once per user per simulation, not per event,
        # so collapse it here and carry it onto each of that user's events.
        $trainingNames  = (@($user.trainingEvents) | ForEach-Object { $_.displayName }) -join '; '
        $trainingStates = (@($user.trainingEvents) | ForEach-Object { $_.latestTrainingStatus } | Select-Object -Unique) -join '; '

        foreach ($event in @($user.simulationEvents)) {
            $events.Add([PSCustomObject]@{
                # --- which simulation ---
                Simulation        = $sim.displayName
                SimulationId      = $sim.id
                Technique         = $sim.attackTechnique      # credentialHarvesting, driveByUrl, etc.
                DeliveryPlatform  = $sim.payloadDeliveryPlatform
                SimLaunched       = [datetime]$sim.launchDateTime

                # --- who ---
                User              = $user.simulationUser.email
                DisplayName       = $user.simulationUser.displayName
                UserId            = $user.simulationUser.userId

                # --- what they did, and from where ---
                # IP / browser / device are the corroborating detail that
                # answers "I never clicked that" challenges.
                EventName         = $event.eventName
                EventTime         = [datetime]$event.eventDateTime
                IpAddress         = $event.ipAddress
                Browser           = $event.browser
                Device            = $event.osPlatformDeviceDetails

                # --- outcome for this user in this simulation ---
                IsCompromised     = $user.isCompromised       # true only if credentials were supplied
                CompromisedAt     = $user.compromisedDateTime
                ReportedPhishAt   = $user.reportedPhishDateTime  # populated if they reported it

                # --- training follow-through ---
                TrainingsAssigned = $user.assignedTrainingsCount
                TrainingsComplete = $user.completedTrainingsCount
                TrainingsInProg   = $user.inProgressTrainingsCount
                TrainingModules   = $trainingNames
                TrainingStatus    = $trainingStates
            })
        }
    }
}
Write-Host "  $($events.Count) user event(s) collected"
#endregion


#region ----- 4. Apply the custom rule ----------------------------------------
Write-Host "`nRule: $ClickThreshold+ clicks since $($win.Cutoff.ToString('yyyy-MM-dd')) (last $($win.Words))" -ForegroundColor Cyan

# The rule in one line: link clicks inside the rolling window.
# Note this deliberately does NOT require consecutive simulations, and does NOT
# require credentials to have been supplied. That is the whole point.
$clicksInWindow = $events | Where-Object {
    $_.EventName -eq 'EmailLinkClicked' -and $_.EventTime -ge $win.Cutoff
}

$offenders = $clicksInWindow |
    Group-Object User |
    Where-Object { $_.Count -ge $ClickThreshold } |
    ForEach-Object {

        $userClicks = $_.Group | Sort-Object EventTime
        $email      = $_.Name

        # All events for this user - not just clicks, and not just inside the
        # window - so we can report context such as how many simulations they
        # were ever targeted by.
        $allUserEvents = $events | Where-Object User -eq $email
        $simsTargeted  = @($allUserEvents | Select-Object -ExpandProperty Simulation -Unique).Count

        # Training figures are summed across the simulations they clicked in.
        $assigned = ($userClicks | Measure-Object TrainingsAssigned -Sum).Sum
        $complete = ($userClicks | Measure-Object TrainingsComplete -Sum).Sum

        [PSCustomObject]@{
            User               = $email
            DisplayName        = $userClicks[0].DisplayName

            # --- the core finding ---
            ClickCount         = $_.Count
            FirstClick         = $userClicks[0].EventTime.ToString('yyyy-MM-dd HH:mm')
            LastClick          = $userClicks[-1].EventTime.ToString('yyyy-MM-dd HH:mm')
            DaysSinceLastClick = [int][math]::Round(((Get-Date) - $userClicks[-1].EventTime).TotalDays)

            # --- severity context ---
            # Clicking is one thing; entering credentials is worse. Someone who
            # also REPORTS phishing is a different case again - they are
            # engaged, just occasionally caught out.
            EverCompromised    = [bool]($userClicks | Where-Object IsCompromised)
            CredsSuppliedCount = @($allUserEvents | Where-Object EventName -eq 'CredSupplied').Count
            TimesReportedPhish = @($allUserEvents | Where-Object { $_.ReportedPhishAt }).Count

            # --- proportion matters ---
            # 2 clicks out of 3 simulations is a very different risk profile
            # from 2 clicks out of 40.
            SimsTargeted       = $simsTargeted
            ClickRatePct       = if ($simsTargeted) { [math]::Round(100 * $_.Count / $simsTargeted) } else { 0 }

            # --- is there a pattern? e.g. always falls for QR codes ---
            Techniques         = (($userClicks.Technique | Select-Object -Unique) -join '; ')

            # --- did they act on previous training? ---
            TrainingAssigned    = $assigned
            TrainingCompleted   = $complete
            TrainingOutstanding = [math]::Max(0, $assigned - $complete)

            # --- corroborating detail ---
            DistinctIPs        = (($userClicks.IpAddress | Where-Object { $_ } | Select-Object -Unique) -join '; ')
            Devices            = (($userClicks.Device    | Where-Object { $_ } | Select-Object -Unique) -join '; ')
            Browsers           = (($userClicks.Browser   | Where-Object { $_ } | Select-Object -Unique) -join '; ')
            Simulations        = (($userClicks.Simulation | Select-Object -Unique) -join '; ')
        }
    } |
    # Worst offenders first; among equals, those ignoring their training first.
    Sort-Object ClickCount, TrainingOutstanding -Descending
#endregion


#region ----- 5. Write the three output files ---------------------------------
Write-Host "`n================= REPEAT OFFENDERS =================" -ForegroundColor Yellow

if ($offenders) {

    $offenders | Format-Table User, ClickCount, LastClick, DaysSinceLastClick, EverCompromised, TrainingOutstanding -AutoSize

    # File names carry the rule and the run date. Six months from now, a file
    # named ..._2clicks-12m_2026-09-09_... still explains exactly who was
    # flagged, by what rule, and when - which matters when a user disputes it.
    $stamp = Get-Date -Format 'yyyy-MM-dd'
    $rule  = "{0}clicks-{1}" -f $ClickThreshold, $win.Label
    $base  = Join-Path $OutFolder "AttackSimRepeatOffenders_${rule}_${stamp}"

    $summaryFile  = "${base}_SUMMARY.csv"
    $evidenceFile = "${base}_EVIDENCE.csv"
    $targetFile   = "${base}_TARGETLIST.csv"

    # --- 1. SUMMARY: one row per flagged user, for review and reporting ---
    $offenders | Export-Csv -Path $summaryFile -NoTypeInformation -Encoding UTF8

    # --- 2. EVIDENCE: one row per individual click ---
    # Timestamp to the second plus IP, browser and device. Defender does not
    # record what a user typed into a simulated login page, so this
    # who/when/where detail is the strongest available evidence.
    $offenderEmails = $offenders.User
    $evidence = $events |
        Where-Object { $_.User -in $offenderEmails -and $_.EventTime -ge $win.Cutoff } |
        Sort-Object User, EventTime |
        Select-Object User, DisplayName, EventName,
            @{ n = 'EventTime';   e = { $_.EventTime.ToString('yyyy-MM-dd HH:mm:ss') } },
            IpAddress, Browser, Device,
            Simulation, Technique, DeliveryPlatform,
            @{ n = 'SimLaunched'; e = { $_.SimLaunched.ToString('yyyy-MM-dd') } },
            IsCompromised, TrainingModules, TrainingStatus,
            TrainingsAssigned, TrainingsComplete

    $evidence | Export-Csv -Path $evidenceFile -NoTypeInformation -Encoding UTF8

    # --- 3. TARGETLIST: the upload file ---
    # The Defender portal's Import control expects ONE EMAIL ADDRESS PER LINE.
    # No header row, no quotes, no byte-order mark. A normal Export-Csv file is
    # rejected with "Unable to retrieve email-addresses from uploaded file",
    # which is why this is written with WriteAllLines and a BOM-less encoder.
    [IO.File]::WriteAllLines($targetFile, $offenders.User, (New-Object Text.UTF8Encoding($false)))

    Write-Host "$($offenders.Count) user(s) matched  |  $($evidence.Count) supporting event(s)" -ForegroundColor Green
    Write-Host "  SUMMARY    (one row per user)      : $summaryFile"  -ForegroundColor Green
    Write-Host "  EVIDENCE   (per-event audit trail) : $evidenceFile" -ForegroundColor Green
    Write-Host "  TARGETLIST (upload to portal)      : $targetFile"   -ForegroundColor Yellow
    Write-Host "`nEmail addresses:" -ForegroundColor Cyan
    $offenders.User | ForEach-Object { "  $_" }
}
else {
    Write-Host "No users met the threshold in this window." -ForegroundColor DarkYellow
    Write-Host "  Try a longer window (e.g. -Window 24m) or a lower -ClickThreshold." -ForegroundColor DarkGray
}
#endregion


#region ----- 6. Show what the built-in setting would have returned -----------
<#
    Printed every run so the difference between the two definitions is visible
    rather than asserted. In most tenants this list is shorter than the one
    above - often empty - because it only counts users who actually surrendered
    credentials, and only in consecutive simulations.

    Note this is an approximation of the built-in rule: it counts total
    credential compromises rather than strictly consecutive ones, so if
    anything it OVERSTATES what the built-in feature would flag. The real
    built-in list is therefore the same length or shorter.
#>
$builtInEquivalent = $events |
    Where-Object EventName -eq 'CredSupplied' |
    Group-Object User |
    Where-Object { $_.Count -ge $ClickThreshold }

Write-Host "`n--- For comparison, built-in basis (credential compromise) ---" -ForegroundColor DarkGray
if ($builtInEquivalent) {
    $builtInEquivalent | ForEach-Object { Write-Host "  $($_.Name) : $($_.Count) compromise(s)" }
} else {
    Write-Host "  No user compromised in $ClickThreshold+ simulations - built-in list would be empty."
}
#endregion
