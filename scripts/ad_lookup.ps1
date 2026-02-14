# scripts/ad_lookup.ps1
# PowerShell script for Active Directory user and group lookups.
# Demonstrates AD administration tasks relevant for a Platform Engineer.
#
# Used for managing users, groups, and troubleshooting
# authentication issues in the on-prem AD environment.
#
# Usage:
#   .\scripts\ad_lookup.ps1 -Action LookupUser -Identity "daniel.parker"
#   .\scripts\ad_lookup.ps1 -Action LookupGroup -Identity "IT-Admins"
#   .\scripts\ad_lookup.ps1 -Action CheckLockout -Identity "daniel.parker"
#   .\scripts\ad_lookup.ps1 -Action ListExpiredPasswords -Days 30

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("LookupUser", "LookupGroup", "CheckLockout", "ListExpiredPasswords")]
    [string]$Action,
    [Parameter(Mandatory=$false)]
    [string]$Identity,
    [Parameter(Mandatory=$false)]
    [int]$Days = 30
)

function Get-ADUserDetails {
    param([string]$Username)
    Write-Host "AD User Lookup: $Username" -ForegroundColor Cyan
    try {
        $user = Get-ADUser -Identity $Username -Properties DisplayName, EmailAddress, Enabled, LockedOut, LastLogonDate, PasswordLastSet, PasswordExpired, MemberOf
        Write-Host "Name:             $($user.DisplayName)"
        Write-Host "Email:            $($user.EmailAddress)"
        Write-Host "Enabled:          $($user.Enabled)"
        Write-Host "Locked Out:       $($user.LockedOut)"
        Write-Host "Last Logon:       $($user.LastLogonDate)"
        Write-Host "Password Expired: $($user.PasswordExpired)"
        foreach ($group in $user.MemberOf) {
            $gn = ($group -split ",")[0] -replace "CN=", ""
            Write-Host "  Group: $gn"
        }
    } catch { Write-Host "Error: $_" -ForegroundColor Red }
}

function Get-ADGroupDetails {
    param([string]$GroupName)
    Write-Host "AD Group Lookup: $GroupName" -ForegroundColor Cyan
    try {
        $group = Get-ADGroup -Identity $GroupName -Properties Description
        $members = Get-ADGroupMember -Identity $GroupName
        Write-Host "Group: $($group.Name)"
        Write-Host "Scope: $($group.GroupScope)"
        Write-Host "Members: $($members.Count)"
        foreach ($m in $members) { Write-Host "  - $($m.Name)" }
    } catch { Write-Host "Error: $_" -ForegroundColor Red }
}

function Test-AccountLockout {
    param([string]$Username)
    Write-Host "Lockout Check: $Username" -ForegroundColor Cyan
    try {
        $user = Get-ADUser -Identity $Username -Properties LockedOut, LockoutTime, BadLogonCount, Enabled
        Write-Host "Locked Out:      $($user.LockedOut)"
        Write-Host "Bad Logon Count: $($user.BadLogonCount)"
        Write-Host "Enabled:         $($user.Enabled)"
        if ($user.LockedOut) {
            Write-Host "Account is LOCKED. Run: Unlock-ADAccount -Identity $Username" -ForegroundColor Red
        }
    } catch { Write-Host "Error: $_" -ForegroundColor Red }
}

function Get-ExpiredPasswords {
    param([int]$DaysThreshold)
    Write-Host "Users with passwords older than $DaysThreshold days" -ForegroundColor Cyan
    try {
        $cutoff = (Get-Date).AddDays(-$DaysThreshold)
        $users = Get-ADUser -Filter { Enabled -eq $true -and PasswordLastSet -lt $cutoff } -Properties DisplayName, PasswordLastSet | Sort-Object PasswordLastSet
        foreach ($u in $users) {
            $age = ((Get-Date) - $u.PasswordLastSet).Days
            Write-Host "  $($u.DisplayName) - $age days old"
        }
    } catch { Write-Host "Error: $_" -ForegroundColor Red }
}

switch ($Action) {
    "LookupUser"          { Get-ADUserDetails -Username $Identity }
    "LookupGroup"         { Get-ADGroupDetails -GroupName $Identity }
    "CheckLockout"        { Test-AccountLockout -Username $Identity }
    "ListExpiredPasswords" { Get-ExpiredPasswords -DaysThreshold $Days }
}
