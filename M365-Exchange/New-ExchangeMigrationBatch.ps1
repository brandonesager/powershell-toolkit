<#
.SYNOPSIS
    Creates Exchange Online migration batches with automatic license assignment.

.DESCRIPTION
    Interactive script for creating Exchange on-premises to Exchange Online migration
    batches. Automatically assigns specified Microsoft 365 licenses to users before
    initiating migration. Migration batches are configured to auto-start and auto-complete.

    Must be run from the Exchange Online PowerShell shell.

.NOTES
    Version : 1.0
    Date    : 2020-02-16

    Requires:
    - PowerShell 5.1+
    - MSOnline module
    - Exchange Online PowerShell module
    - Exchange Online admin permissions
    Category: M365-Exchange
.KEYWORDS
    Exchange, mailbox, migration, provision
#>

## START REQUIRED CONFIGURATION ##
$sTargetDeliveryDomain = "contoso.mail.onmicrosoft.com" 				# your tenant domain goes here
$sNotifyEmailAddresses = "admin@contoso.com" 							# email to send migration notifications to
$sLicensesToAssign = "contoso:ATP_ENTERPRISE","contoso:ENTERPRISEPACK"	# O365 licenses to assign each user before migration
																		# You can use O365-Get-LicenseUsage-Report.ps1 to get these values
$sUsageLocation = "US"													# Usage location for assigning licenses (required)
## END REQUIRED CONFIGURATION ##

## START OPTIONAL CONFIGURATION ##
# Shouldn't need to change these limits, but go ahead. They refer to limits on migrating items in the mailbox.
$sBadItemLimit = "100"
$sLargeItemLimit = "100"
## END OPTIONAL CONFIGURATION ##

Write-Output('** NOTE: Make sure you are running from the Exchange Online Powershell Module shell')

# These will be populated below. We're just initializing them here.
$sUserIDs=""
$sBatchName=""

# Get batch name and mailboxes from user input
# Load VB assembly for InputBox
Write-Output ("{0}: Waiting for user input...")
[void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
$sTitle = 'Input mailboxes to migrate'
$sMsg = 'Please enter comma-separated user IDs to migrate up to Exchange Online: '
$sUserIDs = [Microsoft.VisualBasic.Interaction]::InputBox($sMsg, $sTitle)

# sanity check
If ( [string]::IsNullOrEmpty($sUserIDs) -Or [string]::IsNullOrWhitespace($sUserIDs) ) {
	Write-Output ("{0}: ERROR - No user ID(s) given. Aborting.")
} Else {
	# TODO: Combine MFA-capable authentication so user doesn't get prompted twice
	# TODO: Migrate from MSOnline to Microsoft.Graph module
	# Connect to Azure AD using Microsoft Azure Active Directory Module for Windows PowerShell
	Write-Output ("{0}: Connecting to Azure AD...")
	Import-Module MSOnline
	try {
		Connect-MsolService
	}
	catch {
		Write-Output ("ERROR: Failed to connect to Azure AD: {0}" -f $_.Exception.Message)
		return
	}

	# Assign all 365 licenses to each user
	ForEach ($userID in $sUserIDs) {
		try {
			Write-Output ("{0}: Adding location and licenses to {1}..." -f $userID)
			Set-MsolUser -UserPrincipalName $userID -UsageLocation $sUsageLocation
			Set-MsolUserLicense -UserPrincipalName $userID -AddLicenses $sLicensesToAssign
		}
		catch {
			Write-Output ("ERROR: Failed to assign licenses to {0}: {1}" -f $userID, $_.Exception.Message)
		}
	}

	# Connect to Exchange Online using Microsoft Exchange Online Powershell Module
	Write-Output ("{0}: Connecting to Exchange Online...")
	try {
		Connect-EXOPSSession
	}
	catch {
		Write-Output ("ERROR: Failed to connect to Exchange Online: {0}" -f $_.Exception.Message)
		return
	}

	Write-Output ("{0}: Waiting for user input...")
	$sTitle = 'Input batch name'
	$sMsg = 'Please enter a name for this new batch: '
	$sBatchName = [Microsoft.VisualBasic.Interaction]::InputBox($sMsg, $sTitle)

	# sanity check
	If ( [string]::IsNullOrEmpty($sBatchName) -Or [string]::IsNullOrWhitespace($sBatchName) ) {
		Write-Output ("{0}: ERROR - No batch name given. Aborting.")
	} Else {
		# This migration batch will autostart and autocomplete.
		Write-Output ("{0}: Creating new migration batch named [{1}]..." -f $sBatchName)
		try {
			New-MigrationBatch -Name $sBatchName -UserIds $sUserIDs -AutoStart -AutoComplete -BadItemLimit $sBadItemLimit -LargeItemLimit $sLargeItemLimit -TargetDeliveryDomain $sTargetDeliveryDomain -NotificationEmails $sNotifyEmailAddresses
		}
		catch {
			Write-Output ("ERROR: Failed to create migration batch: {0}" -f $_.Exception.Message)
		}
	} # end if
} # end if

# Pause until a key is pressed
Write-Output ("Done. Press any key to continue...")
$HOST.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
$HOST.UI.RawUI.Flushinputbuffer()
