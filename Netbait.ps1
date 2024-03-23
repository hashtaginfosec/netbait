<#
.SYNOPSIS
Sends honeypot NBNS, LLMNR, and mDNS queries to entice Responder.

.DESCRIPTION
Based on https://www.youtube.com/watch?v=h_cWWL-yyb0 , this script will send out broadcast and multicast name resolution queries to entice Responder into revealing itself. 


.PARAMETER lookup
Name to lookup using NBNS, LLMNR, and mDNS. Default value is HRShare.
.PARAMETER sleep
Sleep this many milliseconds before sending another query. Default is 10,000 millseconds. 
.PARAMETER outFile
Default is false. If $true, outputs to netbait.log. 
.PARAMETER consoleOut
Default is True. Provides console output. 
.PARAMETER eventLog
Will write to event log. Before you can write to Windows Event Log, you need to create the Log facitlity by running the following command in PowerShell with elevated privileges: New-EventLog -Source "NetBait" -LogName NetBait.
.PARAMETER json
Would you like JSON output? Default=False. If $true, outputs to netbait.json.
.PARAMETER spewCreds
Will spill NetNTLM hashes. You can specify these creds via -username, -password, and -domain or use default ones. Default is false.
.PARAMETER domain
Specify domain name to spill if spewCreds is set to $true. Default is corp.
.PARAMETER username
Specify username to spill if spewCreds is set to $true. Default is deployer.
.PARAMETER password
Specify password to spill if spewCreds is set to $true. Default is long and hard to guess.


.EXAMPLE
Invoke-NetBait -lookup FS01 -sleep 10000 
Invoke-NetBait -lookup baitme -sleep 1000 -json $true -consoleOut $false -eventLog $true -outFile $true
Invoke-NetBait -lookup BISHOP -sleep 25000 -consoleOut $true -eventLog $true -outFile $true -spewCreds $true 
Invoke-NetBait -lookup BISHOP -sleep 25000 -consoleOut $true -eventLog $true -outFile $true -spewCreds $true -domain somedomain -username someuser -p "password1"

#>
function Invoke-NetBait {
    param (
        [Parameter()]
        [string]$lookup = "HRShare",
        [Parameter()]
        [string]$sleep = 10000,
        [Parameter()]
        [bool]$outFile = $false,
        [Parameter()]
        [bool]$consoleOut = $true,
        [Parameter()]
        [bool]$eventLog = $false,
        [Parameter()]
        [bool]$spewCreds = $false,
        [Parameter()]
        [bool]$json = $false,
        [Parameter()]
        [string]$domain,
        [Parameter()]
        [string]$username,
        [Parameter()]
        [string]$password
      
        
    )

    if ($outFile) {
        
        Write-Host "[+] File output will be written to netbait.log."
        "-----------------------------------------------------------"| Out-File netbait.log -Append
        "$(Get-Date) - Starting log file"| Out-File netbait.log -Append
        "-----------------------------------------------------------"| Out-File netbait.log -Append
        }
    if ($json) {
        Write-Host "[+] JSON output requested. See netbait.json."
    }
    if ($eventLog) {
        # Define the event source and log name
        $eventSource = "NetBait"
        $logName = "NetBait" 
        # Ensure the event source exists; create it if it does not
        if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
            Write-Host "[!] Event log NetBait does not exist. Create it in elevated PowerShell prompt by running: New-EventLog -Source "NetBait" -LogName NetBait"
        }
        else {
            Write-Host "[+] Will write detections to NetBait log in Windows Event Log."
        }
                
    }

    while ($true) {
        
        Write-Host "$(Get-Date) Sending a lookup for $lookup."
        $detection = Resolve-DnsName $lookup -ErrorVariable detectionError -ErrorAction SilentlyContinue
        if ($detectionError){
                if ($detectionError[0].ToString() -like "*DNS name does not exist*" -or $detectionError[0].ToString() -like "*This operation returned because the timeout period expired*"){
                    Write-Host "Nobody responded. "
                } else { Write-Host "[!] An error occurred."
                Write-Host $detectionError[0].ToString()
            }
            }


    foreach ($item in $detection){
        $response_ip = $item.Address -join ", "
        $response_host = $item.NameHost
        $response_lookup = $item.Name -join ","
        $message = "$response_ip hostname of $response_host responded to $response_lookup"
        
        if ($spewCreds) {
            if (-not $domain) {$domain = "corp"}
            if (-not $username) { $username = "deployer"}
            if (-not $password) { $password = "IDeployedTh33SoYouDeployedThisToolAndWeWentPhishingOnSaturday"}

            New-SmbMapping -RemotePath \\$lookup -UserName $domain\$username -Password $password -ErrorAction SilentlyContinue
            $message = $message + ". I spewed hashes for $domain\$username."
            
            }
        
        if ($outfile) {
            $FileOutput = "$(Get-Date) $message"
            $FileOutput | Out-File -FilePath netbait.log -Append
            }
        
        if ($consoleOut) { 
            Write-Host "$(Get-Date) $message"
            }
        

        if ($eventLog){

            $jsonLog = @{
                Timestamp = $(Get-Date).DateTime
                Responder_Host = $response_host
                Responder_IP = $response_ip
                Lookup_Name = $response_lookup
                Hashes_Spewed = $spewCreds
                Detailed_Message = $message

                }
            $jsonOut = $jsonLog | ConvertTo-Json
            Write-EventLog -LogName $logName -Source $eventSource -EventID 7331 -EntryType Warning -Message $jsonOut 
            if ($json) {
            
                #$jsonLog|ConvertTo-Json
                $jsonOut | Out-File netbait.json -Append
            
            }
        }  
        
        
        }
        Start-Sleep -Milliseconds $sleep

    }

}
