Yes, plenty of ChatGPT and coffee :) 
<img src="https://github.com/hashtaginfosec/netbait/assets/494424/5ddb4d72-94e4-4fd2-b249-cce69b6eab26" height=50% width=50%>

Based on https://www.youtube.com/watch?v=h_cWWL-yyb0 

**NOTE** If the host you're running this from has NBNS, LLMNR, and mDNS disabled, this tool won't work and you'll get `Resolve-DnsName : baitme : DNS name does not exist`. 
**HOWEVER** If nobody is running responder, you also get the same error (which is a good sign). This is something I need to work through. For now, `-ErrorAction SilentlyContinue` should help with this. 

Before you can write to Windows Event Log, you need to create the Log facitlity by running the following command in PowerShell with elevated privileges: 
`New-EventLog -Source "NetBait" -LogName NetBait` 

Then load this PowerShell module with `import-module .\NetBait.ps1`
And run with `Invoke-NetBait -lookup baitme -sleep 1000 -json $true -consoleOut $true -eventLog $true -outFile $true`

Now you'll see log enteries in Windows Event Viewer > Applications and Services Log\NetBait. You'll also see output to console and to a log file named netbait.log.

**PARAMETERS**
    
    -lookup <String>
        Name to lookup using NBNS, LLMNR, and mDNS. Default value is HRShare.

    -sleep <String>
        Sleep this many milliseconds before sending another query. Default is 10,000 millseconds.

    -outFile <Boolean>
        Default is false. If $true, outputs to netbait.log.

    -consoleOut <Boolean>
        Default is True. Provides console output.

    -eventLog <Boolean>
        Will write to event log. Before you can write to Windows Event Log, you need to create the Log facitlity by running the following command in
        PowerShell with elevated privileges: New-EventLog -Source "NetBait" -LogName NetBait.

    -spewCreds <Boolean>
        Will spill NetNTLM hashes for currently logged-on user. Use Carefuly. Default is false.

    -json <Boolean>
        Would you like JSON output? Default=False. If $true, outputs to netbait.json.
        

