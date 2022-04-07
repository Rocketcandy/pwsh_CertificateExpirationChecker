Param(
    # Path to csv    
    [Parameter(Mandatory = $false,
        HelpMessage = "Enter the Path to the .csv you are using")]
    [String]$Path = "C:\Temp\check-urls.csv",
    # Warning Days
    [Parameter(Mandatory = $false,
        HelpMessage = "Enter the number of days before a certificate expires to be in warning status.")]
    [String]$WarningCertAgeDays = 60,
    # Critical Days
    [Parameter(Mandatory = $false,
        HelpMessage = "Enter the number of days before a certificate expires to be in critical status.")]
    [String]$CriticalCertAgeDays = 30,
    # To email addresses
    [Parameter(Mandatory = $false,
        HelpMessage = "Enter comma seperated list of email addresses to send to.")]
    [String]$To = 'IT@example.com',
    # Subject
    [Parameter(Mandatory = $false,
        HelpMessage = "Email subject")]
    [String]$Subject = "SSL Certificate Expiration Dates",
    # From
    [Parameter(Mandatory = $false,
        HelpMessage = "Who should the email be from")]
    [String]$From = "Powershell <PowerShell@example.com>",
    # SMTP Server
    [Parameter(Mandatory = $false,
        HelpMessage = "Enter SMTP address")]
    [String]$SMTPServer = "smtp.exmaple.com"
)
# Set TLS to use version 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Import CSV
$urls = Import-Csv -Path $Path

# Build the report
$Report = foreach ($url in $urls) {
    # Remove url protocal if one is specified and remove the last / and everything after
    $Site = (($url.URL).Replace("https://", "")).Split("/")[0]
    # Get Port number, default to 443 if not specified
    $Port = $Site.Split(":")[1]
    if ($Port -eq "" -or $null -eq $Port) { 
        $Port = 443
    }
    Else {
        # Get site without port if the port isn't 443
        $Site = $Site.Split(":")[0]
    }
    # Build the site request and get data
    try {
        $Req = [System.Net.Sockets.TcpClient]::new($Site, $Port)
        $Stream = [System.Net.Security.SslStream]::new($Req.GetStream(), $true, { $true }) # ignore SSL Errors
        $Stream.AuthenticateAsClient($Site)
        # Get Cert Details
        $CertDetails = $Stream.RemoteCertificate
        # Get Certificate Expiration Date
        $ExpirationDate = $CertDetails.GetExpirationDateString()
    }
    catch {
        # If there is a date hardcoded user that as the date and ignore the site result. Useful for VPN SSL certs where we can't check from inside the network.
        if ($url.ManualExpireDate -ne "") {
            $ExpirationDate = $url.ManualExpireDate
            $details = "Expiration date is hard coded into the spreadsheet make sure to update the spreadsheet when the certificate is updated."
        }
        else {
            $details = "Exception while checking URL $($url.URL)`: $_ "
        }
    }
    # Build info needed for email
    try {
        $ExpiresIn = (New-TimeSpan -Start $(Get-Date) -End $(Get-Date $ExpirationDate)).Days
        if ($ExpiresIn -gt $WarningCertAgeDays) {
            $CheckResult = "OKAY"
        }
        Else {
            if ($ExpiresIn -le $WarningCertAgeDays -and $ExpiresIn -gt $CriticalCertAgeDays) {
                $CheckResult = "WARNING"
            }
            if ($ExpiresIn -le $CriticalCertAgeDays) {
                $CheckResult = "CRITICAL"
            }
            if ($url.ManualExpireDate -eq "") {
                # Add more details for Warning and Critical dates
                $details += "Cert for site $($url.URL) expires in $ExpiresIn days [on $ExpirationDate]`n"
                $details += "Threshold is $minimumCertAgeDays days. Check details:`n"
                $details += "Cert name: $($CertDetails.Subject)`n"
                $details += "Cert thumbprint: $($CertDetails.Thumbprint)`n"
                $details += "Cert effective date: $($CertDetails.NotBefore)`n"
                $details += "Cert issuer: $($CertDetails.Issuer)"
            }
        }
    }
    # Couldn't get the Expiration Date from the site or the .csv
    catch {
        $CheckResult = "ERROR"
    }        

    # Build our table for the email
    $Object = "" | Select-Object "URL", "Check result", "Expires in days", "Expires on", "Server", "Business Application", "Owner", "Issuer", "Wildcard", "Details"
    # Add the table items
    $Object.URL = $url.URL
    $Object.'Check result' = $CheckResult
    $Object.'Expires in days' = $ExpiresIn
    $Object.'Expires on' = $ExpirationDate
    $Object.Server = $url.Server
    $Object.'Business Application' = $url.Application
    $Object.Owner = $url.Owner
    $Object.Issuer = $url.Issuer
    $Object.Wildcard = $url.Wildcard
    $Object.Details = $details
    # Output our table line so it is added to the report
    $Object
    # Clear Variables for the next URL
    Clear-Variable Site, port, Req, Stream, ExpiresIn, ExpirationDate, details -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
}

# Add formating
$html = $Report | Sort-Object -Property "Expires in days" | ConvertTo-Html -Fragment
$FormatedHtml = $html | ForEach-Object {
    # Add the table border and colors by replacing html with what we want.
    $_ -replace "<table>", '<table border="1";>' -replace "<td>CRITICAL</td>", "<td style='color: red'>CRITICAL</td>" -replace "<td>WARNING</td>", "<td style='color: orange'>WARNING</td>" -replace "<td>ERROR</td>", "<td style='color: red'>ERROR</td>" -replace "<td>OKAY</td>", "<td style='color: green'>OKAY</td>"
}
# Build formated Body
$HTMLBody = "Below is the list of URL's we are protecting with an SSL cert and the expiration date.<br><br>"
$HTMLBody += $FormatedHtml
$HTMLBody += "<br>Edit this file to update the list that is checked:<br> `"$Path`""

# If email info is actually setup then send it otherwise export as Test.html
if ($SMTPServer -ne "" -and $null -ne $SMTPServer -and $SMTPServer -ne "smtp.exmaple.com") {
    # Send Email
    Send-MailMessage -From $From -To $To -Subject $Subject -BodyAsHtml $HTMLBody -SmtpServer $SMTPServer -WarningAction SilentlyContinue
}
else {
    Write-Host "SMTP server doesn't seem to be filled in exporting to C:\Temp\Test.html instead"
    if (!(Test-Path -Path "C:\Temp")) {
        Write-Host "C:\Temp doesn't exist Creating it now"
        New-Item "C:\Temp" -ItemType Directory | Out-Null
    }
    #Export to html file
    $HTMLBody | Out-File C:\Temp\Test.html   
}
