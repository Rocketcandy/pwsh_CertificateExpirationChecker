$Servers = "google.com", "example.com"
$ServersWithSSL = foreach ($Server in $Servers) {
    $Port = 443
    $Connection = New-Object System.Net.Sockets.TcpClient($Server, $Port)
    if ($Connection.Connected) {
        $Response = "Yes"
        try {
            $Req = [System.Net.Sockets.TcpClient]::new($Server, $Port)
            $Stream = [System.Net.Security.SslStream]::new($Req.GetStream(), $true, { $true }) # ignore SSL Errors
            $Stream.AuthenticateAsClient($Server)
            # Get Cert Details
            $CertDetails = $Stream.RemoteCertificate
            # Get Certificate Expiration Date
            #$ExpirationDate = $CertDetails.GetExpirationDateString()
            $Subject = $CertDetails.Subject
            $SAN = $CertDetails | Select-Object @{name = 'SAN'; expression = { ($_.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }).format($true) } } | Select-Object -ExpandProperty "SAN"
            $SSL = "Yes"
        }
        catch {
            $SSL = "No"
        }
    }
    else { 
        $Response = "No"
    }
    # Build our table for the email
    $Object = "" | Select-Object "Server", "Port", "Resonse", "SSL", "Subject", "Subject Alternative Name", "Issuer"
    # Add the table items
    $Object.Server = $Server
    $Object.Port = $Port
    $Object.Resonse = $Response
    $Object.SSL = $SSL
    $Object.Subject = $Subject
    $Object.'Subject Alternative Name' = $SAN
    $Object.Issuer = $CertDetails.Issuer
    # Output our table line so it is added to the report
    $Object
    # Clear variables for next server
    Clear-Variable Connection, Subject, SAN, Server, Port, Response, SSL, CertDetails, ExpirationDate -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
}
$ServersWithSSL | Format-Table -AutoSize