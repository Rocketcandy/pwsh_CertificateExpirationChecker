Param(
    [Parameter(Mandatory = $false,
        HelpMessage = "Enter comma seperated list of hostnames to check or IP range in CIDR format 'a.b.c.d/#'")]
    #[String[]]$Servers = "example.com"
    [String[]]$Servers = "192.168.44.0/30"
)

function Get-IpRange {
    <#
    .SYNOPSIS
        Given a subnet in CIDR format, get all of the valid IP addresses in that range.
    .DESCRIPTION
        Given a subnet in CIDR format, get all of the valid IP addresses in that range.
    .PARAMETER Subnets
        The subnet written in CIDR format 'a.b.c.d/#' and an example would be '192.168.1.24/27'. Can be a single value, an
        array of values, or values can be taken from the pipeline.
    .EXAMPLE
        Get-IpRange -Subnets '192.168.1.24/30'
     
        192.168.1.25
        192.168.1.26
    .EXAMPLE
        (Get-IpRange -Subnets '10.100.10.0/24').count
     
        254
    .EXAMPLE
        '192.168.1.128/30' | Get-IpRange
     
        192.168.1.129
        192.168.1.130
    .NOTES
        Function credit: https://github.com/riedyw/PoshFunctions
        Inspired by https://gallery.technet.microsoft.com/PowerShell-Subnet-db45ec74
     
        * Added comment help
    #>
    
    [CmdletBinding(ConfirmImpact = 'None')]
    Param(
        [Parameter(Mandatory, HelpMessage = 'Please enter a subnet in the form a.b.c.d/#', ValueFromPipeline, Position = 0)]
        [string[]] $Subnets
    )
    
    begin {
        Write-Verbose -Message "Starting [$($MyInvocation.Mycommand)]"
    }
    
    process {
        foreach ($subnet in $subnets) {
            if ($subnet -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$') {
                #Split IP and subnet
                $IP = ($Subnet -split '\/')[0]
                [int] $SubnetBits = ($Subnet -split '\/')[1]
                if ($SubnetBits -lt 7 -or $SubnetBits -gt 30) {
                    Write-Error -Message 'The number following the / must be between 7 and 30'
                    break
                }
                #Convert IP into binary
                #Split IP into different octects and for each one, figure out the binary with leading zeros and add to the total
                $Octets = $IP -split '\.'
                $IPInBinary = @()
                foreach ($Octet in $Octets) {
                    #convert to binary
                    $OctetInBinary = [convert]::ToString($Octet, 2)
                    #get length of binary string add leading zeros to make octet
                    $OctetInBinary = ('0' * (8 - ($OctetInBinary).Length) + $OctetInBinary)
                    $IPInBinary = $IPInBinary + $OctetInBinary
                }
                $IPInBinary = $IPInBinary -join ''
                #Get network ID by subtracting subnet mask
                $HostBits = 32 - $SubnetBits
                $NetworkIDInBinary = $IPInBinary.Substring(0, $SubnetBits)
                #Get host ID and get the first host ID by converting all 1s into 0s
                $HostIDInBinary = $IPInBinary.Substring($SubnetBits, $HostBits)
                $HostIDInBinary = $HostIDInBinary -replace '1', '0'
                #Work out all the host IDs in that subnet by cycling through $i from 1 up to max $HostIDInBinary (i.e. 1s stringed up to $HostBits)
                #Work out max $HostIDInBinary
                $imax = [convert]::ToInt32(('1' * $HostBits), 2) - 1
                $IPs = @()
                #Next ID is first network ID converted to decimal plus $i then converted to binary
                For ($i = 1 ; $i -le $imax ; $i++) {
                    #Convert to decimal and add $i
                    $NextHostIDInDecimal = ([convert]::ToInt32($HostIDInBinary, 2) + $i)
                    #Convert back to binary
                    $NextHostIDInBinary = [convert]::ToString($NextHostIDInDecimal, 2)
                    #Add leading zeros
                    #Number of zeros to add
                    $NoOfZerosToAdd = $HostIDInBinary.Length - $NextHostIDInBinary.Length
                    $NextHostIDInBinary = ('0' * $NoOfZerosToAdd) + $NextHostIDInBinary
                    #Work out next IP
                    #Add networkID to hostID
                    $NextIPInBinary = $NetworkIDInBinary + $NextHostIDInBinary
                    #Split into octets and separate by . then join
                    $IP = @()
                    For ($x = 1 ; $x -le 4 ; $x++) {
                        #Work out start character position
                        $StartCharNumber = ($x - 1) * 8
                        #Get octet in binary
                        $IPOctetInBinary = $NextIPInBinary.Substring($StartCharNumber, 8)
                        #Convert octet into decimal
                        $IPOctetInDecimal = [convert]::ToInt32($IPOctetInBinary, 2)
                        #Add octet to IP
                        $IP += $IPOctetInDecimal
                    }
                    #Separate by .
                    $IP = $IP -join '.'
                    $IPs += $IP
                }
                Write-Output -InputObject $IPs
            }
            else {
                Write-Error -Message "Subnet [$subnet] is not in a valid format"
            }
        }
    }
    
    end {
        Write-Verbose -Message "Ending [$($MyInvocation.Mycommand)]"
    }
}

Foreach ($Server in $Servers){
    if($Server -like "*/*"){
        $IPList = Get-IpRange $Server
        $Servers += $IPList
        $Servers = $Servers | Where-Object {$_ -ne $Server}
    }
}
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
    $Object = "" | Select-Object "Server", "Port", "Resonse", "SSL", "Subject", "SAN", "Issuer"
    # Add the table items
    $Object.Server = $Server
    $Object.Port = $Port
    $Object.Resonse = $Response
    $Object.SSL = $SSL
    $Object.Subject = $Subject
    $Object.SAN = $SAN
    $Object.Issuer = $CertDetails.Issuer
    # Output our table line so it is added to the report
    $Object
    # Clear variables for next Server
    Clear-Variable Connection, Subject, SAN, Server, Port, Response, SSL, CertDetails, ExpirationDate -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
}
$ServersWithSSL | Format-Table -AutoSize