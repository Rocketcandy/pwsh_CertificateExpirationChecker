# pwsh_CertificateExpirationChecker
Powershell 7 script to check a list of urls for Certificate Expiration Dates


<html>
Below is the list of URL's we are protecting with an SSL cert and the expiration date.<br><br><table border="1";> <colgroup><col/><col/><col/><col/><col/><col/><col/><col/><col/><col/></colgroup> <tr><th>URL</th><th>Check result</th><th>Expires in days</th><th>Expires on</th><th>Server</th><th>Business Application</th><th>Owner</th><th>Issuer</th><th>Wildcard</th><th>Details</th></tr> <tr><td>https://internalapp.example.com</td><td style='color: red'>CRITICAL</td><td>-37</td><td>3/1/2022</td><td>App Server 01</td><td>Internal App 1</td><td>Web Team</td><td>Internal CA</td><td></td><td>Expiration date is hard coded into the spreadsheet make sure to update the spreadsheet when the certificate is updated.Cert for site https://internalapp.example.com expires in -37 days [on 3/1/2022]
Threshold is 60 days. Check details:
Cert name: CN=*.wikipedia.org
Cert thumbprint: BEF070EC75671CECC6DC24DD25C678921EC8AEF3
Cert effective date: 03/12/2022 01:44:59
Cert issuer: CN=R3, O=Let&#39;s Encrypt, C=US</td></tr> <tr><td>https://brokenurl.example.com</td><td style='color: red'>ERROR</td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td>Exception while checking URL https://brokenurl.example.com: Exception calling &quot;.ctor&quot; with &quot;2&quot; argument(s): &quot;No such host is known.&quot; </td></tr> <tr><td>https://anotherinternalapp.example.com</td><td style='color: orange'>WARNING</td><td>42</td><td>5/20/2022</td><td>App Server 01</td><td>Another Internal App</td><td>Web Team</td><td>Internal CA</td><td></td><td>Expiration date is hard coded into the spreadsheet make sure to update the spreadsheet when the certificate is updated.Cert for site https://anotherinternalapp.example.com expires in 42 days [on 5/20/2022]
Threshold is 60 days. Check details:
Cert name: CN=www.example.org, O=Internet&#160;Corporation&#160;for&#160;Assigned&#160;Names&#160;and&#160;Numbers, L=Los Angeles, S=California, C=US
Cert thumbprint: DF81DFA6B61EAFDFFFFE1A250240DB5D2E6CEE25
Cert effective date: 03/13/2022 19:00:00
Cert issuer: CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US</td></tr> <tr><td>https://en.wikipedia.org/</td><td style='color: green'>OKAY</td><td>63</td><td>6/10/2022 2:44:58 AM</td><td>Wikipedia web server</td><td>Wikipedia</td><td>Web Team</td><td>R3</td><td>Yes</td><td></td></tr> <tr><td>https://vpn.example.com</td><td style='color: green'>OKAY</td><td>327</td><td>3/1/2023</td><td>Firewall</td><td>VPN</td><td>Security Team</td><td>DigiCert</td><td></td><td>Expiration date is hard coded into the spreadsheet make sure to update the spreadsheet when the certificate is updated.</td></tr> <tr><td>https://example.com</td><td style='color: green'>OKAY</td><td>341</td><td>3/14/2023 6:59:59 PM</td><td>Web Server 01</td><td>Web Site</td><td>Web Team</td><td>DigiCert</td><td></td><td></td></tr> </table><br>Edit this file to update the list that is checked:<br> "C:\Temp\check-urls.csv"
</html>
