# Generate self-signed certificate for Windows
$cert = New-SelfSignedCertificate -DnsName "dev.codegrey.ai" -CertStoreLocation "cert:\LocalMachine\My"
$pwd = ConvertTo-SecureString -String "codegrey123" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath ".\cert.pfx" -Password $pwd
Write-Host "Certificate generated: cert.pfx (password: codegrey123)"
