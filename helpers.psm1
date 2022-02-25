Function New-BulkTestCerts {
    param(
        [Int]$Quantity = 1,
        [String]$NamePrefix = 'default',
        [String]$NameSuffix = 'TestCert',
        [String]$ExportDirectory = 'C:\temp',
        [String]$PlainTestPassword = '1234'

    )

    $i = 1
    
    While ($i -le $Quantity) {
      
        $fullCertName = $NamePrefix + $nameSuffix + $i 
    
        $param = @{
    
            CertStoreLocation = 'Cert:\LocalMachine\My'
            DnsName           = @("$NamePrefix_$nameSuffix_$i")
            KeyAlgorithm      = 'RSA'
            KeyExportPolicy   = 'Exportable' # ExportableEncrypted (default), NonExportable
            KeyLength         = 2048
            KeyUsage          = @('DataEncipherment', 'KeyEncipherment', 'DigitalSignature')
            NotAfter          = (Get-Date).AddDays(3650)
            Subject           = "CN={0},DC=certtest,DC=ORG,OU=TestOU" -f $fullCertName
        }
    
        $newCertificate = New-SelfSignedCertificate @param

        $securePassword = ConvertTo-SecureString -String $PlainTestPassword -AsPlainText 

        $newCertificate| Export-PfxCertificate -Password $securePassword -FilePath "$ExportDirectory\$fullCertName.pfx" | Out-Null
        
    
        $i += 1
    }
    
    

}


