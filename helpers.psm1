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

        $newCertificate | Export-PfxCertificate -Password $securePassword -FilePath "$ExportDirectory\$fullCertName.pfx" | Out-Null
        
    
        $i += 1
    }
    
    <#Examples:

New-BulkTestCerts -Quantity 10 -ExportDirectory C:\temp -PlainTestPassword 1234   

#>    

}

Function Import-AzureKeyvaultPFXCertificates {

    [CmdletBinding()]
    Param(
        [String]$ImportDirectory = 'C:\temp',
        [Parameter(Mandatory=$true)]
        [String]$PlainTestPassword,
        [Parameter(Mandatory=$true)]
        [String]$KeyvaultName = 'teaKeyvaultEng'
    )


    $pfxCerts = Get-ChildItem -Path $ImportDirectory -Filter *.pfx

    # Import-AzKeyVaultCertificate uses SecureString for password
    [securestring]$secStringPassword = ConvertTo-SecureString $PlainTestPassword -AsPlainText -Force
    
    if ($pfxCerts.Count -gt 0) {
    
        foreach ($pfxCertificate in $pfxCerts) {
            $pfxCertificate.FullName
    
            [String]$certFullPath = $pfxCertificate.FullName
            [String]$certName = $pfxCertificate.BaseName
    
            $param = @{
                VaultName = $KeyvaultName
                Name      = $certName 
                FilePath  = $certFullPath
                Password  = $secStringPassword
            }
    
            #$param
    
            Import-AzKeyVaultCertificate @param
        } 
    }
    else {
        Write-Output "No PFX certificates found in location $ImportDirectory"
        Break
    }
    
    

}