<#Notes:
      Private keys NEVER leave the keyvault. This is by design.

      When a Key Vault certificate is created, an addressable key and secret are also created with the same name.
      https://docs.microsoft.com/en-us/azure/key-vault/certificates/about-certificates

      To access the content of a keyvault, use access policy

      To Manage the keyvault itself, use RBAC (Management plane vs data plane)

      Turn on diagnostic settings to allow logs to flow to analytics workspace.

      Security:
            https://docs.microsoft.com/en-us/azure/key-vault/general/security-features

#>


<#TODO:
      Setup LogAnalytics workspace
      Setup diagnostics to go to log analytics workspace
      Alert on access to keyvault outside specific IP address ranges
      Alert on expiration dates of certs
      Automate cert management operations
      Populate "Certificate Contacts" with email addresses of Certificate administrators
         When adding a new vertion of a certificate, it will inherit it's certificate policy (Issuance policy per cert)
      Set firewall rule to only allow certain IP's to make calls
#>

<#Kusto Queries (requires setup of diagnostics)

      AzureDiagnostics
      | where ResourceType == 'VAULTS'
      | summarize count() by OperationName, _ResourceId


      AzureDiagnostics
      | where ResourceProvider =="MICROSOFT.KEYVAULT"
      | summarize count() by CallerIPAddress

#>

#Setup keyvault and Certificate names

$azKeyvaultName = 'teaKeyvaultEng' #Set your keyvault name here before continuing.
$certificateName = 'name1'

#General commands

      #List all commands in Az.Keyvault module
      Get-Command -Module az.keyvault
      Get-Module -ListAvailable
#

#Vault Operations

      #List all keyvaults in a subscription
      Get-AzKeyVault

      #Get a specific keyvault
      Get-AzKeyVault -VaultName $azKeyvaultName

      #View Certificate contacts for a keyvault
      Get-AzKeyVaultCertificateContact -VaultName $azKeyvaultName

#

#Certificate Operations

      #List all certificates within a vault
      Get-AzKeyVaultCertificate -VaultName $azKeyvaultName

      #List information on a specific certificate in a key vault
      Get-AzKeyVaultCertificate -VaultName $azKeyvaultName -Name $certificateName

      #Enable or Disable a certificate
      Update-AzKeyVaultCertificate -VaultName $azKeyvaultName -Name $certificateName -Enable $false -PassThru

      #Get expiration date of certs in keyvault
      $keyVaultCerts = Get-AzKeyVaultCertificate -VaultName $azKeyvaultName
      $keyVaultCerts | Select Name, Expires

      #Remove a certificate from keyvault store
      Remove-AzKeyVaultCertificate -VaultName $azKeyvaultName -Name 'name1' -Force

      #Import Certificate

      <#
      Import-AzureKeyVaultCertificate
            [-VaultName] <String>
            [-Name] <String>
            -FilePath <String>
            [-Password <SecureString>]
            [-Tag <Hashtable>]
            [-DefaultProfile <IAzureContextContainer>]
            [-WhatIf]
            [-Confirm]
            [<CommonParameters>]
      #>

      [string]$certificatePassword = '1234Pass'


      # Import-AzKeyVaultCertificate uses SecureString for password
      [securestring]$secStringPassword = ConvertTo-SecureString $certificatePassword -AsPlainText -Force

      [securestring]$secStringPassword = Get-AzKeyVaultSecret -Name 'OATICertPassword' -VaultName $azKeyvaultName -AsPlainText | ConvertTo-SecureString -AsPlainText -Force

      [String]$certPath = 'C:\Temp\POS_OASIS.pfx' #'C:\Scripts\AzureKeyvaultExamples$certificateNametestcert.pfx'
                  
      [String]$certName = 'PSO-OASIS'


      $param = @{
            VaultName = $azKeyvaultName
            Name = $certName 
            FilePath = $certPath
            Password = $secStringPassword
      }

      Import-AzKeyVaultCertificate @param

#


#Certificate Policy Operations

      #View Certificate Polices
      Get-AzKeyVaultCertificatePolicy -VaultName $azKeyvaultName -Name $certificateName

      #Disable Certificate Issuance Policy (Not certificate!)
      Set-AzKeyVaultCertificatePolicy -VaultName $azKeyvaultName -Name $certificateName -Disabled
#

#Secret Operations

      #Get Keyvault Secrets
      Get-AzKeyVaultSecret -VaultName $azKeyvaultName

      #Create or update a secret (basically a password)
      $securePassword = ConvertTo-SecureString -AsPlainText -String 'PlainTextPasswordForCertificates' 
      Set-AzKeyVaultSecret -Name OATICertPassword -SecretValue $securePassword -VaultName $azKeyvaultName

      #Retrieve secret value in plain text
      Get-AzKeyVaultSecret -Name 'OATICertPassword' -VaultName $azKeyvaultName -AsPlainText
#

#Key Operations

      #Retrieve key (Allows cert operations for certificates)
      Get-AzKeyVaultKey -VaultName $azKeyvaultName

#



#Generate log data
while ($true) {
      Get-AzKeyVaultCertificate -VaultName $azKeyvaultName

      sleep -Seconds 2
}
#