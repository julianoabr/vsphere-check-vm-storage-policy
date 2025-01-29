#BEFORE USING MAIN SCRIPT YOU HAVE TO RUN THIS TO CREATE
#1. AES.KEY
#2. SAVE YOUR DOMAIN CRED
#3. CREATE CRED TO USE IN YOUR SCRIPT

#1. Create KEY #This section is obrigatory
$Key = New-Object Byte[] 32
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
$Key | Out-File -FilePath "$env:systemdrive\TMP\latestaes.key"


#2. Create Credential using AES KEY (will ask from credential) #This section is obrigatory
(get-credential).Password | ConvertFrom-SecureString -key (Get-Content "$env:systemdrive\TMP\latestaes.key") | Set-Content "$env:systemdrive\TMP\domainUser-encryptedPwd.txt"



#DOES NOT RUN - IT IS THE WAY THAT YOU USE IN YOUR MAIN SCRIPT
#3.Using Password with Script - put it in your script
$userName = 'user@domain.com'

$password = Get-Content "$env:systemdrive\TMP\domainUser-encryptedPwd.txt" | ConvertTo-SecureString -Key (Get-Content "$env:systemdrive\TMP\latestaes.key")

$credential = New-Object System.Management.Automation.PsCredential($username,$password)