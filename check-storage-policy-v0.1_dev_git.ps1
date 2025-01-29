#Requires -RunAsAdministrator
#Requires -Modules Vmware.VimAutomation.Core

<#
.Synopsis
   Check if VMs of vCenter are compliance with configured storage policies
.DESCRIPTION
   Check if VMs of vCenter are compliance with configured storage policies
.EXAMPLE
   Inserir posteriormente
.EXAMPLE
   Inserir posteriormente
.CREATEDBY
    Juliano Alves de Brito Ribeiro (find me at julianoalvesbr@live.com or https://github.com/julianoabr or https://youtube.com/@powershellchannel)
.VERSION INFO
    0.1
.VERSION NOTES
    
.VERY IMPORTANT
    “Todos os livros científicos passam por constantes atualizações. 
    Se a Bíblia, que por muitos é considerada obsoleta e irrelevante, 
    nunca precisou ser atualizada quanto ao seu conteúdo original, 
    o que podemos dizer dos livros científicos de nossa ciência?” 

#>

<#

Possible errors: 

Get-SpbmStoragePolicy : 12/18/2024 2:55:06 PM	Get-SpbmStoragePolicy		com.vmware.vapi.std.errors.unauthenticated {'messages': [com.vmware.vapi.std.localizable_message {'id': 
com.vmware.vapi.endpoint.method.authentication.required, 'default_message': Authentication required., 'args': [], 'params': , 'localized':}], 'data': , 'error_type': UNAUTHENTICATED, 'challenge': Basic 
realm="VAPI endpoint",SIGN realm=8071d07acde1696c78beb1fb27afaafc7371c346,service="VAPI endpoint",sts="https://d4-vcavc-a1.host.intranet/sts/STSService/vsphere.local"}.	
At V:\BOX\PROCESS\VMware\VM\StoragePolicy\tmp-function-check-storpol.ps1:11 char:30
+     $tmpAllStoragePolicies = Get-SpbmStoragePolicy | Select-Object -E ...
+                              ~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Get-SpbmStoragePolicy], CisException
    + FullyQualifiedErrorId : VMware.VimAutomation.ViCore.Impl.V1.Service.Tagging.Cis.TaggingServiceCisImpl.GetTag.Error,VMware.VimAutomation.Storage.Commands.Cmdlets.Spbm.GetStorageProfile

Solution:
https://knowledge.broadcom.com/external/article/316636/gettagassignments-and-getspbmstoragepoli.html

#>

Clear-Host

#VALIDATE MODULE
$moduleExists = Get-Module -Name Vmware.VimAutomation.Core

if ($moduleExists){
    
    Write-Output "The Module Vmware.VimAutomation.Core is already loaded"
    
}#if validate module
else{
    
    Import-Module -Name Vmware.VimAutomation.Core -WarningAction SilentlyContinue -ErrorAction Stop
    
}#else validate module

#VALIDATE IF OPTION IS NUMERIC
function isNumeric ($x) {
    $x2 = 0
    $isNum = [System.Int32]::TryParse($x, [ref]$x2)
    return $isNum
} #end function is Numeric


#FUNCTION CONNECT TO VCENTER
function Connect-TovCenterServer
{
    [CmdletBinding()]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateSet('Manual','Automatic')]
        $methodToConnect = 'Automatic',
        
                      
        [Parameter(Mandatory=$true,
                   Position=1)]
        [System.String[]]$vCenterServerList,
                
       
        [Parameter(Mandatory=$false,
                   Position=2)]
        [ValidateSet('80','443')]
        [System.String]$port = '443',

        [Parameter(Mandatory=$false,
                   Position=3)]
        [System.String]$userName = 'domain\user'

    )

    #set up path and user variables
    $AESKeyFilePath = "$env:systemdrive\TMP\latestaes.key" # location of the AESKey                
    
    $SecurePwdFilePath = "$env:systemdrive\TMP\domainUser-encryptedPwd.txt" # location of the file that hosts the encrypted password  
        
    $userUPN = $userName # User account login 

    #use key and password to create local secure password
    $AESKey = Get-Content -Path $AESKeyFilePath 
    
    $pwdTxt = Get-Content -Path $SecurePwdFilePath

      
    $securePass = $pwdTxt | ConvertTo-SecureString -Key $AESKey

    #crete a new psCredential object with required username and password
    $vCenterCred = New-Object System.Management.Automation.PSCredential($userUPN, $securePass)
 
    if ($methodToConnect -like 'Automatic'){
        
        foreach ($vCenterServer in $vCenterServerList){
        
            $Script:workingServer = $vCenterServer

            $vCentersConnected = $global:DefaultVIServers.Count

            if ($vCentersConnected -eq 0){
            
                Write-Host "Before we continue, I validate that you are not connected to any vCenter" -ForegroundColor DarkGreen -BackgroundColor White
            
            }#validate connected vCenters
            else{
            
                Disconnect-VIServer -Server * -Confirm:$false -Force -Verbose -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            
            }#validate connected vCenters
                     
        
        }#end of Foreach

    }#end of If Method to Connect
    else{
        
        $numberofVCConnected = ($global:DefaultVIServers).Count

        if ($numberofVCConnected -eq 0){
            
            Write-Host "You are not connected to any vCenter" -ForegroundColor DarkGreen -BackgroundColor White
            
        }#validate connected vCenters
        else{
            
            Disconnect-VIServer -Server * -Confirm:$false -Force -Verbose -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            
         }#validate connected vCenters
        
        $workingLocationNum = ""
        
        $tmpWorkingLocationNum = ""
        
        $Script:WorkingServer = ""
        
        $i = 0

        #MENU SELECT VCENTER
        foreach ($vCenterServer in $vCenterServerList){
	   
                $vcServerValue = $vCenterServer
	    
                Write-Output "            [$i].- $vcServerValue ";	
	            $i++	
                }#end foreach	
                Write-Output "            [$i].- Exit this script ";

                while(!(isNumeric($tmpWorkingLocationNum)) ){
	                $tmpWorkingLocationNum = Read-Host "Type vCenter Number that you want to connect"
                }#end of while

                    $workingLocationNum = ($tmpWorkingLocationNum / 1)

                if(($WorkingLocationNum -ge 0) -and ($WorkingLocationNum -le ($i-1))  ){
	                $Script:WorkingServer = $vcServers[$WorkingLocationNum]
                }
                else{
            
                    Write-Host "Exit selected, or Invalid choice number. End of Script " -ForegroundColor Red -BackgroundColor White
            
                    Exit;
                }#end of else
      
    }#end of Else Method to Connect

    foreach ($vCenterServer in $vCenterServerList){

        #Connect to Vcenter
        Connect-VIServer -Server $Script:WorkingServer -Port $port -WarningAction Continue -ErrorAction Stop -Credential $vCenterCred
     
        Write-Host "You are connected to vCenter: $Script:WorkingServer" -ForegroundColor White -BackGroundColor DarkMagenta

    }#end of foreach
    
}#End of Function Connect to Vcenter

#DEFINE VCENTER LIST
$vcServerList = @()

#ADD OR REMOVE vCenters according to your domain      
$vcServerList = ('vcenter1.your.domain','vcenter2.your.domain','vcenter3.your.domain') | Sort-Object

$currentDate = (Get-Date -Format "ddMMyyyy-HHmm").ToString()

$outputPath = "$env:systemdrive\TMP\STORPOL"


##################################### MAIN SCRIPT ###############################################

foreach ($vcServer in $vcServerList)
{
    
    Connect-ToVcenterServer -methodToConnect Automatic -vCenterServerList $vcServer -Port 443 -Verbose

    $vCenterName = ""

    $vCenterName = ($global:DefaultVIServer.Name).Split(".")[0]

    $tmpAllStoragePolicies = @()

    $tmpAllStoragePolicies = Get-SpbmStoragePolicy | Select-Object -ExpandProperty Name | Sort-Object

    #$allStoragePolicies = Get-SpbmStoragePolicy | Where-Object -FilterScript {$PSItem.Name -like "ALLOCATION*" -or $PSItem.Name -like "PAYGO*"} | Select-Object -ExpandProperty Name

    $allStoragePolicies = @()
        
    foreach ($StorPol in $tmpAllStoragePolicies)
    {
    
        $storPolObj = Get-SpbmStoragePolicy -Name $storPol

        if (((Get-SpbmEntityConfiguration -StoragePolicy $storPolObj -VMsOnly).count) -eq 0){
    
            Write-Host "`n"
            Write-Host -NoNewLine "The storage policy: $storPol " -ForegroundColor White -BackgroundColor DarkMagenta
            write-host -NoNewline "does not have any VMs on it. I will not verify nothing in this policy" -ForegroundColor White -BackgroundColor Red
    
        }#end of IF
        else{
        
            Write-Host "`n"
            Write-Host -NoNewLine "The storage policy: $storPol " -ForegroundColor DarkGreen -BackgroundColor White
            Write-Host -NoNewline "have VMs on it. I will add to final list" -ForegroundColor White -BackgroundColor Green

            $allStoragePolicies += $storPol

        }#end of Else

    
    }#end of Foreach StorPol

Write-Host "`n"

Write-Host "These are the storage policies that I found with VMs:" -ForeGroundColor White -BackGroundColor Blue

$allStoragePolicies

    foreach ($storPol in $allStoragePolicies)
    {
    
        $storPolObj = Get-SpbmStoragePolicy -Name $storPol

        #GET ONLY NONCOMPLIANT VMs
        Get-SpbmEntityConfiguration -StoragePolicy $storPolObj -CheckComplianceNow -VMsOnly | Where-Object -FilterScript {$PSItem.ComplianceStatus -eq 'nonCompliant' -or $PSItem.ComplianceStatus -eq $null} | Out-File -FilePath "$outputPath\$vCenterName-VM-NotComplianceStorPol-$currentDate.txt" -Append

        #GET HARDDISKS non compliant
        $hdComplianceAll = Get-SpbmEntityConfiguration -StoragePolicy $storPolObj -CheckComplianceNow -HardDisksOnly | Where-Object -FilterScript {$PSItem.ComplianceStatus -eq 'nonCompliant' -or $PSItem.ComplianceStatus -eq $null}

        foreach ($hdItem in $hdComplianceAll)
        {
      
          $hdItemEntity = $hdItem.Entity

          $storPolNameHD = $hdItem.StoragePolicy
      
          $tmphdItemVM = $hdItem.ID

          $hdItemVM = $tmphdItemVM.Split("/")[0]

          $vmName = Get-VM -Id $hdItemVM | Select-Object -ExpandProperty Name

          Write-Host "The HD: $hdItemEntity of VM named: $vmName is not compliant with Storage Policy: $storPolNameHD" -ForegroundColor White -BackgroundColor Red  

          Write-Output "The HD: $hdItemEntity of VM named: $vmName is not compliant with Storage Policy: $storPolNameHD" | Out-File -FilePath "$outputPath\$vCenterName-HDS-NotComplianceStorPol-$currentDate.txt" -Append

        }#end of foreach

    }#end of ForEach Final StorPol

}#end of ForEach

Start-Sleep -Seconds 10

$sendMail = $true
#$sendMail = $false


if ($sendMail){

    Clear-Host

    Write-Host "Today I will send mail to HCP VMware Team" -ForegroundColor White -BackgroundColor DarkBlue
    
    Set-Location -Path $outputPath

    #$fileFromToday = ((Get-Date -Format dMMMyy).ToString())
    $fileFromToday = ((Get-Date -UFormat %d%m%Y).ToString())

    $fileLocation = $outputPath

    $tmpAttachs = @()

    $fileAttachs = @()

    $tmpAttachs = Get-ChildItem -File | Where-Object -FilterScript {($_.Name -like "*.txt") -and ($_.Name -like "*$fileFromToday*") -and $_.LastWriteTime -gt ((Get-date).AddMinutes(-120))} | Select-Object -ExpandProperty Name


    foreach ($attach in $tmpAttachs)
        {
        
        $attachment = $fileLocation + '\' + $attach
        
        $fileAttachs += $attachment
        
        }

    $tmpHTML = Get-Content "$env:systemdrive\TMP\contentStorPol.html"

    $finalHTML = $tmpHTML | Out-String


    ###########Define Variables########

    $fromaddress = "psrobot@yourdomain.com"
    $toaddress = "group1.yourdomain.com","group2.yourdomain.com","group3.yourdomain.com"
    $CCaddress = "boss@yourdomain.com","manager@yourdomain.com"
    $HVSubject = "[vCenter1][vCenter2] VMs Storage Policies Checking"
    $HVattachment = $fileAttachs
    $smtpServer = "192.168.10.50" #your smtp server

####################################

    Send-MailMessage -SmtpServer $smtpServer -From $fromaddress -To $toaddress -Cc $CCaddress -Subject $HVSubject -Body $finalHTML -BodyAsHtml -Attachments $HVattachment -Priority Normal -Encoding UTF8 -Verbose


}#end of IF
else{

    Write-Host "Today I will not send mail to HCP VMware" -ForegroundColor White -BackgroundColor DarkBlue

}#end of Else