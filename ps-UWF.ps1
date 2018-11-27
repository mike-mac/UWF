function Remove-NTFSPermissions($folderPath, $accountToRemove, $permissionToRemove) {
 
    $fileSystemRights = [System.Security.AccessControl.FileSystemRights]$permissionToRemove
 
    $inheritanceFlag = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
 
    $propagationFlag = [System.Security.AccessControl.PropagationFlags]"None"
 
    $accessControlType =[System.Security.AccessControl.AccessControlType]::Allow
 
 
 
 
    $ntAccount = New-Object System.Security.Principal.NTAccount($accountToRemove)
 
    if($ntAccount.IsValidTargetType([Security.Principal.SecurityIdentifier])) {
 
        $FileSystemAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($ntAccount, $fileSystemRights, $inheritanceFlag, $propagationFlag, $accessControlType)
 
         
 
        $oFS = New-Object IO.DirectoryInfo($folderPath)
 
        $DirectorySecurity = $oFS.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
 
         
 
        $DirectorySecurity.RemoveAccessRuleAll($FileSystemAccessRule)
 
         
 
        $oFS.SetAccessControl($DirectorySecurity)
 
         
 
        return "Permissions " + $permissionToRemove + " Removed on " + $folderPath + " folder"
 
    }
 
    return 0
 
}
# Global variables
    $NAMESPACE = "root\standardcimv2\embedded"
function Enable-UWF {
 
    # Global variables
    #$NAMESPACE = "root\standardcimv2\embedded"
     
    ########################################################################################################################
 
    # Get current state of UWF
    $objUWFFilter = Get-WmiObject -Namespace $NAMESPACE -Class UWF_Filter;
     
    if(!$objUWFFilter) {
        write-output "`nUnable to retrieve Unified Write Filter settings. from $NAMESPACE" | out-file -FilePath $env:temp\UWF.log -Append
        return;
    }
 
    # Check if UWF is enabled
    if(($objUWFFilter.CurrentEnabled)-or($objUWFFilter.NextEnabled)) {
        write-output "`nUWF Filter is enabled" | out-file -FilePath $env:temp\UWF.log -Append
    } else {
        write-output "`nUWF Filter is NOT enabled, enabling now..." | out-file -FilePath $env:temp\UWF.log -Append
 
        # Call the method to enable UWF after the next restart.  This sets the NextEnabled property to false.
        $retval = $objUWFFilter.Enable();
         
        # Check the return value to verify that the enable is successful
        if ($retval.ReturnValue -eq 0) {
            write-output "Unified Write Filter will be enabled after the next system restart." | out-file -FilePath $env:temp\UWF.log -Append
        } else {
            "Unknown Error: " + "{0:x0}" -f $retval.ReturnValue
        }
 
    }
    }
    # Only perform config if after the next restart the UWF is enabled
$objUWFFilter = Get-WmiObject -Namespace $NAMESPACE -Class UWF_Filter;
If($objUWFFilter.NextEnabled){
    write-output "UWF is set to enabled after next restart, continue to check config" | out-file -FilePath $env:temp\UWF.log -Append
 
    # Get volume protect state
    $objUWFVolumeC = Get-WmiObject -Namespace $NAMESPACE -Class UWF_Volume -Filter "CurrentSession = false" | ? {(get-volume -DriveLetter C).UniqueId -like "*$($_.VolumeName)*"}
 
    # Check if C is protected
    If(!$objUWFVolumeC.Protected){
        write-output "C Drive not protected, will enable protection now.." | out-file -FilePath $env:temp\UWF.log -Append
        #enable protection
        #$retval = $objUWFVolumeC.Protect()
        uwfmgr.exe volume protect c:
         # Check the return value to verify that it was successful
        #if ($retval.ReturnValue -eq 0) {
        #    write-host "Unified Write Filter will protect the C drive after the next system restart." -ForegroundColor Green
        #} else {
        #    "Unknown Error: " + "{0:x0}" -f $retval.ReturnValue
        #}
    }    

    # Overlay size and type
 
    $objUWFOverlayConfig = Get-WmiObject -Namespace $NAMESPACE -Class UWF_OverlayConfig -Filter "CurrentSession = false"
 
    If($objUWFOverlayConfig.MaximumSize -le 1024){
        # need to set maximum size
        $OverlaySize = (Get-Volume -DriveLetter C).SizeRemaining-((Get-Volume -DriveLetter C).SizeRemaining/2) | % {[math]::truncate($_ /1MB)}
        write-output "`nTry to set overlay max size to $OverlaySize MB." | out-file -FilePath $env:temp\UWF.log -Append
        $objUWFOverlayConfig.SetMaximumSize($OverlaySize);
        $WarningSize = [math]::Round($OverlaySize/10*8)
        $CriticalSize = [math]::Round($OverlaySize/10*9)
        uwfmgr.exe overlay set-warningthreshold $WarningSize
        uwfmgr.exe overlay set-criticalthreshold $CriticalSize
    }
 
    If($objUWFOverlayConfig.Type -ne 1){
        # Set overlay type to Disk based
        write-host "`nTry to set overlay type to Disk based" -ForegroundColor Yellow
        $objUWFOverlayConfig.SetType(1)
    }
    # File exclusions
 
        $objUWFVolumeC = Get-WmiObject -Namespace $NAMESPACE -Class UWF_Volume -Filter "CurrentSession = false" | ? {(get-volume -DriveLetter C).UniqueId -like "*$($_.VolumeName)*"}
        $FileExclusionList = @(
         
           #Exclusions for Defender and SCEP https://msdn.microsoft.com/en-us/library/windows/hardware/mt571986(v=vs.85).aspx
           "\ProgramData\Microsoft\Microsoft Security Client", `
           #"\ProgramData\Microsoft\Windows Defender", `
           #"\Program Files\Windows Defender", `
           "\Program Files (x86)\Windows Defender", `
           "\Users\All Users\Microsoft\Microsoft Security Client", `
          # "\Windows\WindowsUpdate.log", `
          # "\Windows\Temp\MpCmdRun.log", `
        
           #BITS: https://msdn.microsoft.com/en-us/library/windows/hardware/mt571989(v=vs.85).aspx
           "\Users\All Users\Microsoft\Network\Downloader", `
 
           #https://docs.microsoft.com/en-us/windows-hardware/customize/enterprise/uwfexclusions
           "\Windows\wlansvc\Policies", `
           "\Windows\dot2svc\Policies", `
           "\ProgramData\Microsoft\wlansvc\Profiles\Interfaces", `
           "\ProgramData\Microsoft\dot3svc\Profiles\Interfaces", `
            #SCCM and Other Exclusions
            "\Program Files\Windows Defender", `
            "\Windows\WindowsUpdate.log", `
            "\Windows\Temp\MpCmdRun.log", `
            "\ProgramData\Microsoft\Windows Defender", `
            "\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft System Center", `
            "\windows\ccm", `
            "\windows\ccm\UserAffinityStore.sdf", `
            "\windows\ccm\InventoryStore.sdf", `
            "\windows\ccm\CcmStore.sdf", `
            "\windows\ccm\StateMessageStore.sdf", `
            "\windows\ccm\CertEnrollmentStore.sdf", `
            "\windows\ccm\ServiceData", `
            "\windows\ccmssetup", `
            "\windows\ccmcache", `
            "\_TaskSequence", `
            "\windows\bootstat.dat", `
            "\Windows\wlansvc\Policies", `
            "\ProgramData\Microsoft\wlansvc\Profiles\Interfaces", `
            "\ProgramData\Microsoft\dot3svc\Profiles\Interfaces", `
            "\Windows\dot2svc\Policies", `
            "\Program Files\Windows Defender", `
            "\ProgramFiles(X86)\Windows Defender", `
            "\ProgramData\Microsoft\Windows Defender", `
            "\Windows\WindowsUpdate.log", `
            "\Windows\Temp\MpCmdRun.log", `
            "\ProgramData\Microsoft\Windows Defender", `
            "\Windows\System32\Microsoft\Protect", `
            "\ProgramData\Microsoft\Crypto", `
            "\ProgramData\Microsoft\Network\Downloader", `
            "\windows\System32\Winevt\Logs"
     
        )
 
        write-host "`n"
 
        ForEach($File in $FileExclusionList){
         
            If(!($objUWFVolumeC.FindExclusion($File)).bFound){
 
                write-host "$File needs to be added to exclusions"
                $objUWFVolumeC.AddExclusion($File)
 
            }
 
        }
     
        # Reg exclusions
        $objUWFRegFilter = Get-WmiObject -Namespace $NAMESPACE -Class UWF_RegistryFilter -Filter "CurrentSession = false"
         
        $RegExclusionList = @(
 
            #Exclusions for Defender and SCEP https://msdn.microsoft.com/en-us/library/windows/hardware/mt571986(v=vs.85).aspx
            #"HKLM\SOFTWARE\Microsoft\Windows Defender", `
            "HKLM\SOFTWARE\Microsoft\Microsoft Antimalware", 
 
            #https://docs.microsoft.com/en-us/windows-hardware/customize/enterprise/uwfexclusions
            "HKLM\Software\Microsoft\Windows\CurrentVersion\BITS\StateIndex", `
            "HKLM\SOFTWARE\Policies\Microsoft\Windows\Wireless\GPTWirelessPolicy", `
            "HKLM\SOFTWARE\Policies\Microsoft\Windows\WiredL2\GP_Policy", `
            "HKLM\SYSTEM\CurrentControlSet\services\Wlansvc", `
            "HKLM\SYSTEM\CurrentControlSet\services\WwanSvc", `
            "HKLM\SYSTEM\CurrentControlSet\services\dot3svc", `
            "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones", `
            "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation", `
            #SCCM and Such
            "HKLM\SOFTWARE\Microsoft\Windows Defender", `
            "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones", `
            "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation", `
            "HKLM\SOFTWARE\Microsoft\Windows Defender", `
            "HKLM\Software\Microsoft\SystemCertificates\SMS\Certificates", `
            "HKLM\SOFTWARE\Microsoft\Antimalware", `
            "HKLM\Software\Microsoft\Windows\CurrentVersion\BITS\StateIndex", `
            "HKLM\SYSTEM\CurrentControlSet\services\dot3svc", `
            "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones", `
            "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation", `
            "HKLM\SOFTWARE\Microsoft\CCM\StateSystem", `
            "HKLM\SOFTWARE\Policies\Microsoft\Windows\WiredL2\GP_Policy", `
            "HKLM\SOFTWARE\Policies\Microsoft\Windows\Wireless\GPTWirelessPolicy", `
            "HKLM\SYSTEM\CurrentControlSet\services\Wlansvc", `
            "HKLM\SYSTEM\CurrentControlSet\services\WwanSvc", `
            "HKLM\SYSTEM\CurrentControlSet\services\dot3svc"

        )
 
     
        ForEach($Reg in $RegExclusionList){
 
            If(!($objUWFRegFilter.FindExclusion($Reg)).bFound){
 
                write-host "$Reg needs to be added to exclusions"
                $objUWFRegFilter.AddExclusion($Reg)
 
            }
 
        }
 
     
    } else {
 
        write-host "UWF is not set to enabled on the next restart, will not check config"
 
    }

    # Pagefile creation on a separate volume
   $PageFileDriveLetter = "P"
   $PageFileDriveSizeGB = 5
   # Check page file does not exist
   $PFUsage = Get-WmiObject -Class Win32_PageFileUsage -Property Name
   If(!($PFUsage) -or ($($PFUsage.Name) -eq "C:\pagefile.sys")){
       Write-Warning "Pagefile does not exist, will create one on a $PageFileDriveLetter drive"
 
       # create page file drive if does not exist
       $PageFileDrive = Get-CimInstance -ClassName CIM_StorageVolume -Filter "Name='$($PageFileDriveLetter):\\'"
       If(!$PageFileDrive){
 
           Write-Warning -Message "Failed to find the DriveLetter $PageFileDriveLetter specified, creating new volume now...."
           $CVol = get-volume -DriveLetter C
           $VolSizeRemaining = [int]($CVol.SizeRemaining /1GB).ToString(".")
           If($VolSizeRemaining -lt $PageFileDriveSizeGB){
               Write-Error "Not enough free space on the C drive to create a new volume for the page file"
               return
           } else {
               write-host "Enough free space on the C drive is available to create the new $PageFileDriveLetter drive"
               #enable optimise drives service (defrag) otherwise resize fails
               Set-Service -Name defragsvc -StartupType Manual -ErrorAction SilentlyContinue
 
               $NewCDriveSize = $CVol.Size-"$($PageFileDriveSizeGB)GB"
               write-host "Resizing C: from $($CVol.Size) to $NewCDriveSize"
               Get-Partition -DriveLetter C | Resize-Partition -Size $NewCDriveSize -ErrorAction Stop
               write-host "Resized C to $NewCDriveSize. Now creating new $PageFileDriveLetter drive from the free space..."
               # Create new partition
               Get-Volume -DriveLetter C | Get-Partition | Get-Disk | New-Partition -UseMaximumSize -DriveLetter $PageFileDriveLetter | Format-Volume
 
           }
 
       } else {
           write-host "$PageFileDriveLetter already exists"
       }
 
       write-host "Creating page file on $PageFileDriveLetter drive"
       New-CimInstance -ClassName Win32_PageFileSetting -Property  @{Name= "$($PageFileDriveLetter):\pagefile.sys"} -ErrorAction Stop | Out-Null
       $InitialSize = [math]::Round((get-volume -DriveLetter $PageFileDriveLetter).SizeRemaining /1MB /10 *9)
       $MaximumSize = [math]::Round((get-volume -DriveLetter $PageFileDriveLetter).SizeRemaining /1MB /10 *9)
       # http://msdn.microsoft.com/en-us/library/windows/desktop/aa394245%28v=vs.85%29.aspx            
       Get-CimInstance -ClassName Win32_PageFileSetting -Filter "SettingID='pagefile.sys @ $($PageFileDriveLetter):'" -ErrorAction Stop | Set-CimInstance -Property @{
           InitialSize = $InitialSize ;
           MaximumSize = $MaximumSize ; 
       } -ErrorAction Stop
         
       Write-Verbose -Message "Successfully configured the pagefile on drive letter $DriveLetter"
 
 
 
   } else {
 
       write-host "Pagefile already exists: $($PFUsage.Name)"
 
   }
   $UWF_Feature = (Get-WindowsOptionalFeature -Online -FeatureName Client-UnifiedWriteFilter -ErrorAction SilentlyContinue).State
 
If($UWF_Feature -eq "Disabled"){
 
    write-host "Not installed"
    Enable-WindowsOptionalFeature -Online -FeatureName Client-UnifiedWriteFilter -All -ErrorAction SilentlyContinue
 
    write-host "Please run this script again after a restart, to enable UWF filter" -ForegroundColor Yellow
 
    pause
 
    exit 3010
 
} else {
 
    write-host "`nClient-UnifiedWriteFilter WindowsOptionalFeature installed, now configure UWF" -ForegroundColor Green
     
    Enable-UWF -ErrorAction SilentlyContinue
 
    If(test-path p:){
        $folder = "P:\"
        Remove-NTFSPermissions $folder "Authenticated Users" "Modify"
        Remove-NTFSPermissions $folder "Users" "ReadAndExecute"
    }
 
}
