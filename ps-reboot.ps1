# .\ps-reboot.ps1 -lock 'True' -time '9:00PM' -time2 '6:30AM'
#Reboot on Lock.xml must be in same directory as script
#essentailly Lock.xml is an export task from task scheduler. In this case I exported a task that reboots the machine if the user locks the workstation

Param(
  [string]$lock, #True
  [string]$time, #9:00PM
  [string]$time2 #6:30AM
)

ipmo ScheduledTasks 
$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -command "& {Restart-Computer -Force}"' 

$trigger = @()
$trigger += New-ScheduledTaskTrigger -Daily -At $time
$trigger += New-ScheduledTaskTrigger -Daily -At $time2

#$trigger =  New-ScheduledTaskTrigger -Daily -At $time
$principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "UWF Reboot Script" -Description "Reboot UWF computer depending on param" -Principal $principal
#$locktask = Register-ScheduledTask -Xml (get-content '.\task.xml' | out-string) -TaskName "Reboot On Lock" -Principal $principal
If($lock='True'){
Register-ScheduledTask -Xml (get-content '.\task.xml' | out-string) -TaskName "Reboot On Lock" #-Principal $principal
}

