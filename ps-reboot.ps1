# .\ps-reboot.ps1 -lock 'True' -time '9:00PM' -time2 '6:30AM'
#Reboot on Lock.xml must be in same directory as script

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

# SIG # Begin signature block
# MIIFcAYJKoZIhvcNAQcCoIIFYTCCBV0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUXlTCPyjyGN9why/7nHHko1/b
# rOagggMKMIIDBjCCAe6gAwIBAgIQHlPb1/yWt7JN6KfQPQq+dTANBgkqhkiG9w0B
# AQsFADAbMRkwFwYDVQQDDBBDT04gQ29kZSBTaWduaW5nMB4XDTE4MDExMTE3NDU0
# MVoXDTIzMDExMTE3NTU0MVowGzEZMBcGA1UEAwwQQ09OIENvZGUgU2lnbmluZzCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANWHsowKgPxFLdv7Fsqb668X
# Xguh0mxrjQz9fyKml5VD2oH6U9k57x7atNO8YFl0hhPJ9Ez9Ul+hdqgk2K6UqRRV
# 0j/GALw3bYANXWP1F6U2nvrvjJoVlUu0i9zhTThWWk2uPhKy5C+10CRKBL05vTo2
# ZOzP9bqh2xz+4VAumE+DY81dYqpHlmk+7wqoh520CDTb/RuT830z2EeKiT3a99BG
# oKUJTH7zC+d/ymNSfJMybBCBGLQzsaDnVVm+gnhdHJRV1id3eDib14VXzdKWfdZZ
# c+pxzVUKQ3lwJWsy/jHnhBDgFWs3T+UwCoXy3I4Omn1Hwi+pW+6mFWOTY6Rcr8kC
# AwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0G
# A1UdDgQWBBRY6czcrftmVh/n55iZEedWA+AyEjANBgkqhkiG9w0BAQsFAAOCAQEA
# nmDc1RRHzPPEasryUYYMD1Axg6ROwlo/JjCU9rWvpD4bhUK//KhxFK4/raxHwRBL
# N9cUktZVMyLhzn8lxd1k3NQUBKODlUmTrPZyatBIUVzlzkqHp4oleoN5zGmUVrXR
# T0rlD1qBsQQ5JNiGcZsO5Kg2NSe/0VQROiBKYkRS/5A/dsTjZI39pkqXgUJn9V98
# C1qjZKHM0olpMk96miVw5ZyKPO14CRHZ4PReZ9uSYiQPrQB4WZnmVJEU/HYBghL/
# bVOEozavu3f9EguRny0l1lPG7JI2TcYuDngoOixf5LiFtxppxv839byizocYOmOq
# zCnun1AjWW1aRV+fWQUvxDGCAdAwggHMAgEBMC8wGzEZMBcGA1UEAwwQQ09OIENv
# ZGUgU2lnbmluZwIQHlPb1/yWt7JN6KfQPQq+dTAJBgUrDgMCGgUAoHgwGAYKKwYB
# BAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAc
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUYAwb
# ElMfjbWXKQ3HQuR5FpcaspAwDQYJKoZIhvcNAQEBBQAEggEAjIb2G91S2wKsbENb
# UQQhtUQ05SRG7eVddxZFOj62+LKbNG0GTfvBdatSlIe690MTGt63FtJ4ioVtRj42
# MRwxHStS4N3PPsNGAyjpvXJ6ea3keqdHm7fEP/Y2McDJaT9HzJ7ur3ikT52OzgWD
# S6lBiheaMQy1wiT5av5hIDbAzJVhut7XiFxAdXpOnlD1sSuvsMUQiVRLK8E79C+t
# UeQFTC0mks1N8JuaDKiOMensdJQDGsnRq+VfpBPh2JMB6ese/jmfChnw8bEozoie
# ibA9CozEghCGGbKxPM67ZM4S63ZBm40T4hSgGWvv/t2mWcbquOkv0myhxvTbjfj8
# 6cgL4w==
# SIG # End signature block
