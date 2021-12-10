# Active Directory Cheatsheet

## AD Introduction

Goal:
1. Perform user hunting to track down where users are logged into in the network.
2. Dump credentials and/or obtain Kerberos tickets.
3. Gain access to the user's machine using creds/ticket.
4. (Possibly) escalate privileges in the machine.
5. Repeat steps above until you have administrative privileges in the Domain Controller.

## AD Enumeration

### Enumeration - Manual




Enum users/groups/computers
* Look for users with high-privs across the domain e.g. Domain Admins or Derivative Local Admins
* Look for custom groups.
```
# get all users in the domain
cmd> net user /domain
cmd> net user [username] /domain

# get all groups in the domain
cmd> net group /domain
cmd> net group [groupname] /domain

# get all computers in the domain
cmd> net computer /domain
cmd> net computer \\[computername] /domain
```

Enum Domain Controller hostname (PdcRoleOwner)
```
PS> [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

Enum via. Service Principal Names (Service Accounts)


### Enumeration - Automated

PowerShell

PowerShell automated users/groups/computers enum
```
# build the LDAP path
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName

# instantiate DirectorySearcher class with LDAP provider path.
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry($SearchString, "[domain_name]\[user]","[password]")
$Searcher.SearchRoot = $objDomain

# ###########################
# UNCOMMENT FILTERS AS NEEDED
# ###########################

# filter by Domain Admin users
$Searcher.filter="memberof=CN=Domain Admins,CN=Users,DC=corp,DC=com"

# filter by all Users in domain
# $Searcher.filter="samAccountType=805306368"

# filter by all Groups in domain
# $Searcher.filter="objectcategory=group"

# filter by all Computers in domain
# $Searcher.filter="objectcategory=computer"

# filter by all Computers AND operating sys is Windows 10
# $Searcher.filter="(&(objectcategory=computer)(operatingsystem=*Windows 10*))"

# invoke
$Result = $Searcher.FindAll()

# print each object and its properties
Foreach($obj in $Result) {
        Foreach($prop in $obj.Properties){$prop}
        Write-Host "------------------------"
}
```




## AD Authentication




## AD Lateral Movement




## AD Persistence



