# build the LDAP path
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName

# instantiate DirectorySearcher class with LDAP provider path.
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry($SearchString, "corp.com\offsec","lab")
$Searcher.SearchRoot = $objDomain

# filter by Domain Admin users
$Searcher.filter="memberof=CN=Domain Admins,CN=Users,DC=corp,DC=com"
# filter by all Users in domain
$Searcher.filter="samAccountType=805306368"
# filter by all Groups in domain
$Searcher.filter="objectcategory=group"
# filter by all Computers in domain
$Searcher.filter="objectcategory=computer"
# filter by all Computers AND operating sys is Windows 10
$Searcher.filter="(&(objectcategory=computer)(operatingsystem=*Windows 10*))"

# invoke
$Result = $Searcher.FindAll()

# print each object and its properties
Foreach($obj in $Result) {
	Foreach($prop in $obj.Properties){$prop}
	Write-Host "------------------------"
}
