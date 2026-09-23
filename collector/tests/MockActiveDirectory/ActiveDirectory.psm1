# TEST DOUBLE ONLY. Minimal fake of the RSAT ActiveDirectory module (plus Resolve-DnsName) so the collector
# can be smoke-tested end-to-end on any OS without a domain. Never place this folder on a production PSModulePath.
#
# Topology: forest contoso.test, one domain, three DCs:
#   localhost    - PDC/all FSMO, GC, healthy
#   127.0.0.2    - GC, inbound replication failing (8606), clock +95 s
#   dc3.invalid  - unreachable
Set-StrictMode -Version Latest

$script:Now = Get-Date
$script:DomainDN = 'DC=contoso,DC=test'
$script:Sid = 'S-1-5-21-1111111111-2222222222-3333333333'
function New-Obj { param([hashtable]$H) return [pscustomobject]$H }

function Get-ADForest {
    [CmdletBinding()] param([string]$Identity, [string]$Server)
    New-Obj @{ Name = 'contoso.test'; RootDomain = 'contoso.test'; ForestMode = 'Windows2012R2Forest'; SchemaMaster = 'localhost'; DomainNamingMaster = 'localhost'
        Domains = @('contoso.test'); Sites = @('HQ', 'Branch', 'Empty'); GlobalCatalogs = @('localhost', '127.0.0.2'); UPNSuffixes = @() }
}

function Get-ADDomainController {
    [CmdletBinding()] param([switch]$Discover, [string]$DomainName, [string[]]$Service, [string]$Filter, [string]$Server)
    if ($Discover) { return New-Obj @{ HostName = @('localhost') } }
    @(
        New-Obj @{ HostName = 'localhost'; Name = 'DC1'; Site = 'HQ'; IPv4Address = '127.0.0.1'; OperatingSystem = 'Windows Server 2022 Datacenter'; OperatingSystemVersion = '10.0 (20348)'; IsGlobalCatalog = $true; IsReadOnly = $false; OperationMasterRoles = @('SchemaMaster', 'DomainNamingMaster', 'PDCEmulator', 'RIDMaster', 'InfrastructureMaster') }
        New-Obj @{ HostName = '127.0.0.2'; Name = 'DC2'; Site = 'Branch'; IPv4Address = '127.0.0.2'; OperatingSystem = 'Windows Server 2016 Standard'; OperatingSystemVersion = '10.0 (14393)'; IsGlobalCatalog = $true; IsReadOnly = $false; OperationMasterRoles = @() }
        New-Obj @{ HostName = 'dc3.invalid'; Name = 'DC3'; Site = 'Branch'; IPv4Address = '10.255.255.1'; OperatingSystem = 'Windows Server 2012 R2 Standard'; OperatingSystemVersion = '6.3 (9600)'; IsGlobalCatalog = $false; IsReadOnly = $false; OperationMasterRoles = @() }
    )
}

function Get-ADDomain {
    [CmdletBinding()] param([string]$Identity, [string]$Server)
    New-Obj @{ NetBIOSName = 'CONTOSO'; DistinguishedName = $script:DomainDN; DomainSID = (New-Obj @{ Value = $script:Sid }); DomainMode = 'Windows2016Domain'
        PDCEmulator = 'localhost'; RIDMaster = 'localhost'; InfrastructureMaster = 'localhost' }
}

function Get-ADRootDSE {
    [CmdletBinding()] param([string]$Server)
    $offset = 0
    if ($Server -eq '127.0.0.2') { $offset = 95 }
    New-Obj @{ configurationNamingContext = "CN=Configuration,$script:DomainDN"; schemaNamingContext = "CN=Schema,CN=Configuration,$script:DomainDN"
        namingContexts = @($script:DomainDN, "CN=Configuration,$script:DomainDN", "CN=Schema,CN=Configuration,$script:DomainDN", "DC=DomainDnsZones,$script:DomainDN", "DC=ForestDnsZones,$script:DomainDN")
        currentTime = (Get-Date).ToUniversalTime().AddSeconds($offset); isSynchronized = $true }
}

function Get-ADOptionalFeature { [CmdletBinding()] param([string]$Filter, [string]$Server) New-Obj @{ Name = 'Recycle Bin Feature'; EnabledScopes = @() } }

function New-ADObj {
    param([string]$Sam, [int]$Uac = 512, [string]$Class = 'user', [hashtable]$Extra = @{})
    $h = @{ sAMAccountName = $Sam; DistinguishedName = "CN=$Sam,OU=Test,$script:DomainDN"; ObjectClass = $Class; userAccountControl = $Uac
        lastLogonTimestamp = $script:Now.AddDays(-200).ToFileTimeUtc(); operatingSystem = $null; whenCreated = $script:Now.AddYears(-3); pwdLastSet = $script:Now.AddDays(-400).ToFileTimeUtc()
        servicePrincipalName = @(); memberOf = @() }
    foreach ($k in $Extra.Keys) { $h[$k] = $Extra[$k] }
    return New-Obj $h
}

function Get-ADObject {
    [CmdletBinding()] param([string]$Identity, [string]$LDAPFilter, [string]$SearchBase, [string[]]$Properties, [string]$Server, [int]$ResultPageSize)
    if ($Identity) {
        if ($Identity -like 'CN=Directory Service*') { return New-Obj @{ tombstoneLifetime = 180 } }
        if ($Identity -like 'CN=DFSR-GlobalSettings*') { return New-Obj @{ 'msDFSR-Flags' = 48 } }
        if ($Identity -eq $script:DomainDN) { return New-Obj @{ 'ms-DS-MachineAccountQuota' = 10 } }
        throw "Mock Get-ADObject: unknown identity $Identity"
    }
    if ($SearchBase -like 'CN=Schema*') {
        if ($LDAPFilter -like '*msLAPS-PasswordExpirationTime*') { return @(New-Obj @{ Name = 'ms-LAPS-PasswordExpirationTime' }) }
        return @()
    }
    if ($LDAPFilter -like '*memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins*') { return @((New-ADObj 'admin1' -Extra @{ DistinguishedName = "CN=admin1,OU=Admins,$script:DomainDN" }), (New-ADObj 'svc_sql_admin' -Extra @{ DistinguishedName = "CN=svc_sql_admin,OU=Admins,$script:DomainDN" })) }
    if ($LDAPFilter -like '*memberOf:1.2.840.113556.1.4.1941:=CN=Schema Admins*') { return @(New-ADObj 'admin1' -Extra @{ DistinguishedName = "CN=admin1,OU=Admins,$script:DomainDN" }) }
    if ($LDAPFilter -like '*memberOf:1.2.840.113556.1.4.1941:*') { return @() }
    if ($LDAPFilter -like '*(adminCount=1)*') {
        return @(
            (New-ADObj 'admin1' 66048 -Extra @{ DistinguishedName = "CN=admin1,OU=Admins,$script:DomainDN" })
            (New-ADObj 'svc_sql_admin' 512 -Extra @{ DistinguishedName = "CN=svc_sql_admin,OU=Admins,$script:DomainDN"; servicePrincipalName = @('MSSQLSvc/sql01.contoso.test:1433') })
            (New-ADObj 'former_admin' 512)
        )
    }
    if ($LDAPFilter -like '*4194304*') { return @(New-ADObj 'legacy_app') }
    if ($LDAPFilter -like '*lastLogonTimestamp<=*' -and $LDAPFilter -like '*objectCategory=person*') { return @((New-ADObj 'olduser1'), (New-ADObj 'olduser2')) }
    if ($LDAPFilter -like '*operatingSystem=*XP*') { return @(New-ADObj 'WIN7-KIOSK$' 4096 'computer' @{ operatingSystem = 'Windows 7 Enterprise' }) }
    if ($LDAPFilter -like '*operatingSystem=Windows*' -and $LDAPFilter -like '*(!(msLAPS-PasswordExpirationTime=*))*') { return @(New-ADObj 'WS001$' 4096 'computer' @{ operatingSystem = 'Windows 11 Enterprise' }) }
    if ($LDAPFilter -eq '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))') { return @(1..50 | ForEach-Object { New-ADObj "user$_" }) }
    if ($LDAPFilter -eq '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))') { return @(1..20 | ForEach-Object { New-ADObj "PC$_`$" 4096 'computer' }) }
    return @()
}

function Get-ADReplicationPartnerMetadata {
    [CmdletBinding()] param([string]$Target, [string]$Partition, [string]$PartnerType)
    if ($Target -eq '127.0.0.2') {
        return @(New-Obj @{ Partner = "CN=NTDS Settings,CN=DC1,CN=Servers,CN=HQ,CN=Sites,CN=Configuration,$script:DomainDN"; Partition = $script:DomainDN
                LastReplicationSuccess = $script:Now.AddHours(-30); ConsecutiveReplicationFailures = 12; LastReplicationResult = 8606 })
    }
    @(New-Obj @{ Partner = "CN=NTDS Settings,CN=DC2,CN=Servers,CN=Branch,CN=Sites,CN=Configuration,$script:DomainDN"; Partition = $script:DomainDN
            LastReplicationSuccess = $script:Now.AddMinutes(-10); ConsecutiveReplicationFailures = 0; LastReplicationResult = 0 })
}

function Get-ADReplicationFailure {
    [CmdletBinding()] param([string]$Target)
    if ($Target -eq '127.0.0.2') { return @(New-Obj @{ FailureCount = 12; Partner = "CN=NTDS Settings,CN=DC1,CN=Servers,CN=HQ,CN=Sites,CN=Configuration,$script:DomainDN"; LastError = 8606; FirstFailureTime = $script:Now.AddHours(-30) }) }
    @()
}

function Get-ADReplicationAttributeMetadata {
    [CmdletBinding()] param([string]$Object, [string[]]$Properties, [string]$Server)
    $age = 2
    if ($Object -like 'DC=DomainDnsZones*') { $age = 12 }
    New-Obj @{ AttributeName = 'dSASignature'; LastOriginatingChangeTime = $script:Now.AddDays(-$age) }
}

function Get-ADTrust {
    [CmdletBinding()] param([string]$Filter, [string[]]$Properties, [string]$Server)
    @(New-Obj @{ Target = 'fabrikam.test'; Direction = 'Inbound'; IntraForest = $false; ForestTransitive = $false; SIDFilteringQuarantined = $false; TGTDelegation = $false; UsesAESKeys = $false; whenChanged = $script:Now.AddDays(-5) })
}

function Get-ADReplicationSite { [CmdletBinding()] param([string]$Filter, [string]$Server)
    @('HQ', 'Branch', 'Empty') | ForEach-Object { New-Obj @{ Name = $_; DistinguishedName = "CN=$_,CN=Sites,CN=Configuration,$script:DomainDN" } } }
function Get-ADReplicationSubnet { [CmdletBinding()] param([string]$Filter, [string[]]$Properties, [string]$Server)
    @((New-Obj @{ Name = '10.0.0.0/16'; Site = "CN=HQ,CN=Sites,CN=Configuration,$script:DomainDN" }), (New-Obj @{ Name = '10.1.0.0/16'; Site = "CN=Branch,CN=Sites,CN=Configuration,$script:DomainDN" }), (New-Obj @{ Name = '192.168.50.0/24'; Site = $null })) }
function Get-ADReplicationSiteLink { [CmdletBinding()] param([string]$Filter, [string[]]$Properties, [string]$Server)
    @(New-Obj @{ Name = 'DEFAULTIPSITELINK'; SitesIncluded = @('HQ', 'Branch'); ReplicationFrequencyInMinutes = 180 }) }

function Get-ADUser {
    [CmdletBinding()] param([string]$Identity, [string]$LDAPFilter, [string[]]$Properties, [string]$Server)
    if ($LDAPFilter) { return @(New-Obj @{ SamAccountName = 'krbtgt'; PasswordLastSet = $script:Now.AddDays(-900) }) }
    if ($Identity -like '*-500') { return New-Obj @{ PasswordLastSet = $script:Now.AddDays(-30); Enabled = $true } }
    if ($Identity -like '*-501') { return New-Obj @{ PasswordLastSet = $null; Enabled = $false } }
    throw "Mock Get-ADUser: unknown identity $Identity"
}

function Get-ADGroup {
    [CmdletBinding()] param([string]$Identity, [string]$Server)
    $names = @{ '-512' = 'Domain Admins'; '-518' = 'Schema Admins'; '-519' = 'Enterprise Admins'; '-525' = 'Protected Users'; 'S-1-5-32-544' = 'Administrators' }
    foreach ($k in $names.Keys) { if ($Identity.EndsWith($k)) { return New-Obj @{ DistinguishedName = "CN=$($names[$k]),CN=Users,$script:DomainDN"; SID = (New-Obj @{ Value = $Identity }) } } }
    if ($Identity -eq 'DnsAdmins') { return New-Obj @{ DistinguishedName = "CN=DnsAdmins,CN=Users,$script:DomainDN"; SID = (New-Obj @{ Value = "$script:Sid-1101" }) } }
    throw "Mock Get-ADGroup: not found $Identity"
}

function Get-ADDefaultDomainPasswordPolicy { [CmdletBinding()] param([string]$Server) New-Obj @{ MinPasswordLength = 8; ComplexityEnabled = $true; LockoutThreshold = 0 } }
function Get-ADFineGrainedPasswordPolicy { [CmdletBinding()] param([string]$Filter, [string]$Server) @() }

function Resolve-DnsName {
    [CmdletBinding()] param([string]$Name, [string]$Type, [switch]$DnsOnly, [switch]$QuickTimeout, [string]$Server)
    if ($Name -like '_ldap._tcp.pdc.*') { return @(New-Obj @{ Type = 'SRV'; NameTarget = 'localhost' }) }
    if ($Name -like '_gc._tcp.*') { return @((New-Obj @{ Type = 'SRV'; NameTarget = 'localhost' }), (New-Obj @{ Type = 'SRV'; NameTarget = '127.0.0.2' })) }
    # DC3 missing from locator; a decommissioned DC still registered
    @((New-Obj @{ Type = 'SRV'; NameTarget = 'localhost' }), (New-Obj @{ Type = 'SRV'; NameTarget = '127.0.0.2' }), (New-Obj @{ Type = 'SRV'; NameTarget = 'olddc.contoso.test' }))
}

Export-ModuleMember -Function *
