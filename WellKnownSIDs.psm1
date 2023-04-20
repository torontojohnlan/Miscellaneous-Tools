class wellKnownPrincipals{
    static [string[]] $wellKnownSIDs=@(
        "S-1-5-1"
        "S-1-5-113"
        "S-1-5-114"
        "S-1-5-2"
        "S-1-5-3"
        "S-1-5-4"
        "S-1-5-6"
        "S-1-5-7"
        "S-1-5-8"
        "S-1-5-9"
        "S-1-5-10"
        "S-1-5-11"
        "S-1-5-12"
        "S-1-5-13"
        "S-1-5-14"
        "S-1-5-15"
        "S-1-5-17"
        "S-1-5-18"
        "S-1-5-19"
        "S-1-5-20"
        "S-1-5-32-544"
        "S-1-5-32-545"
        "S-1-5-32-546"
        "S-1-5-32-547"
        "S-1-5-32-548"
        "S-1-5-32-549"
        "S-1-5-32-550"
        "S-1-5-32-551"
        "S-1-5-32-552"
        "S-1-5-32-554"
        "S-1-5-32-555"
        "S-1-5-32-556"
        "S-1-5-32-557"
        "S-1-5-32-558"
        "S-1-5-32-559"
        "S-1-5-32-560"
        "S-1-5-32-561"
        "S-1-5-32-562"
        "S-1-5-32-568"
        "S-1-5-32-569"
        "S-1-5-32-573"
        "S-1-5-32-574"
        "S-1-5-32-575"
        "S-1-5-32-576"
        "S-1-5-32-577"
        "S-1-5-32-578"
        "S-1-5-32-579"
        "S-1-5-32-580"
        "S-1-5-64-10"
        "S-1-5-64-14"
        "S-1-5-64-21"
        "S-1-5-80"
        "S-1-5-80-0"
        "S-1-5-83-0"
    )
    static [string[]] $wellKnownRIDs=@(
        "500"
        "501"
        "502"
        "512"
        "513"
        "514"
        "515"
        "516"
        "517"
        "518"
        "519"
        "520"
        "544"
        "545"
        "546"
        "547"
        "551"
        "552"
        "553"
    )
    static [string[]] $builtinADGroups=@(
        "Access Control Assistance Operators",
        "Account Operators",
        "Administrators",
        "Allowed RODC Password Replication",
        "Backup Operators",
        "Certificate Service DCOM Access",
        "Cert Publishers",
        "Cloneable Domain Controllers",
        "Cryptographic Operators",
        "Denied RODC Password Replication",
        "Device Owners",
        "DHCP Administrators",
        "DHCP Users",
        "Distributed COM Users",
        "DnsUpdateProxy",
        "DnsAdmins",
        "Domain Admins",
        "Domain Computers",
        "Domain Controllers",
        "Domain Guests",
        "Domain Users",
        "Enterprise Admins",
        "Enterprise Key Admins",
        "Enterprise Read-only Domain Controllers",
        "Event Log Readers",
        "Group Policy Creator Owners",
        "Guests",
        "Hyper-V Administrators",
        "IIS_IUSRS",
        "Incoming Forest Trust Builders",
        "Key Admins",
        "Network Configuration Operators",
        "Performance Log Users",
        "Performance Monitor Users",
        "Pre–Windows 2000 Compatible Access",
        "Print Operators",
        "Protected Users",
        "RAS and IAS Servers",
        "RDS Endpoint Servers",
        "RDS Management Servers",
        "RDS Remote Access Servers",
        "Read-only Domain Controllers",
        "Remote Desktop Users",
        "Remote Management Users",
        "Replicator",
        "Schema Admins",
        "Server Operators",
        "Storage Replica Administrators",
        "System Managed Accounts",
        "Terminal Server License Servers",
        "Users",
        "Windows Authorization Access",
        "WinRMRemoteWMIUsers_"
    )

    static [boolean] isWellKnown([string]$s,[string]$type){
        if($type -eq "SID"){
            if($s -in [wellKnownPrincipals]::wellKnownSIDs){return $true} # found in known SID list
            if($s -notmatch "S-\d{1}-(\d{1,14}-)+(?<RID>\d{1,14})$") {throw "$s is not a valid SID"} # not a valid SID. Ideally exception should be thrown here
            else{if($Matches.RID -in [wellKnownPrincipals]::wellKnownRIDs) {return $true}}
            return $false
        }
        elseif($type -eq "name"){
            if($s -in [wellknownPrincipals]::builtinADGroups){ return $true}
            else {return $false}
        }
        else { throw "invalid comparison type"}
    }
}
