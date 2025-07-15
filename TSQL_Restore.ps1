param (
    [Parameter(Mandatory = $true)]
        [string]$FSxID,
        [Parameter(Mandatory = $true)]
        [string]$FSxRegion,
        [Parameter(Mandatory = $true)]
        [string]$serverInstanceName,
        [Parameter(Mandatory = $true)]
        [string]$databaseName,
        [Parameter(Mandatory = $true)]
        [bool]$isClustered = $False,       
        [Parameter(Mandatory = $false)]
        [bool]$transactionRestore = $False,
        [Parameter(Mandatory = $true)]
        [string]$snapshot,
        [Parameter(Mandatory = $false)]
        [string]$tlogbackup_lastfile,
        [Parameter(Mandatory = $false)]
        [string]$transaction_date
)



#Get Mapped Ontap Volumes
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$responseObject = $responseObject -or @{}


# Define and create the log directory if it doesn't exist
$LogFilesPath = "C:\cfn\log"
if (-not (Test-Path -Path $LogFilesPath -PathType Container)) {
New-Item -Path $LogFilesPath -ItemType Directory
}

$includeLogVolumes = [System.Convert]::ToBoolean('false')

try {
#Requires -Module AWS.Tools.SimpleSystemsManagement

$svmOntapUuid = ''
$dblist = @()
if(-not ([string]::IsNullOrEmpty($databaseName))) {
$dblist = $databaseName.Split(",")
$databaseList = ''
$databaseqList = ''
$dblist | ForEach-Object{
   $db = $_
   $dbgroup ="["+$db+"]"
   $dbquote = "'"+$db+"'"
   if ([string]::IsNullOrEmpty($databaseList)){
      $databaseList += $dbgroup
      $databaseqList += $dbquote
      }
    else {
     $databaseList = $databaseList+','+$dbgroup
     $databaseqList = $databaseqList+','+$dbquote 
    }
   }
}

$executableInstance = "$env:COMPUTERNAME"
if ($serverInstanceName -ne 'MSSQLSERVER') {
    $executableInstance = "$env:COMPUTERNAME\$serverInstanceName"
}

if ("TrustAllCertsPolicy" -as [type]) {} else {
Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
    ServicePoint srvPoint, X509Certificate certificate,
    WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
}
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if ($connection -eq $null) {
$connection = Test-Connection -ComputerName fsx-aws-certificates.s3.amazonaws.com -Quiet -Count 1
}
if ($connection -eq $False) {
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\" -Name State -Value 146944 -Force | Out-Null
}
#The solution is expecting that FSx credentials are saved in AWS SSM parameter store to have a safe and encrypted manner of passing credentials
$SsmParameter = (Get-SSMParameter -Name "/netapp/wlmdb/$FSxID" -WithDecryption $True).Value | Out-String | ConvertFrom-Json
$FSxUserName = $SsmParameter.fsx.username
$FSxPassword = $SsmParameter.fsx.password
$FSxPasswordSecureString = ConvertTo-SecureString $FSxPassword -AsPlainText -Force
$FSxCredentials = New-Object System.Management.Automation.PSCredential($FSxUserName, $FSxPasswordSecureString)
$FSxCredentialsInBase64 = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($FSxUserName + ':' + $FSxPassword))
$FSxHostName = "management.$FSxID.fsx.$FSxRegion.amazonaws.com"

$isprivatesubnet = $connection -eq $False
if (-not $isprivatesubnet) {
$FSxCertificateificateUri = 'https://fsx-aws-Certificates.s3.amazonaws.com/bundle-' + $FSxRegion + '.pem'
$tempCertFile = (New-TemporaryFile).FullName
Invoke-WebRequest -Uri $FSxCertificateificateUri -OutFile $tempCertFile
$Certificate = Import-Certificate -FilePath $tempCertFile -CertStoreLocation Cert:\LocalMachine\Root
$regionCertificate = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Subject -like $Certificate.Subject }
Remove-Item -Path $tempCertFile -Force -ErrorAction SilentlyContinue
}

Function Invoke-ONTAPRequest {
param(
    [Parameter(Mandatory = $true)]
    [string]$ApiEndpoint,

    [Parameter(Mandatory = $false)]
    [string]$ApiQueryFilter = '',

    [Parameter(Mandatory = $false)]
    [string]$ApiQueryFields = '',

    [Parameter(Mandatory = $false)]
    [string]$method = 'GET',

    [Parameter(Mandatory = $false)]
    [hashtable]$body
)


if (-not ([string]::IsNullOrEmpty($ApiQueryFilter))) {

$Params = @{
    "URI"     = 'https://' + $FSxHostName + '/api' + $ApiEndpoint + '?' + $ApiQueryFilter + '&' + $ApiQueryFields
    "Method"  = $method
    "Headers" =@{"Authorization" = "Basic $FSxCredentialsInBase64"}
    "ContentType" = "application/json"
 }
} else {
    $Params = @{
    "URI"     = 'https://' + $FSxHostName + '/api' + $ApiEndpoint
    "Method"  = $method
    "Headers" =@{"Authorization" = "Basic $FSxCredentialsInBase64"}
    "ContentType" = "application/json"
 }   
}
if (-not ([string]::IsNullOrEmpty($body))) {
    $jsonbody = ConvertTo-JSON $body
    $Params.Add("Body", $jsonbody)
}
       $paybod = ConvertTo-JSON $body
        $payload = ConvertTo-JSON $Params -Depth 5


if ($isprivatesubnet -eq $False -and $regionCertificate -ne $null) {
    try {
    return Invoke-RestMethod @Params -Certificate $regionCertificate
    } catch { Write-Host "Failed to execute ONTAP REST command $_"}
} else {
    return Invoke-RestMethod @Params
}
}

Function Get-VolumeIdsList($sqlqueryresponse) {        
        $sqlJsonResponse = $sqlqueryresponse | convertFrom-Json
        $volumeIds = @()
        foreach ($record in $sqlJsonResponse) {    
            if ($null -ne $record.volumeId) {
                $cleanVolumeId = $record.volumeId.Replace(" ", "").Replace("`r","").Replace("`n","")
                if ($volumeIds -notcontains $cleanVolumeId) {
                    $volumeIds += $cleanVolumeId
                }
            }
        }
        $volumeIds
    }

Function Get-SerialNumberOfWinVolumes($winvolumes) {
        try {
            $Lunserialnumbers = @()
            $VolumeSerialMapping = @{}
            $BusTypes = @()

            
            $allDisks = Get-Disk | Select SerialNumber, Number, BusType

            foreach ($volumeid in $winvolumes) {
                if ($null -eq $volumeid) {
                    Write-output "Skipping volume with null volumeid"
                    continue
                }

                $vol = Get-Volume -Path $volumeid | Get-Partition | Where-Object DiskNumber -in $allDisks.Number
                $serialNumber = $allDisks | Where-Object Number -eq $vol.DiskNumber | Select -ExpandProperty SerialNumber
                $BusType = $allDisks | Where-Object Number -eq $vol.DiskNumber | Select -ExpandProperty BusType

                $VolumeSerialMapping[$volumeid] = $serialNumber
                $Lunserialnumbers += $serialNumber
                $BusTypes += $BusType
            }

            $Lunserialnumbers = $Lunserialnumbers | where { -not $_.StartsWith('vol') } | select -Unique
            if ($Lunserialnumbers.count -eq 0 -and $BusTypes.Count -gt 0 -and  $BusTypes -notcontains 'iSCSI') {
                throw "Only iSCSI volumes are supported"
            }

            return @{
                Lunserialnumbers = $Lunserialnumbers | select -Unique
                VolumeSerialMapping = $VolumeSerialMapping
            }
        }
        catch {
            throw "An error occurred while getting the serial numbers of Windows volumes: $_"
        }
    }

Function Get-LunFromSerialNumber($SerialNumbers, $VolumeSerialMapping) {
        Write-output "Get ONTAP lun name from serial numbers for: $VolumeSerialMapping"

        $QueryFilter = ''
        foreach ($SerialNumber in $SerialNumbers) {
            if ($SerialNumber -ne '') {
                $QueryFilter += [System.Web.HttpUtility]::UrlEncode($SerialNumber) + '|'
            }
        }
        
        $QueryFilter = $QueryFilter.TrimEnd('|')

        $Params = @{
            "ApiEndPoint" = "/storage/luns"
            "method" = "GET"
        }

        [string[]]$LunNames = @()
        $VolumeLunMapping = @{}
        $LunNameUUIDMap = @{}
        if ($QueryFilter -ne '') {
            $Params += @{
                "ApiQueryFilter" = "serial_number=$QueryFilter"
                "ApiQueryFields" = "fields=uuid,name,serial_number,lun_maps.igroup,svm"
                }
            $Response = Invoke-ONTAPRequest @Params
            $LunRecords = $Response.records

            Write-Host "Lun Records  Mapping: $($LunRecords | ConvertTo-Json)"

            foreach ($record in $LunRecords) {
                $LunNames += $record.name
                foreach ($volumeId in $VolumeSerialMapping.Keys) {
                    if ($VolumeSerialMapping[$volumeId] -eq $record.serial_number) {
                        $lunName = $record.name -replace '^\/vol\/(.*?)\/.*$', '$1'
                        $VolumeLunMapping[$volumeId] = $lunName
                        $LunNameUUIDMap[$record.uuid] = @{
                            "Path" = $record.name
                            "igroupUUID" = $record.lun_maps.igroup.uuid
                            "igroupName" = $record.lun_maps.igroup.name
                            "svm" = $record.svm.name
                        }
                    }
                }
            }
        }
 
        return @{
            LunNames = $LunNames
            VolumeLunMapping = $VolumeLunMapping
            LunNameUUIDMap = $LunNameUUIDMap
        }
    }

Function Get-VolumeIdFromName($Names, $volumeLunMapping) {
        Write-output "Get Volume Id from name: $Names"

        $QueryFilter = ''
        foreach ($Name in $Names) {
            if ($Name -ne '') {
                $QueryFilter += [System.Web.HttpUtility]::UrlEncode($Name) + '|'
            }
        }
        $QueryFilter = $QueryFilter.TrimEnd('|')


        $Params = @{
            "ApiEndPoint" = "/storage/volumes"
            "method" = "GET"
        }

        if ($QueryFilter -ne '') {
            $Params += @{"ApiQueryFilter" = "name=$QueryFilter"}
        
            $Response = Invoke-ONTAPRequest @Params
            $VolumeNameMapping = @{}
            foreach ($record in $Response.records) {
                foreach ($volumeId in $volumeLunMapping.Keys) {
                    if ($volumeLunMapping[$volumeId] -eq $record.name) {
                        $VolumeNameMapping[$volumeId] = @{
                            "uuid" = $record.uuid
                            "name" = $record.name
                        }
                    }
                }
            }
        }
        

        return @{
            Response = $Response
            volumeNameMapping = $VolumeNameMapping
        }
    }

Function Restore-ONTAPSnapshot($volumeUUID,$volumeName,$snapshot,$action) {
       
        if ($action -eq 'CREATE') {
        Write-Host "Creating snapshot $snapshot on the volume $volumeName "
        $Params = @{
            "ApiEndPoint" = "/storage/volumes/$volumeUUID/snapshots"
            "method" = "POST"
            "ApiQueryFields" = "return_records=true"
            "body" = @{
                "name" = "$snapshot"
                "comment" = "TSQL backup pre-restore snapshot"
            }
             }
        
        }

        else {
        Write-Host "Restoring snapshot $snapshot on the volume $volumeName" 

        $Params = @{
            "ApiEndPoint" = "/storage/volumes/$volumeUUID"
            "method" = "PATCH"
            "body" = @{
                "restore_to.snapshot.name" = "$snapshot"
                }
            }
        }
            
            Write-output $Params
            $Response = Invoke-ONTAPRequest @Params
            Write-output $Response
            return($Response)


    }

Function ONTAP-LUNMapping($lunUUID,$igroupUUID,$lunPath,$igroupName,$svm,$action) {
 
        $MapParams = @{
            "ApiEndPoint" = "/protocols/san/lun-maps"
            "method" = "POST"
            "body" = @{
                "igroup.name" = "$igroupName"
                "lun.name" = "$lunPath"
                "svm.name" = "$svm"
            }
        }
        

        $UnmapParams = @{
            "ApiEndPoint" = "/protocols/san/lun-maps/$lunUUID/$igroupUUID"
            "method" = "DELETE"
            "body" = @{
                "igroup.name" = "$igroupName"
                "lun.name" = "$lunPath"
            }
        }

        if($action -eq 'map') {
            Write-output "Mapping LUN $lunPath to igroup $igroupName"
            $Response = Invoke-ONTAPRequest @MapParams
            Write-output $Response
            return($Response)
         }   
         elseif($action -eq 'unmap') {
            Write-output "Unmapping LUN $lunPath from igroup $igroupName"
            $Response = Invoke-ONTAPRequest @UnmapParams
            Write-output $Response
            return($Response)
         } 

    }    

Function Get-VolumeIdFromPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$absolutePath
    )
    $pattern = '{(.+)}'
    if ($absolutePath -match $pattern) {
         $volumeID= $matches[1]
         Write-Host $volumeID
    }
    else {
        throw "Could not find VolumeID for $absolutePath"
    }
    return $volumeID
}

Function Remove-SQLDependency($instanceName,$DBName,$volPaths) {
    try {
        

        if ($volPaths.count -ne 0) {
            $query = "set nocount on; SELECT DB_NAME(dbid) as DBName, COUNT(dbid) as NumberOfConnections FROM sys.sysprocesses WHERE DB_NAME(dbid) = '$DBName' GROUP BY dbid FOR JSON PATH"

            $sqlres = sqlcmd -Q $query -y 0

            if (-not [string]::IsNullOrEmpty($sqlres)) {
                Write-Information "$logPrefix Database $dbname is in use"
                $responseObject['error'] = 'SQLServerError: Database $dbname is in use'
                return $responseObject | ConvertTo-Json -Depth 5
            }

            $clusterServiceStatus = (Get-Service -Name clussvc -ErrorAction SilentlyContinue).Status
            if ($instanceName -eq 'MSSQLSERVER') {
                $resourceType  = 'SQL Server'
            } else {
                $resourceType  = 'SQL Server (' + $instanceName + ')'
            }


            $windowsVolumeIds = $volPaths | ForEach-Object {        
                Get-VolumeIdFromPath -absolutePath $_                
            } | Sort-Object -Unique

            Write-Information "$logPrefix Windows Volume Ids: $windowsVolumeIds"
            if ($clusterServiceStatus -eq 'Running') {
                $sqlgroup = Get-ClusterResource | Where-Object Name -eq $resourceType
                $sqlserver = Get-WmiObject -namespace root\MSCluster MSCluster_Resource -filter "Name='$sqlgroup'"
                $resourcegroup = $sqlserver.GetRelated() | Where Type -eq 'Physical Disk'
                Write-Host "Resource Group: $resourcegroup"

                Write-Host "Resource type: $resourceType  Server resource:$sqlserver"
                $clusterdisksToRemove = @()
                foreach ($resource in $resourcegroup) {
                    $disks = $resource.GetRelated("MSCluster_Disk")
                    foreach ($disk in $disks) {
                        $diskpart = $disk.GetRelated("MSCluster_DiskPartition")
                        $clusterdisk = ($resource.name).replace('\\r\\n','')
                        $diskdrive = $diskpart.path
                        $disklabel = $diskpart.volumelabel
                        $diskvolume = $diskpart.VolumeGuid
                        if ($windowsVolumeIds -contains $diskpart.VolumeGuid) {
                            $clusterdisksToRemove += $clusterdisk
                        }
                    }
                }

                Write-Information "$logPrefix Cluster Disks to remove $clusterdisksToRemove"
                if ($clusterdisksToRemove.count -ne 0) {
                    $clusterdisksToRemove | ForEach-Object {
                        $diskToRemove = $_
                        $diskToRemove = $diskToRemove.ToString()
                        write-Information "$logPrefix Removing disk $diskToRemove"
                        $null = (Remove-ClusterResourceDependency -Resource $resourceType -Provider $diskToRemove)
                    }
                return($clusterdisksToRemove)     
                }   
            }
        }

    }  catch {
        Write-Host "$logPrefix An error occurred while removing SQL dependency: $_.Exception.Message"
        $responseObject['error'] = 'SQLServerError: $_.Exception.Message'
        return $responseObject | ConvertTo-Json -Depth 5
    }
}   

Function Get-AvalilableTLogBackups{
    param(
        [Parameter(Mandatory = $true)]
        [string]$executableInstance,
        [Parameter(Mandatory = $true)]
        [string]$databaseName,
        [Parameter(Mandatory = $true)]
        [string]$snapshot

    )
    $Dblisterrlog = "C:\cfn\log\dblist_err.log"

    $sqlqueryfortlogbackuplist = @"
    SET NOCOUNT ON;
    DECLARE @JSONData nvarchar(max)
    SET @JSONData = (SELECT 
        bs.database_name,
		bs.backup_finish_date,
        bm.physical_device_name
    FROM 
        msdb.dbo.backupset bs
    INNER JOIN 
        msdb.dbo.backupmediafamily bm ON bs.media_set_id = bm.media_set_id
    WHERE 
        bm.physical_device_name LIKE  '%$snapshot%' AND bs.database_name = '$databaseName'
    FOR JSON PATH)
    SELECT @JSONData;
"@


try{
$sqlqueryresponse =  (sqlcmd -S $executableInstance -Q $sqlqueryfortlogbackuplist -y 0 -r1 2> $Dblisterrlog)
 if (Get-Content $Dblisterrlog) { throw }
 $sqlJsonResponse = $sqlqueryresponse | convertFrom-Json
Write-Output $sqlJsonResponse
$backup_finishtime = $sqlJsonResponse.backup_finish_date

Write-Output "$backup_finishtime"

    }
    catch {
       Write-Output "Failed to get backup details from msdb: $($_.Exception.Message )"
       $Errordetails = Get-Content $Dblisterrlog
       Write-Output $Errordetails
    }
 
 
    $tlogbackupquery = @"
    SET NOCOUNT ON;
    DECLARE @JSONData nvarchar(max)
    DECLARE @BackupDate DATETIME = '$backup_finishtime';
    SET @JSONData = (

SELECT 
    bs.database_name,
    bs.backup_start_date,
    bs.backup_finish_date,
	bs.type,
    bs.recovery_model,
    bm.physical_device_name
FROM 
    msdb.dbo.backupset bs
INNER JOIN 
    msdb.dbo.backupmediafamily bm ON bs.media_set_id = bm.media_set_id
WHERE 
    bs.backup_start_date > @BackupDate  AND bs.type = 'L'
    FOR JSON PATH)
    SELECT @JSONData;
"@

try{
$tbkpqueryresponse =  (sqlcmd -S $executableInstance -Q $tlogbackupquery -y 0 -r1 2> $Dblisterrlog)
 if (Get-Content $Dblisterrlog) { throw }
 $tlogJsonResponse = $tbkpqueryresponse | convertFrom-Json

$tlogbackups = @()
$sortedRecords = $tlogJsonResponse | Sort-Object {[datetime]::Parse($_.backup_finish_date)}
$tlogbackups = $sortedRecords | ForEach-Object { $_.physical_device_name }


Write-Output "$tlogbackups"
return $tlogbackups
    }
    catch {
       Write-Output "Failed to get transaction backup list from msdb: $($_.Exception.Message )!"
       $Errordetails = Get-Content $Dblisterrlog
       Write-Output $Errordetails
    } 


}
$instanceRespones = @{}

try {

if(-not ([string]::IsNullOrEmpty($databaseName))) {
    $sqlqueryfordatabaseandvolumelist = @"
                SET NOCOUNT ON;
                DECLARE @JSONData nvarchar(max)
                SET @JSONData = (SELECT DISTINCT 
                    DB_NAME(mf.database_id) AS DatabaseName,
                    vs.logical_volume_name as VolumeName,
                    vs.volume_id as VolumeId
                FROM 
                    sys.master_files AS mf
                INNER JOIN 
                    sys.databases d ON mf.database_id = d.database_id
                CROSS APPLY 
                    sys.dm_os_volume_stats(mf.database_id, mf.[file_id]) AS vs
                WHERE 
                    vs.volume_mount_point collate SQL_Latin1_General_CP1_CI_AS != 'C:\'
                    AND REVERSE(SUBSTRING(REVERSE(mf.physical_name), 1, 3)) in ('mdf','ndf','ldf')
                    AND d.name collate SQL_Latin1_General_CP1_CI_AS IN ($databaseqList)
                FOR JSON PATH)
                SELECT @JSONData;
"@
} else {
    $sqlqueryfordatabaseandvolumelist = @"
                SET NOCOUNT ON;
                DECLARE @JSONData nvarchar(max)
                SET @JSONData = (SELECT DISTINCT 
                    DB_NAME(mf.database_id) AS DatabaseName,
                    vs.logical_volume_name as VolumeName,
                    vs.volume_id as VolumeId
                FROM 
                    sys.master_files AS mf
                INNER JOIN 
                    sys.databases d ON mf.database_id = d.database_id
                CROSS APPLY 
                    sys.dm_os_volume_stats(mf.database_id, mf.[file_id]) AS vs
                WHERE 
                    vs.volume_mount_point collate SQL_Latin1_General_CP1_CI_AS != 'C:\'
                    AND REVERSE(SUBSTRING(REVERSE(mf.physical_name), 1, 3)) in ('mdf','ndf','ldf')
                FOR JSON PATH)
                SELECT @JSONData;
"@

}
    $MappedVolumesErrorFile = "C:\cfn\log\mapped_volumes_err_$serverInstanceName_$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds().toString()).log"
    $Dblisterrlog = "C:\cfn\log\dblist_err.log"
    try {
    $sqlqueryresponse =  (sqlcmd -S $executableInstance -Q $sqlqueryfordatabaseandvolumelist -y 0 -r1 2> $Dblisterrlog) 
    if (Get-Content $Dblisterrlog) { throw }
    }
    catch {
       Write-Output "Failed to get mapping for disks: $_. Check if database is in running state!"
       Write-Output $sqlqueryresponse
    }


    $volumeIds = Get-VolumeIdsList $sqlqueryresponse


    $result = Get-SerialNumberOfWinVolumes $volumeIds
    $SerialNumbers = $result.Lunserialnumbers

    $lunResult = Get-LunFromSerialNumber $SerialNumbers $result.VolumeSerialMapping

    $VolumeNames = $lunResult.LunNames
    #Write-output "LUNs: $($VolumeNames |ConvertTo-Json)" 
    $volumeLunMapping = $lunResult.VolumeLunMapping
    
    if (!($VolumeNames.count -gt 0)) {
        throw "Couldn't get associated Ontap LUN volume names"
    }

    $volumeResult = Get-VolumeIdFromName $VolumeNames $volumeLunMapping
    $volumes = $volumeResult.Response
    $volumeNameMapping = $volumeResult.volumeNameMapping
    $LunUUIDMap = $lunResult.LunNameUUIDMap
    #Write-output "Volume Ids: $($volumes | ConvertTo-Json)"
    #Write-output "LUN Ids: $($LunUUIDMap | ConvertTo-Json)"

      $sqlConn = New-Object System.Data.SQLClient.SQLConnection
      # Open SQL Server connection to master
      $sqlConn.ConnectionString = "server='" + $executableInstance +"';database='master';Integrated Security=True;"
      $sqlConn.Open()
      $Command = New-Object System.Data.SQLClient.SQLCommand
      $Command.Connection = $sqlConn

      $SQLParams= @{
         "Action" = 'suspend'
         "Conn" = $sqlConn
         "cmdsession" = $Command
         "BackupType" = $backup_type
      }
 

                    
    #Offline the database(s)
    try {
        Write-Output "Putting database $databaseName offline for restore"

        $offlinedatabases= "ALTER DATABASE ["+$databaseName+"] SET OFFLINE WITH ROLLBACK IMMEDIATE"
        $Command.CommandText = $offlinedatabases
        $Command.ExecuteNonQuery() | Out-Null
        Write-Output "Database $databaseName is now offline"
        Write-Output $offlinedatabases
    } catch {
       Write-Output "Failed to offline database! Retry after sometime"
       exit 1 
    }



    #Create tail backup for the database(s) and pre-restore snapshot on FSxN
    $timestamp = (Get-Date -Format "yyyyMMddHHmmss")
    try {
        Write-Output "Taking tail log backup for database $databaseName"
        $tailbackup = $snapshot+'_'+$timestamp+'_taillog.bkm'

        $sqlbackuptail = "BACKUP LOG "+$databaseList+" TO DISK = '"+$tailbackup+"' WITH NORECOVERY;"
        $Command.CommandText = $offlinedatabases
        $Command.ExecuteNonQuery() | Out-Null
        Write-Output "Database $databaseName is now offline"
        Write-Output $offlinedatabases
    } catch {
       Write-Output "Failed to take tail log backup"
    }
     

    #Remove disks from Windows cluster disks if clustered
    if ($isClustered -eq $True) {
        Write-Output "Removing database $databaseName from cluster disks"
        $sqlclusterdisks = Remove-SQLDependency $serverinstanceName $databaseName $volumeIds
        Write-Output "Disks for database $databaseName is now removed from SQL server dependency"
        Write-Output $sqlclusterdisks
        }
    
    #Unmap LUNs from the cluster
    foreach ($Lun in $LunUUIDMap.GetEnumerator()) {
        $lunUUID = $($Lun.Key)
        $lunPath = $($Lun.Value).Path
        $igroupName = $($Lun.Value).igroupName
        $igroupUUID = $($Lun.Value).igroupUUID
        $svmname = $($Lun.Value).svm
        $unmapLun = ONTAP-LUNMapping $lunUUID $igroupUUID $lunPath $igroupName $svmname 'unmap'
        Write-Output "Unmapped LUN $lunPath ($lunUUID) from cluster disks from igroup $igroupName ($igroupUUID)"
        Write-Output $unmapLun 
    }   



    #Restore snapshot for all the volumes

     foreach ($record in $volumes.records) {
           $volumeUUID = $record.uuid
           $volumeName = $record.name
           Write-output "Restoring snapshot for $volumeName ($volumeUUID)"
           try {
                $snapshotResult = Restore-ONTAPSnapshot $volumeUUID $volumeName $snapshot 'RESTORE'
            } catch {
                Write-Output "Snapshot restore failed for volume $volumeName. Aborting restore process"
                exit 1

            }

        }
    Start-Sleep -Seconds 2
    #Map back LUNs from the cluster
    foreach ($Lun in $LunUUIDMap.GetEnumerator()) {
        $lunUUID = $($Lun.Key)
        $lunPath = $($Lun.Value).Path
        $igroupName = $($Lun.Value).igroupName
        $igroupUUID = $($Lun.Value).igroupUUID
        $svmname = $($Lun.Value).svm
        $unmapLun = ONTAP-LUNMapping $lunUUID $igroupUUID $lunPath $igroupName $svmname 'map'
        Write-Output "Mapped LUN $lunPath ($lunUUID) from cluster disks to igroup $igroupName ($igroupUUID)"
        Write-Output $mapLun 
    }   
    Start-Sleep -Seconds 2

    #Rescan disks
    echo "RESCAN" | diskpart 
    
    #Add back disk to cluster and SQL Server dependency
    if ($isClustered -eq $True) {
        Write-Output "Adding cluster disks of database $databaseName to SQL server"
        if ($serverInstanceName -eq 'MSSQLSERVER') {
                $SQLresource  = 'SQL Server'
        } else {
                $SQLresource  = 'SQL Server (' + $serverInstanceName + ')'
            }
        $sqlclusterdisks | ForEach-Object {
            $diskToAdd = $_
            $diskToAdd = $diskToAdd.ToString()
            write-Host "Adding back disk $diskToAdd"
            Start-ClusterResource -Name $diskToAdd

            Add-ClusterResourceDependency -Resource $SQLresource -Provider $diskToAdd
        }
        Write-Output "Disks for database $databaseName is now added to SQL server dependency"
     }
    Start-Sleep -Seconds 20
    
    #Restore metadata backup on SQL server

    $metabackup = $snapshot+'.bkm'
    if ($transactionRestore -eq $True) {
            Write-Output "Restoring metadatabackup with NORECOVERY for database $databaseName"
            $sqlbackupquery = "RESTORE DATABASE  "+$databaseList+" FROM DISK = '"+$metabackup+"' WITH METADATA_ONLY, NORECOVERY;"
            try {
                $sqlbackupresponse = $Command.ExecuteNonQuery();
                Write-output "Successfully restored database - $databaseName"
            } catch {
                Write-Output "Failed to restore metadata backup database(s) $databaseName for backup $metabackup!"
                exit 1
            }
        
            Write-Output "Restoring transaction log backup for database $databaseName"  
            $tlogs_to_restore = Get-AvalilableTLogBackups $executableInstance $databaseName $snapshot
            $totalRecords = $tlogs_to_restore.count
            $counter = 0
            $tlogs_to_restore | ForEach-Object {
                $tlog = $_
                $counter++
                Write-Output "Restoring transaction log backup $counter of $totalRecords"

                if (($counter -eq $totalRecords) -Or ((-not [string]::IsNullOrEmpty($tlogbackup_lastfile)) -And ($tlog -match $tlogbackup_lastfile))) {
                    if([string]::IsNullOrEmpty($transaction_date)){
                        $sqlbackupquery = "RESTORE LOG "+$databaseName+" FROM DISK = '"+$tlog+"' WITH FILE = 1,  NOUNLOAD,  STATS = 5, RECOVERY;"
                    } else {
                        Write-Output "Recovering point-in-time to provided transaction timestamp $transaction_date fromm $tlog"
                        $sqlbackupquery = "RESTORE LOG "+$databaseName+" FROM DISK = '"+$tlog+"' WITH FILE = 1,  NOUNLOAD,  STATS = 5, STOPAT = N'$transaction_date';"
                    }
                    }
                else {
                $sqlbackupquery = "RESTORE LOG "+$databaseName+" FROM DISK = '"+$tlog+"' WITH FILE = 1,  NOUNLOAD,  STATS = 5, NORECOVERY;"
                }
                Write-output $sqlbackupquery
                $Command.CommandText = $sqlbackupquery
                try {
                    $sqlbackupresponse = $Command.ExecuteNonQuery();
                    Write-output "Successfully restored transaction log backup - $tlog"
                } catch {
                      Write-Output "Failed to restore transaction log backup $tlog on database $databaseName!"
                      exit 1
                    }                    
                }

            }
       
    else {
    $sqlbackupquery = "RESTORE DATABASE  "+$databaseList+" FROM DISK = '"+$metabackup+"' WITH REPLACE,METADATA_ONLY;"

    Write-output $sqlbackupquery
    $Command.CommandText = $sqlbackupquery
    try {
        $sqlbackupresponse = $Command.ExecuteNonQuery();
        Write-output "Successfully restored database - $databaseName"
        } catch {
          Write-Output "Failed to restore metadata backup database(s) $databaseName for snapshot $snapshot!"
          Write-Output "Resuming databases explicitly in case metadata backup failure failed to unfreeze"

          if ($sqlConn.State -eq [System.Data.ConnectionState]::Open) {
                        $sqlConn.Close()
                     }
                    # Dispose of the connection and command objects
                    $sqlConn.Dispose()
                    $Command.Dispose()
        }
    }
    #Online the database
    try {
        Write-Output "Putting database $databaseName online after restore"

        $onlinedatabases= "ALTER DATABASE ["+$databaseName+"] SET ONLINE"
        $Command.CommandText = $onlinedatabases
        $Command.ExecuteNonQuery() | Out-Null
        Write-Output "Database $databaseName is now online"
        Write-Output $onlinedatabases
    } catch {
       Write-Output "Failed to online database! Retry after sometime"
       exit 1 
    }

    $sqlConn.Close()
    $sqlConn.Dispose()
    $Command.Dispose()


    $responseObject = @{
        volumes = $processedRecords
    }
    $instanceRespones[$serverInstanceName] = $responseObject
} catch {
    Write-Information "An error occurred while processing the records: $_.Exception.Message"
    $instanceRespones[$serverInstanceName] = "error: $_"
}


return 
} catch {
Write-Host "Failed to execute: $_"
return $_.Exception.Message
} 
 
 
