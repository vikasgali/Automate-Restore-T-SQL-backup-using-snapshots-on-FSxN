This script wil automate the T-SQL restore flow from the application-consistent backup created using snapshots on FSx for ONTAP filesystem and TSQL metadata backup. This will also restore transaction logs 
The script fetches the disks assigned to SQL instance/databases and maps that back to LUN and volume on FSx for ONTAP. 

# Pre-requisites: 

Some of the pre-requisites for running script are as below
1. The script expects the FSx credentails to be saved as AWS SSM parameter as a secure way of storing and retreiving credentials. 
	a. Create a parameter of type 'Secure String' with name as '/tsql/filesystem/<FSxN filesystem ID>'
	b. For value enter the fsx credentials in JSON format as {fsx:{username:'fsxadmin',password:'password'}}
2. AWS.Tools.SimpleSystemsManagement PowerShell module needs to be installed on the system where script is running.
3. The script expects the backups were taken using the script hosted at <this link>. Expectation is that ONTAP snapshot and SQL metadata backup have the same naming to map.

# Usage:

# To restore a single database that has failed to previous full state of volume snapshot:

TSQL_Restore.ps1 -FSxID <FSx filesystem ID> -FSxRegion <AWS region> -serverInstanceName <SQL Server instance name>  -databaseName <database Name> -isClustered <$True if cluster and $False if standalone> -snapshot <FSxN snapshot name> 

Example for FCI:

TSQL_Restore.ps1 -FSxID fs-07a22f282fd4f5a20 -FSxRegion eu-south-2 -serverInstanceName 'ENGINEERING' -databaseName 'Payments' -isClustered $True -snapshot 'Payments_20250514111905'


Example for Standalone:

TSQL_Restore.ps1 -FSxID fs-07a22f282fd4f5a20 -FSxRegion eu-south-2 -serverInstanceName 'MSSQLSERVER' -databaseName 'Finance' -isClustered $False -snapshot 'Finance_20250524140920'

# To restore database to a snapshot backup and all transaction logs available after that:

TSQL_Restore.ps1 -FSxID <FSx filesystem ID> -FSxRegion <AWS region> -serverInstanceName <SQL Server instance name>  -databaseName <database Name> -isClustered <$True if cluster and $False if standalone> -snapshot <FSxN snapshot name> -transactionRestore <$True to restore transaction logs, $False or skip to exclude>

Example:

TSQL_Restore.ps1 -FSxID 'fs-07a22f282fd4f5a20' -FSxRegion 'eu-south-2' -serverInstanceName 'ENGINEERING' -databaseName 'Payments' -isClustered $True -snapshot 'Payments_20250521083504' -transactionRestore $True

# To restore database to a previous snapshot backup and upto a specified transaction log backup

TSQL_Restore.ps1 -FSxID <FSx filesystem ID> -FSxRegion <AWS region> -serverInstanceName <SQL Server instance name>  -databaseName <database Name> -isClustered <$True if cluster and $False if standalone> -snapshot <FSxN snapshot name> -transactionRestore <$True to restore transaction logs, $False or skip to exclude> -tlogbackup_lastfile <last transaction log name to restore> -transaction_date <timestamp to restore up to>

Example:

TSQL_Restore.ps1 -FSxID 'fs-07a22f282fd4f5a20' -FSxRegion 'eu-south-2' -serverInstanceName 'ENGINEERING' -databaseName 'Payments' -isClustered $True -snapshot 'Payments_20250521083504' -transactionRestore $True -tlogbackup_lastfile 'Payments_20250521091525.trn' -transaction_date '2025-05-21T09:10:31'

# To restore backup for a database and restore a point-in-time from transaction log backup:

TSQL_Restore.ps1 -FSxID <FSx filesystem ID> -FSxRegion <AWS region> -serverInstanceName <SQL Server instance name>  -databaseName <database Name> -isClustered <$True if cluster and $False if standalone> -snapshot <FSxN snapshot name> -transactionRestore <$True to restore transaction logs, $False or skip to exclude> -tlogbackup_lastfile <last transaction log name to restore> -transaction_date <timestamp to restore up to>

Example:

TSQL_Restore.ps1 -FSxID 'fs-07a22f282fd4f5a20' -FSxRegion 'eu-south-2' -serverInstanceName 'ENGINEERING' -databaseName 'Payments' -isClustered $True -snapshot 'Payments_20250521083504' -transactionRestore $True -tlogbackup_lastfile 'Payments_20250521091525.trn' -transaction_date '2025-05-21T09:10:31'