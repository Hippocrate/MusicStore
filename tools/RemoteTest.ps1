param(
    [Parameter(Mandatory=$true)]
    [string] $projectFile,
    [Parameter(Mandatory=$true)]
    [string] $server,
    [string] $serverFolder="dev",
    [string] $userName,
    [string] $password
)

$pass = ConvertTo-SecureString $password -AsPlainText -Force
$cred= New-Object System.Management.Automation.PSCredential ($userName, $pass);

function Is-Elevated() {
    $user = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $user.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

Set-Item WSMan:\localhost\Client\TrustedHosts "$server" -Force
chcp 65001

$remoteScript = {
	cd C:\dev\musicstore
	dir 
	$env:DNX_TRACE=1
	.\web.cmd
}

Invoke-Command -ComputerName $server -Credential $cred -ScriptBlock $remoteScript
