# Check-NTLM.ps1

$results = @()
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"

if (Test-Path $lsaPath) {
    # Authentication Level
    $minClient = Get-ItemProperty -Path $lsaPath -Name "NtlmMinClientSec" -ErrorAction SilentlyContinue
    $minServer = Get-ItemProperty -Path $lsaPath -Name "NtlmMinServerSec" -ErrorAction SilentlyContinue
    
    $clientVal = if ($minClient) { $minClient.NtlmMinClientSec } else { "Default" }
    $serverVal = if ($minServer) { $minServer.NtlmMinServerSec } else { "Default" }
    
    $results += [PSCustomObject]@{
        CheckName = "NTLM - Min Client Security"
        Value     = "$clientVal"
        Details   = "0x0=None, 0x80000=NTLMv2"
        RawData   = $clientVal
    }
    
    $results += [PSCustomObject]@{
        CheckName = "NTLM - Min Server Security"
        Value     = "$serverVal"
        Details   = "0x0=None, 0x80000=NTLMv2"
        RawData   = $serverVal
    }
    
    # Restrictions
    $restrictSend = Get-ItemProperty -Path $lsaPath -Name "RestrictSendingNTLMTraffic" -ErrorAction SilentlyContinue
    $restrictRecv = Get-ItemProperty -Path $lsaPath -Name "RestrictReceivingNTLMTraffic" -ErrorAction SilentlyContinue
    
    $sendVal = if ($restrictSend) { $restrictSend.RestrictSendingNTLMTraffic } else { "Default (Allow)" }
    $recvVal = if ($restrictRecv) { $restrictRecv.RestrictReceivingNTLMTraffic } else { "Default (Allow)" }
    
    $results += [PSCustomObject]@{
        CheckName = "NTLM - Restrict Sending"
        Value     = "$sendVal"
        Details   = "0=Allow, 1=Audit, 2=Deny"
        RawData   = $sendVal
    }
    
    $results += [PSCustomObject]@{
        CheckName = "NTLM - Restrict Receiving"
        Value     = "$recvVal"
        Details   = "0=Allow, 1=Audit, 2=Deny"
        RawData   = $recvVal
    }
}
else {
    $results += [PSCustomObject]@{
        CheckName = "NTLM Settings"
        Value     = "Key Missing"
        Details   = "LSA\MSV1_0 key not found"
        RawData   = $null
    }
}

return $results
