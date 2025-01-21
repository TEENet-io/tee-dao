#Requires -Version 7
#Requires -PSEdition Core
#source[https://thomasvanlaere.com/posts/2023/03/azure-confidential-computing-verifying-microsoft-azure-attestation-jwt-tokens/]

<#
.SYNOPSIS
    Validates a JSON web signature, supports RSA and ECDsa.
.DESCRIPTION
    Validates a JSON web signature, takes one argument, "Jwt," and validates a JSON web signature using RSA or ECDsa algorithms.
.PARAMETER -Jwt
    JWT consist of three parts: a header, a payload, and a signature.
.INPUTS
    None.
.OUTPUTS
    System.Management.Automation.PSObject
.EXAMPLE
    PS C:\> .\Confirm-AttestationTokenSignature.ps1 -Jwt "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vc2hhcmVkd2V1LndldS5hdHRlc3QuYXp1cmUubmV0L2NlcnRzIiwia2lkIjoiZFJLaCtoQmNXVWZRaW1TbDNJdjZaaFN0VzNUU090MFRod2lUZ1VVcVpBbz0iLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2NzE4NjUyMTgsImlhdCI6MTY3MTgzNjQxOCwiaXNzIjoiaHR0cHM6Ly9zaGFyZWR3ZXUud2V1LmF0dGVzdC5henVyZS5uZXQiLCJqdGkiOiJjZTM5NWU1ZGU5YzYzOGQzODRjZDNiZDA2MDQxZTY3NGVkZWU4MjAzMDU1OTZiYmEzMDI5MTc1YWYyMDE4ZGEwIiwibmJmIjoxNjcxODM2NDE4LCJzZWN1cmVib290Ijp0cnVlLCJ4LW1zLWF0dGVzdGF0aW9uLXR5cGUiOiJhenVyZXZtIiwieC1tcy1henVyZXZtLWF0dGVzdGF0aW9uLXByb3RvY29sLXZlciI6IjIuMCIsIngtbXMtYXp1cmV2bS1hdHRlc3RlZC1wY3JzIjpbMCwxLDIsMyw0LDUsNiw3XSwieC1tcy1henVyZXZtLWJvb3RkZWJ1Zy1lbmFibGVkIjpmYWxzZSwieC1tcy1henVyZXZtLWRidmFsaWRhdGVkIjp0cnVlLCJ4LW1zLWF6dXJldm0tZGJ4dmFsaWRhdGVkIjp0cnVlLCJ4LW1zLWF6dXJldm0tZGVidWdnZXJzZGlzYWJsZWQiOnRydWUsIngtbXMtYXp1cmV2bS1kZWZhdWx0LXNlY3VyZWJvb3RrZXlzdmFsaWRhdGVkIjp0cnVlLCJ4LW1zLWF6dXJldm0tZWxhbS1lbmFibGVkIjpmYWxzZSwieC1tcy1henVyZXZtLWZsaWdodHNpZ25pbmctZW5hYmxlZCI6ZmFsc2UsIngtbXMtYXp1cmV2bS1odmNpLXBvbGljeSI6MCwieC1tcy1henVyZXZtLWh5cGVydmlzb3JkZWJ1Zy1lbmFibGVkIjpmYWxzZSwieC1tcy1henVyZXZtLWlzLXdpbmRvd3MiOmZhbHNlLCJ4LW1zLWF6dXJldm0ta2VybmVsZGVidWctZW5hYmxlZCI6ZmFsc2UsIngtbXMtYXp1cmV2bS1vc2J1aWxkIjoiTm90QXBwbGljYXRpb24iLCJ4LW1zLWF6dXJldm0tb3NkaXN0cm8iOiJVYnVudHUiLCJ4LW1zLWF6dXJldm0tb3N0eXBlIjoiTGludXgiLCJ4LW1zLWF6dXJldm0tb3N2ZXJzaW9uLW1ham9yIjoyMCwieC1tcy1henVyZXZtLW9zdmVyc2lvbi1taW5vciI6NCwieC1tcy1henVyZXZtLXNpZ25pbmdkaXNhYmxlZCI6dHJ1ZSwieC1tcy1henVyZXZtLXRlc3RzaWduaW5nLWVuYWJsZWQiOmZhbHNlLCJ4LW1zLWF6dXJldm0tdm1pZCI6IjY1MDZCNTMxLTE2MzQtNDMxRS05OUQyLTQyQjdEMzQxNEFEMCIsIngtbXMtaXNvbGF0aW9uLXRlZSI6eyJ4LW1zLWF0dGVzdGF0aW9uLXR5cGUiOiJzZXZzbnB2bSIsIngtbXMtY29tcGxpYW5jZS1zdGF0dXMiOiJhenVyZS1jb21wbGlhbnQtY3ZtIiwieC1tcy1ydW50aW1lIjp7ImtleXMiOlt7ImUiOiJBUUFCIiwia2V5X29wcyI6WyJlbmNyeXB0Il0sImtpZCI6IkhDTEFrUHViIiwia3R5IjoiUlNBIiwibiI6InRYa1JMQUFCUTd2Z1g5NjQySjJqUzJsMW03MFlNcDl3Nnd4U2dPWVdzZmhpZkNub0Z6SC1pd2llLXUwNmhxZnVQa0hQQ29GZjBoUzN6R0VvbFJmLVNwc1daWTRvQ0s3bjNBR0tHZmRKNFJ4eVhwaHhDVTRKNlU0SDdpUGQ1MWRQTTFGalBySkVyMXRXRTlnQ00teTF5MFZpbTN2Y0FwOG43MElGWHRIdi1LdlpkczlYMFdWZUdPY0tNSk04SlQ2ZzcxazFFY1E0bWQ2Zk02NEpaVDF6VGtwNk41OG5rcUYweENtZkEzcmJYbFBValNKOEEtR1BYUTYxdFRnd1FFTURheFkxamRyWUNWQ1BSZ0pacnliTEVBc2pKWk5RNlVIeHlYMHNFNW5iaGtsb0loQlgzWE5YajVRbGxxZkZGSlhfZlk5SnJmWFF6VzAxYnNWSGswZTFPUSJ9XSwidm0tY29uZmlndXJhdGlvbiI6eyJjb25zb2xlLWVuYWJsZWQiOnRydWUsImN1cnJlbnQtdGltZSI6MTY3MTgzNTU0OCwic2VjdXJlLWJvb3QiOnRydWUsInRwbS1lbmFibGVkIjp0cnVlLCJ2bVVuaXF1ZUlkIjoiNjUwNkI1MzEtMTYzNC00MzFFLTk5RDItNDJCN0QzNDE0QUQwIn19LCJ4LW1zLXNldnNucHZtLWF1dGhvcmtleWRpZ2VzdCI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsIngtbXMtc2V2c25wdm0tYm9vdGxvYWRlci1zdm4iOjMsIngtbXMtc2V2c25wdm0tZmFtaWx5SWQiOiIwMTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsIngtbXMtc2V2c25wdm0tZ3Vlc3Rzdm4iOjIsIngtbXMtc2V2c25wdm0taG9zdGRhdGEiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwieC1tcy1zZXZzbnB2bS1pZGtleWRpZ2VzdCI6IjU3NDg2YTQ0N2VjMGYxOTU4MDAyYTIyYTA2Yjc2NzNiOWZkMjdkMTFlMWM2NTI3NDk4MDU2MDU0YzVmYTkyZDIzYzUwZjlkZTQ0MDcyNzYwZmUyYjZmYjg5NzQwYjY5NiIsIngtbXMtc2V2c25wdm0taW1hZ2VJZCI6IjAyMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwieC1tcy1zZXZzbnB2bS1pcy1kZWJ1Z2dhYmxlIjpmYWxzZSwieC1tcy1zZXZzbnB2bS1sYXVuY2htZWFzdXJlbWVudCI6ImFkNmRlMTZhYzU5ZWU1MjM1MWM2MDM4ZGY1OGQxYmU1YWVhZjQxY2QwZjdjODFiMjI3OWVjY2EwZGY2ZWY0M2EyYjY5ZDY2M2FkNjk3M2Q2ZGJiOWRiMGZmZDdhOTAyMyIsIngtbXMtc2V2c25wdm0tbWljcm9jb2RlLXN2biI6MTE1LCJ4LW1zLXNldnNucHZtLW1pZ3JhdGlvbi1hbGxvd2VkIjpmYWxzZSwieC1tcy1zZXZzbnB2bS1yZXBvcnRkYXRhIjoiYzY1MDA4NTlhZjk1NDQwMjA2YWFjNWU5M2ViNTBhMGYyY2ZkNGZhMmM1NDg1ZTA1YTVjNzdhNWQ4MWMzZGVlMzAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJ4LW1zLXNldnNucHZtLXJlcG9ydGlkIjoiY2Y1ZWE3NDJmMDhjYjQ1MjQwZThhZDQ3MTliNjExNTAyOGYzZTFkOWQ4ODE3NWEyNDdlYjdjNmM4NmRhNjQ5MyIsIngtbXMtc2V2c25wdm0tc210LWFsbG93ZWQiOnRydWUsIngtbXMtc2V2c25wdm0tc25wZnctc3ZuIjo4LCJ4LW1zLXNldnNucHZtLXRlZS1zdm4iOjAsIngtbXMtc2V2c25wdm0tdm1wbCI6MH0sIngtbXMtcG9saWN5LWhhc2giOiJ3bTltSGx2VFU4MmU4VXFvT3kxWWoxRkJSU05rZmU5OS02OUlZRHE5ZVdzIiwieC1tcy1ydW50aW1lIjp7ImNsaWVudC1wYXlsb2FkIjp7Im5vbmNlIjoiIn0sImtleXMiOlt7ImUiOiJBUUFCIiwia2V5X29wcyI6WyJlbmNyeXB0Il0sImtpZCI6IlRwbUVwaGVtZXJhbEVuY3J5cHRpb25LZXkiLCJrdHkiOiJSU0EiLCJuIjoia1ZUTFN3QUFRcGd0bHFrd1JyRFhoRGdfYzFNZmhSWEkzeE5QbENWMWVWbEVoNWVybE1jS1oxcl9GVV9yMXFmamZiWGd3cmFMYldSQTBpUGlkdnN2ZXJHMDhVRmlBazc2bjlIclNHcVFzendTWDNNRzhUblNtTEU4bEc3N0t2OGx5TXhDN0N5LTlnN05fMXpiMGxHX3doOW1DSG1IVGdJSXAxTHU2WFNOb2tza3F4QUJVV1VxQjcxekZORWV0THNfNktNV0dCd2o3d1lQR0J0Y21ZV0VDeGYwUUprNDdxR0Z0UEZiSU40SEg4MVFKakJBSjA1OEo5Nk15b3ZFNlZOZkdEWEZRSEZ5XzJ3S0JJTzcwTzBLTm11RFVrUWdwaklWRVcxbGt1c2JOUnR4VU91VVJmUWlOaWpKaXRoeFdud1d5ZVdRc0xGaFNoeU8wVDljWDVPMHBRIn1dfSwieC1tcy12ZXIiOiIxLjAifQ.DTCCvMi2bZrK1BWBu1FTDxKoFnE9iQdbti_zvJlyHATjoc9rrCcCP8it_tfMwY1ZquILPDSWqQmXW9O0Dva3x06KhMUuX6begrpN8LROKM0_9n1Zy2Rxg3bnlxhzNV0c6neMeC2bvcGAf2Ikej6EaKX7KnZ4Y4cME_iLrDNbLIyq7sZCrUrZNJtjVuzvWQ03n4dFyZTgco1LIdlgzVZB50HFopTA67asW8SvWkl3RHYmXF1wYaujqTxXDvzhFZbyrLQF1S7da74XVj65mpFcSOkqXb28NYkBndxvfjVsyI-b8UiLYU9WhscNCZBZCfXszqB69ySxvWQGOuoQfHBTAQ"
#>

param (
    [Parameter(Mandatory = $false)]
    [string]
    $Jwt
)

$ErrorActionPreference = 'Stop'

function ConvertTo-ByteArray ([string]$Base64UrlEncodedData) {
    $Base64EncodedString = ConvertTo-Base64EncodedString -Base64UrlEncodedData $Base64UrlEncodedData
    return [Convert]::FromBase64String($Base64EncodedString)
}

function ConvertTo-Base64EncodedString ([string]$Base64UrlEncodedData) {
    $Base64EncodedString = $Base64UrlEncodedData.Replace('-', '+').Replace('_', '/')
    switch ($Base64EncodedString.Length % 4) {
        0 { break; }
        2 { $Base64EncodedString += '=='; break; }
        3 { $Base64EncodedString += '='; break; }
    }
    return $Base64EncodedString
}

function Test-Jws ([string]$jwsValue, [string] $jwsType, [Switch] $TestValueNullOrEmpty, [Switch] $TestBase64JsonMalformed ) {
    if ($TestValueNullOrEmpty) {
        if ([string]::IsNullOrEmpty($jwsValue)) {
            Write-Warning -Message "Null or empty $jwsType."
        }
    }
    elseif ($TestBase64JsonMalformed) {
        if ( !$jwsValue.StartsWith("eyJ")) {
            Write-Warning -Message "Possible malformed base64 value for $jwsType."
        }
    }
}


$JwtSplit = $Jwt.Split('.')

# JWS JSON Serialization
[string]$jwsHeader = $JwtSplit[0]
[string]$jwPayload = $JwtSplit[1]
[string]$jwsSignature = $JwtSplit[2]

Test-Jws -jwsValue $jwsHeader -jwsType "JWS Header" -TestValueNullOrEmpty -TestBase64JsonMalformed
Test-Jws -jwsValue $jwPayload -jwsType "JWS Payload" -TestValueNullOrEmpty -TestBase64JsonMalformed
Test-Jws -jwsValue $jwsSignature -jwsType "JWS Signature" -TestValueNullOrEmpty

$data = "{0}.{1}" -f $jwsHeader, $jwPayload
$dataBytes = [System.Text.UTF8Encoding]::UTF8.GetBytes($data)
$hashedDataBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash($dataBytes)

$jwsSignatureBytes = ConvertTo-ByteArray -Base64UrlEncodedData $jwsSignature

$hashResult = $null

[PSCustomObject]$jwsHeaderObject = [System.Text.Encoding]::UTF8.GetString((ConvertTo-ByteArray -Base64UrlEncodedData $jwsHeader)) | ConvertFrom-Json

if ($null -eq $jwsHeaderObject) {
    throw "Unable to deserialize the JWS Header JSON."
}

Write-Host "Using algorithm '$($jwsHeaderObject.alg)'.."  -ForegroundColor Green
switch ($jwsHeaderObject.alg) {
    "RS256" {
        $hashAlgorithm = [System.Security.Cryptography.HashAlgorithmName]::SHA256;
        $padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        break;
    }
    "RS384" {
        $hashAlgorithm = [System.Security.Cryptography.HashAlgorithmName]::SHA384;
        $padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        break;
    }
    "RS512" {
        $hashAlgorithm = [System.Security.Cryptography.HashAlgorithmName]::SHA512;
        $padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        break;
    }
    "ES256" {
        $hashAlgorithm = [System.Security.Cryptography.HashAlgorithmName]::SHA256;
        break;
    }
    "ES384" {
        $hashAlgorithm = [System.Security.Cryptography.HashAlgorithmName]::SHA384;
        break;
    }
    "ES512" {
        $hashAlgorithm = [System.Security.Cryptography.HashAlgorithmName]::SHA512;
        break;
    }
    Default {
        throw "Unknown/unimplemented JSON Web Algorithm"
    }
}

if ($jwsHeaderObject.jku) {
    Write-Host "Getting certificates from '$($jwsHeaderObject.jku)'.."  -ForegroundColor Green
    $getJkuResponse = Invoke-RestMethod -Uri $jwsHeaderObject.jku -Method Get

    $matchingCertificate = $getJkuResponse.keys | Where-Object { $_.kid -eq $jwsHeaderObject.kid }
    if ($matchingCertificate) {
        Write-Host "Found matching certificate for kid '$($jwsHeaderObject.kid)'! "  -ForegroundColor Green
    }
    else {
        Write-Error -Message "No matching certificate found for kid '$($jwsHeaderObject.kid)'.."
    }

    $publicCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($matchingCertificate.x5c[-1]))
    switch ($jwsHeaderObject.alg[0]) {
        "R" {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($publicCertificate)
            $hashResult = $rsa.VerifyHash($hashedDataBytes, $jwsSignatureBytes, $hashAlgorithm, $padding)
        }
        "E" {
            $ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($publicCertificate)
            $hashResult = $ecdsa.VerifyHash($hashedDataBytes, $jwsSignatureBytes, $hashAlgorithm, $padding)
        }
        Default {}
    }

    $fgc = if($hashResult) {"green"} else {"red"}
    Write-Host "Hash result: $hashResult" -ForegroundColor $fgc
}
elseif ($jwsHeaderObject.x5c) {
    $publicCertificate = $null

    foreach ($x5cItem in $jwsHeaderObject.x5c) {
        $tempCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($x5cItem))
        $chainTrustValidator = [System.IdentityModel.Selectors.X509CertificateValidator]::ChainTrust;
        $chainTrustValidator.Validate($tempCert);

        if ($tempCert.Thumbprint -ieq $jwsHeaderObject.kid) {
            $publicCertificate = $tempCert
        }
        $tempCert = $null
    }

    if ($publicCertificate) {
        Write-Host "Found matching certificate for kid '$($jwsHeaderObject.kid)'! " -ForegroundColor Green
    }
    else {
        Write-Error -Message "No matching certificate found for kid '$($jwsHeaderObject.kid)'.."
    }

    switch ($jwsHeaderObject.alg[0]) {
        "R" {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($publicCertificate)
            $hashResult = $rsa.VerifyHash($hashedDataBytes, $jwsSignatureBytes, $hashAlgorithm, $padding)
        }
        "E" {
            $ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($publicCertificate)
            $hashResult = $ecdsa.VerifyHash($hashedDataBytes, $jwsSignatureBytes, [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)

        }
    }

    $fgc = if ($hashResult) { "green" } else { "red" }
    Write-Host "Hash result: $hashResult" -ForegroundColor $fgc
} else {
    Write-Warning -Message "No jku or x5c found."
}
