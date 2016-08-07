#https://www.projecthoneypot.org/faq.php#h
function Get-projecthoneypot() {
#https://www.projecthoneypot.org/terms_of_service_use.php
	Param(
		[Parameter(Mandatory = $true)][string]$ip,
		[AllowEmptyString()]$api_key="<api_key>"
	)
	$ip_arr = $ip.split(".")
	[array]::Reverse($ip_arr)
	$ip = $ip_arr -join(".")
	$query = $api_key+ "." + "$ip" + ".dnsbl.httpbl.org"
	try {
	$response = [System.Net.Dns]::GetHostAddresses("$query") | select -expandproperty IPAddressToString
	} catch {
	return $false
	}
	$decode = $response.split(".")
	if($decode[0] -eq "127") {
	$days_since_last_seen = $decode[1]
	$threat_score = $decode[2]
	switch ($decode[3]){
	0 { $meaning = "Search Engine"}
	1 { $meaning = "Suspicious"}
	2 { $meaning = "Harvester"}
	3 { $meaning = "Suspicious & Harvester"}
	4 { $meaning = "Comment Spammer"}
	5 { $meaning = "Suspicious & Comment Spammer"}
	6 { $meaning = "Harvester & Comment Spammer"}
	7 { $meaning = "Suspicious & Harvester & Comment Spammer"}
	default {$meaning = "Unknown"}
	}
	$return_obj = [PSCustomObject] @{
    last_seen = $days_since_last_seen
    threat_score = $threat_score
    meaning = $meaning
    }
	return $return_obj
	
	} else {
	return "Illegal response"
	}
		
}

