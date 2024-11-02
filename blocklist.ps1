# Define the URLs of the blocklist files
$blocklist_urls = @(
    "http://lists.blocklist.de/lists/all.txt",
    "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset",
    "https://abuseipdb.tmiland.com/abuseipdb.txt"
)

# Define the base name of the firewall rule
$rule_base_name = "Blocklist"

# Check if the firewall rule already exists
$existingRules = Get-NetFirewallRule -Name "$rule_base_name-*" -ErrorAction SilentlyContinue

# If rules exist, delete them
if ($existingRules) {
    $existingRules | Remove-NetFirewallRule
    Write-Host "Existing firewall rules deleted."
}

# Download the blocklist files and save them as temporary files
$blocklist_files = @()
foreach ($url in $blocklist_urls) {
    $tmp_file = New-TemporaryFile
    Invoke-WebRequest -Uri $url -OutFile $tmp_file
    $blocklist_files += $tmp_file
}

# Filter IP addresses and remove duplicates
$ip_addresses = @()
foreach ($file in $blocklist_files) {
    $content = Get-Content $file
    $ip_addresses += $content | Where-Object {$_ -match '\b(?:\d{1,3}\.){3}\d{1,3}\b' -or $_ -match '\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'} | Sort-Object -Unique
    Remove-Item $file
}

# Create a new firewall rule with the blocklist lines as remote addresses
# Split the blocklist lines into batches of 10000 to avoid exceeding the limit
$batch_size = 10000
$batch_count = [Math]::Ceiling($ip_addresses.Count / $batch_size)

for ($i = 0; $i -lt $batch_count; $i++) {
    $start_index = $i * $batch_size
    $end_index = [Math]::Min(($i + 1) * $batch_size - 1, $ip_addresses.Count - 1)
    $remote_addresses = $ip_addresses[$start_index..$end_index]

    $rule_name = "$rule_base_name-$i"
    New-NetFirewallRule -Name $rule_name -DisplayName $rule_name -Description "Block IPs from blocklists" -Direction Inbound -Action Block -RemoteAddress $remote_addresses
}

Write-Host "Firewall rules created successfully."
