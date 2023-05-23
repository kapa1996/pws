#TCP Rule
New-NetFirewallRule -DisplayName "Allow inbound ICMPv4 (Ping)" -Direction Inbound -Protocol ICMPv4 -Action Allow 

#RDP Rule enable
New-NetFirewallRule -DisplayName "RDP IN" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Profile Any

#kaspersky inbound rules 
New-NetFirewallRule -DisplayName "Kaspersky IN"  -Direction Inbound -Protocol UDP –LocalPort 13000 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName "Kaspersky IN"  -Direction Inbound -Protocol UDP –LocalPort 15000 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName "Kaspersky IN"  -Direction Inbound -Protocol TCP –LocalPort 14000 -Action Allow -Profile Any

#kaspersky outbound rules
New-NetFirewallRule -DisplayName "Kaspersky OUT" -Direction outbound -Protocol UDP –LocalPort 13000 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName "Kaspersky OUT" -Direction outbound -Protocol UDP –LocalPort 15000 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName "Kaspersky OUT" -Direction outbound -Protocol TCP –LocalPort 14000 -Action Allow -Profile Any

#manageengine Rules in and out 
New-NetFirewallRule -DisplayName "ManageEngine"  -Direction Inbound -Protocol TCP -LocalPort 8027,8383 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName "ManageEngine"   -Direction Outbound -Protocol TCP -LocalPort 8027,8383 -Action Allow -Profile Any