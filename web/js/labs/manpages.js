// Manual pages for every lab CLI. `help` lists command names; `man <command>` explains one,
// with examples to type. Written for FortiTatake in its own words; it describes what the lab supports.

// [name, synopsis, description, [[example, what it shows], ...]]
const WIN = [
  ["ipconfig", "ipconfig [/all | /renew | /release | /flushdns]", "Shows the PC's IPv4 address, mask and default gateway. /all adds DHCP state, the DHCP server and the DNS servers. /renew asks DHCP for a lease again; /release gives the lease back; /flushdns empties the resolver cache.", [["ipconfig", "Address, mask and gateway"], ["ipconfig /all", "Plus DHCP and DNS servers"], ["ipconfig /renew", "Retry DHCP after fixing the FortiGate's DHCP server"]]],
  ["ping", "ping [-n count] [-l size] [-f] <host>", "Sends ICMP echo requests and reports replies, round-trip times and TTL. -n sets how many, -l the payload size, -f sets Don't Fragment, which with -l finds the path MTU.", [["ping 10.10.10.1", "Is the gateway reachable?"], ["ping -n 2 www.fortinet.com", "Name resolution plus reachability"], ["ping -f -l 1472 8.8.8.8", "Does a full 1500-byte packet pass without fragmenting?"]]],
  ["tracert", "tracert <host>", "Lists each router on the path by sending probes with growing TTL. A row of asterisks means that hop doesn't answer, or something drops the probes.", [["tracert 8.8.8.8", "Path through the FortiGate and the ISP"], ["tracert 172.16.40.15", "Which next hop the lab routes to"]]],
  ["pathping", "pathping <host>", "Traces the path like tracert, then measures loss at each hop.", [["pathping 192.168.50.10", "Where along the path packets are lost"]]],
  ["nslookup", "nslookup <name> [server]", "Asks a DNS server for a name's address. Without a server it uses the PC's first DNS server. It ignores the hosts file, so it shows what DNS really answers.", [["nslookup www.fortinet.com", "Answer from the PC's DNS server"], ["nslookup www.fortinet.com 8.8.8.8", "Ask a specific resolver"]]],
  ["arp", "arp -a", "Lists the IP-to-MAC entries the PC has learned on its LAN.", [["arp -a", "Did the PC learn the gateway's MAC?"]]],
  ["route", "route print | route add|delete 0.0.0.0 mask 0.0.0.0 <gateway>", "Shows the PC's routing table, or adds and removes its default route. Lab PCs keep a default route only.", [["route print", "Routes and the default gateway"], ["route delete 0.0.0.0", "Remove the default route"], ["route add 0.0.0.0 mask 0.0.0.0 10.10.10.1", "Set it back"]]],
  ["netstat", "netstat -ano", "Lists the PC's TCP and UDP connections and listening ports with their process IDs.", [["netstat -ano", "Open connections after a curl or an RDP session"]]],
  ["curl", "curl [-k] [-I] <url>", "Makes an HTTP or HTTPS request and prints the reply. -I shows headers only; -k accepts an untrusted certificate. On the real network the connection stays open for a minute, like a browser, so the FortiGate's session list shows it.", [["curl http://192.168.50.10", "Reach the DMZ web server"], ["curl -I https://www.fortinet.com", "Headers only, through NAT"], ["curl -k https://10.10.10.1", "The FortiGate's admin page"]]],
  ["tnc", "tnc <host> -port <n>   (Test-NetConnection)", "Opens a TCP connection to a port and reports whether it succeeded. Without -port it pings.", [["tnc 192.168.50.10 -port 443", "Is HTTPS allowed to the server?"], ["Test-NetConnection 10.10.10.50 -Port 445", "SMB to the NAS"]]],
  ["ssh", "ssh <user>@<host>", "Opens an SSH session to a lab device. exit closes it.", [["ssh admin@10.10.10.1", "Log in to the FortiGate"], ["ssh admin@10.10.10.50", "Log in to the NAS"]]],
  ["telnet", "telnet <host> [port]", "Opens a Telnet session, or tests a TCP port when you give one.", [["telnet 203.0.113.1", "Log in to the ISP router"], ["telnet 192.168.50.10 80", "Is port 80 open?"]]],
  ["netsh", "netsh interface ip show config\nnetsh interface ip set address name=\"Ethernet0\" static <ip> <mask> [<gateway>] | dhcp\nnetsh interface ip set dns name=\"Ethernet0\" static <ip> | dhcp\nnetsh interface ip add dns name=\"Ethernet0\" <ip> index=2\nnetsh interface ip delete dns name=\"Ethernet0\" all | <ip>\nnetsh interface set interface name=\"Ethernet0\" admin=enable | disable", "Changes the PC's addressing: a static address, mask and gateway, or DHCP, and its DNS servers. The lab PC has one adapter, Ethernet0. Changes reach the real network at once.", [["netsh interface ip set address name=\"Ethernet0\" static 10.10.10.77 255.255.255.0 10.10.10.1", "Static address and gateway"], ["netsh interface ip set dns name=\"Ethernet0\" static 10.10.10.1", "Primary DNS"], ["netsh interface ip add dns name=\"Ethernet0\" 8.8.8.8 index=2", "Secondary DNS"], ["netsh interface ip set address name=\"Ethernet0\" dhcp", "Back to DHCP"]]],
  ["Get-NetIPConfiguration", "Get-NetIPConfiguration", "PowerShell view of the adapter: address, gateway and DNS servers.", [["Get-NetIPConfiguration", "Same facts as ipconfig, PowerShell style"]]],
  ["New-NetIPAddress", "New-NetIPAddress -InterfaceAlias Ethernet0 -IPAddress <ip> -PrefixLength <n> [-DefaultGateway <ip>]", "Sets a static address. Remove the current one first if there is one.", [["New-NetIPAddress -InterfaceAlias Ethernet0 -IPAddress 10.10.10.78 -PrefixLength 24 -DefaultGateway 10.10.10.1", "Static address in PowerShell"]]],
  ["Remove-NetIPAddress", "Remove-NetIPAddress -InterfaceAlias Ethernet0 -Confirm:$false", "Removes the static address.", [["Remove-NetIPAddress -InterfaceAlias Ethernet0 -Confirm:$false", "Clear the address before setting a new one"]]],
  ["Set-DnsClientServerAddress", "Set-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses (\"<ip>\",\"<ip>\") | -ResetServerAddresses", "Sets the DNS servers, or goes back to the ones DHCP gives.", [["Set-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses (\"10.10.10.1\",\"1.1.1.1\")", "Two DNS servers"]]],
  ["Set-NetIPInterface", "Set-NetIPInterface -InterfaceAlias Ethernet0 -Dhcp Enabled | Disabled", "Turns DHCP on or off for the adapter.", [["Set-NetIPInterface -InterfaceAlias Ethernet0 -Dhcp Enabled", "Back to DHCP"]]],
  ["notepad", "notepad C:\\Windows\\System32\\drivers\\etc\\hosts", "Opens the hosts file in the editor. Lines like \"10.10.10.1 fw.lab\" answer before DNS for ping and curl. Ctrl+S saves, Esc closes.", [["notepad C:\\Windows\\System32\\drivers\\etc\\hosts", "Add a local name"]]],
  ["type", "type <file>", "Prints a text file.", [["type C:\\Windows\\System32\\drivers\\etc\\hosts", "Check the hosts file"]]],
  ["forticlient", "forticlient connect | status | disconnect", "Drives the FortiClient VPN on this PC.", [["forticlient connect", "Bring the VPN up"], ["forticlient status", "Tunnel state and the address it got"]]],
  ["login", "login <user> <password>", "Answers the FortiGate's firewall authentication portal for this PC.", [["login jperez Lab2026!", "Authenticate before identity-based policies"]]],
  ["ver", "ver", "Prints the Windows version.", [["ver", ""]]],
  ["systeminfo", "systeminfo", "Prints host name, OS and network adapter details.", [["systeminfo", ""]]],
  ["hostname", "hostname", "Prints the PC's name.", [["hostname", ""]]],
  ["cls", "cls", "Clears the console.", [["cls", ""]]],
];

const LINUX = [
  ["ip", "ip a | ip route | ip neigh\nsudo ip addr add|del <ip/len> dev eth0 | sudo ip addr flush dev eth0\nsudo ip route add|replace|del default via <gateway>\nsudo ip link set eth0 up|down", "Shows and changes addressing. Reading needs no sudo; changing does. Lab hosts have one adapter (eth0), one IPv4 address and a default route.", [["ip a", "Address on eth0"], ["ip route", "Default gateway"], ["sudo ip addr flush dev eth0", "Remove the address"], ["sudo ip addr add 10.10.10.91/24 dev eth0", "Set one"], ["sudo ip route add default via 10.10.10.1", "Set the gateway"]]],
  ["ping", "ping [-c count] [-s size] [-M do] <host>", "Sends ICMP echo requests. -c sets how many, -s the payload size, -M do forbids fragmentation (path MTU tests).", [["ping -c 3 10.10.10.1", "Gateway reachable?"], ["ping -c 2 -s 1472 -M do 8.8.8.8", "Full-size packet without fragmenting"]]],
  ["traceroute", "traceroute <host>", "Lists the routers on the path.", [["traceroute 8.8.8.8", "Path to the Internet"]]],
  ["nslookup", "nslookup <name> [server]", "Asks DNS for a name. Ignores /etc/hosts.", [["nslookup www.fortinet.com", ""], ["nslookup intranet.lab 10.10.10.1", "Ask the FortiGate's DNS"]]],
  ["dig", "dig [@server] <name> [type]", "Detailed DNS query: flags, answer section, TTLs and timing.", [["dig www.fortinet.com", ""], ["dig @1.1.1.1 fortinet.com", "Ask a public resolver"]]],
  ["curl", "curl [-k] [-I] <url>", "HTTP or HTTPS request. On the real network the connection stays open for a minute so the FortiGate's session list shows it.", [["curl -I http://192.168.50.10", "Headers from the DMZ server"], ["curl -k https://10.10.10.1", "FortiGate admin page"]]],
  ["nc", "nc -zv <host> <port> | nc -zvu <host> <port>", "Tests whether a TCP (or with -u, UDP) port answers.", [["nc -zv 10.10.10.50 445", "SMB on the NAS"], ["nc -zv 192.168.50.10 22", "SSH to the server"]]],
  ["ss", "ss -tuln | ss -tnp", "Lists listening sockets (-l) or connections, TCP (-t) and UDP (-u).", [["ss -tuln", "What this server listens on"]]],
  ["cat", "cat <file>", "Prints a file. Config files here: /etc/hosts, /etc/hostname, /etc/resolv.conf, /etc/netplan/50-cloud-init.yaml.", [["cat /etc/resolv.conf", "Which DNS servers are used"], ["cat /etc/netplan/50-cloud-init.yaml", "Saved addressing"]]],
  ["ls", "ls <dir>", "Lists a directory.", [["ls /etc/netplan", ""]]],
  ["nano", "[sudo] nano <file>", "Opens the editor. ^O writes the file, ^X exits (answer Y or N if it changed), ^W searches, ^K cuts a line, ^U pastes. Files under /etc need sudo to save. vi and vim open the same editor.", [["sudo nano /etc/netplan/50-cloud-init.yaml", "Edit the saved addressing, then sudo netplan apply"], ["sudo nano /etc/hosts", "Add a local name"]]],
  ["netplan", "netplan get | sudo netplan apply | sudo netplan try", "Reads /etc/netplan/50-cloud-init.yaml and applies it: dhcp4, addresses, the default route and nameservers. A mistake in the file is reported and nothing changes.", [["netplan get", "What the file says"], ["sudo netplan apply", "Apply it"]]],
  ["dhclient", "sudo dhclient [-r] eth0", "Asks DHCP for a lease; -r releases it.", [["sudo dhclient eth0", "Get an address from the FortiGate"]]],
  ["resolvectl", "resolvectl status", "Shows the DNS servers in use.", [["resolvectl status", ""]]],
  ["hostnamectl", "hostnamectl [set-hostname <name>]", "Shows or changes the host name.", [["hostnamectl", ""]]],
  ["sudo", "sudo <command>", "Runs one command as root. Needed to change addressing and to save files under /etc.", [["sudo ip link set eth0 down", ""]]],
  ["ssh", "ssh <user>@<host>", "Opens an SSH session to a lab device.", [["ssh admin@10.10.10.1", "Log in to the FortiGate"]]],
  ["telnet", "telnet <host> [port]", "Opens a Telnet session, or tests a port.", [["telnet 203.0.113.1", "Log in to the ISP router"]]],
  ["uname", "uname [-a]", "Prints the kernel and OS.", [["uname -a", ""]]],
  ["hostname", "hostname", "Prints the host name.", [["hostname", ""]]],
  ["login", "login <user> <password>", "Answers the FortiGate's firewall authentication portal for this host.", [["login jperez Lab2026!", ""]]],
  ["clear", "clear", "Clears the console.", [["clear", ""]]],
];

const IOS = [
  ["enable", "enable", "Moves from user mode (>) to privileged mode (#), where configuration starts.", [["enable", ""]]],
  ["disable", "disable", "Back to user mode.", [["disable", ""]]],
  ["configure terminal", "configure terminal   (conf t)", "Enters global configuration mode, (config)#. Needs privileged mode.", [["conf t", ""]]],
  ["interface", "interface <name>   (in config mode)", "Enters interface configuration, (config-if)#. Use the router's interface names (show ip interface brief).", [["interface ge0", ""]]],
  ["ip address", "ip address <ip> <mask> | no ip address   (in interface mode)", "Sets or removes the interface address.", [["ip address 203.0.113.1 255.255.255.252", ""]]],
  ["shutdown", "shutdown | no shutdown   (in interface mode)", "Takes the interface down or brings it up. Traffic through it stops on the real network too.", [["shutdown", "Simulate an ISP outage"], ["no shutdown", "Restore it"]]],
  ["description", "description <text>   (in interface mode)", "Labels the interface in the running config.", [["description to Clinica San Rafael", ""]]],
  ["ip route", "ip route <network> <mask> <next-hop | Null0> | no ip route <network> <mask> [<next-hop>]", "Adds or removes a static route. Null0 drops the traffic (a blackhole).", [["ip route 10.10.10.0 255.255.255.0 203.0.113.2", "Route the customer LAN"], ["ip route 192.0.2.0 255.255.255.0 Null0", "Blackhole a prefix"]]],
  ["hostname", "hostname <name>   (in config mode)", "Renames the router; the prompt changes.", [["hostname CLARO-EDGE", ""]]],
  ["ip name-server", "ip name-server <ip>   (in config mode)", "Sets the router's DNS server.", [["ip name-server 8.8.8.8", ""]]],
  ["do", "do <exec command>   (in config modes)", "Runs a show or ping without leaving configuration mode.", [["do show ip interface brief", ""]]],
  ["exit", "exit", "Leaves interface mode to config mode, or config mode to privileged mode.", [["exit", ""]]],
  ["end", "end", "Returns to privileged mode from any configuration mode.", [["end", ""]]],
  ["write memory", "write memory   (wr, copy running-config startup-config)", "Saves the configuration.", [["wr", ""]]],
  ["show ip interface brief", "show ip interface brief", "Each interface with its address and up/down state.", [["show ip interface brief", ""]]],
  ["show ip route", "show ip route", "The routing table: connected, static and dynamic routes.", [["show ip route", ""]]],
  ["show interfaces", "show interfaces", "Interface details and counters.", [["show interfaces", ""]]],
  ["show arp", "show arp", "IP-to-MAC entries the router learned.", [["show arp", ""]]],
  ["show running-config", "show running-config", "The current configuration.", [["show running-config", ""]]],
  ["show version", "show version", "Software version and uptime.", [["show version", ""]]],
  ["show access-lists", "show access-lists", "Access lists and their hit counts.", [["show access-lists", ""]]],
  ["show logging", "show logging", "Recent log messages.", [["show logging", ""]]],
  ["show clock", "show clock", "Router time.", [["show clock", ""]]],
  ["show ip ospf neighbor", "show ip ospf neighbor", "OSPF neighbours and their state (labs with OSPF).", [["show ip ospf neighbor", ""]]],
  ["show ip bgp summary", "show ip bgp summary | show ip bgp", "BGP peers and prefixes received, or the BGP table (labs with BGP).", [["show ip bgp summary", ""]]],
  ["ping", "ping <ip>", "Five echo requests from the router.", [["ping 8.8.8.8", ""]]],
  ["traceroute", "traceroute <ip>", "Path from the router.", [["traceroute 203.0.113.2", ""]]],
  ["ssh", "ssh -l <user> <ip>", "SSH from the router to another device.", [["ssh -l admin 203.0.113.2", ""]]],
  ["telnet", "telnet <ip>", "Telnet from the router.", [["telnet 203.0.113.2", ""]]],
];

const FORTIOS = [
  ["config", "config <path> / edit <name> / set <attr> <value> / unset <attr> / next / end", "Changes configuration. Press ? at any point for the options, Tab to complete. end saves and leaves the block; abort leaves without saving.", [["config system interface\nedit port1\nset allowaccess ping https ssh\nend", "Admin access on an interface"], ["config firewall policy\nedit 0\nset srcintf internal\nset dstintf wan1\nset srcaddr all\nset dstaddr all\nset action accept\nset schedule always\nset service ALL\nset nat enable\nend", "A basic outbound policy"]]],
  ["show", "show [full-configuration] <path>", "Prints configuration: non-default settings, or all of them with full-configuration.", [["show firewall policy", ""], ["show full-configuration system interface port1", ""]]],
  ["get system status", "get system status", "Version, serial, hostname, operation mode, HA mode.", [["get system status", ""]]],
  ["get system interface", "get system interface", "Interfaces with addresses and status.", [["get system interface", ""]]],
  ["get router info routing-table", "get router info routing-table all | details <ip> | database", "The active routes; details <ip> shows which route a destination uses; database also shows inactive candidates.", [["get router info routing-table all", ""], ["get router info routing-table details 172.16.40.15", "Which interface traffic to that host uses"], ["get router info routing-table database", "Backup routes that aren't active"]]],
  ["get system arp", "get system arp", "ARP table.", [["get system arp", ""]]],
  ["get system performance status", "get system performance status", "CPU, memory, sessions and uptime.", [["get system performance status", ""]]],
  ["diagnose sniffer packet", "diagnose sniffer packet <interface|any> '<filter>' <verbose 1-6> <count> <a|l>", "Prints packets as they cross the FortiGate. The filter uses tcpdump syntax ('host 10.10.10.100 and port 443'). Verbose 4 adds the interface and direction; count 0 runs until Ctrl+C; a or l print absolute or local timestamps. On the real network you can download a .pcap afterwards. Click a wire on the map for the same view of any link.", [["diagnose sniffer packet any 'icmp' 4", "Pings in and out on every interface"], ["diagnose sniffer packet wan1 'port 53' 4 0 l", "DNS on the WAN, with local timestamps"], ["diagnose sniffer packet any 'host 10.10.10.100 and port 443' 4 20", "One host's HTTPS, 20 packets"]]],
  ["diagnose debug flow", "diagnose debug flow filter addr|saddr|daddr|proto|port <value>\ndiagnose debug flow show function-name enable\ndiagnose debug enable\ndiagnose debug flow trace start <count>\ndiagnose debug flow trace stop / diagnose debug reset", "Traces packets through the FortiGate's decisions: session lookup, DNAT, route, policy, SNAT. The last line says what happened: Allowed by Policy-N, Denied by forward policy check (policy 0 = implicit deny), or iprope_in_check failed (traffic to the FortiGate itself that the interface doesn't accept). Give a count: without one, only the next packet is traced.", [["diagnose debug flow filter addr 10.10.10.100\ndiagnose debug flow show function-name enable\ndiagnose debug enable\ndiagnose debug flow trace start 10", "Trace one PC's next 10 packets"], ["diagnose debug disable\ndiagnose debug reset", "Stop and clean up"]]],
  ["diagnose sys session", "diagnose sys session filter src|dst|dport|policy <value> | filter clear\ndiagnose sys session list | clear", "Lists sessions in the session table: protocol, state, policy_id, SNAT/DNAT and counters. On the real network it reads the kernel's table, so traffic must be running or have just run (web sessions stay a minute; pings about 10 s).", [["diagnose sys session filter clear\ndiagnose sys session filter src 10.10.10.100\ndiagnose sys session list", "One PC's sessions"], ["diagnose sys session filter dport 443\ndiagnose sys session list", "All HTTPS sessions"]]],
  ["diagnose firewall iprope lookup", "diagnose firewall iprope lookup <src> <sport> <dst> <dport> <proto> <in-interface>", "Asks which policy would match a flow, without sending traffic.", [["diagnose firewall iprope lookup 10.10.10.100 12345 8.8.8.8 443 tcp internal", ""]]],
  ["execute ping", "execute ping-options source <ip> | reset\nexecute ping <host>", "Pings from the FortiGate; ping-options source chooses the source address.", [["execute ping 8.8.8.8", ""], ["execute ping-options source 10.10.10.1\nexecute ping 172.16.40.15", "From the LAN address"]]],
  ["execute traceroute", "execute traceroute <host>", "Path from the FortiGate.", [["execute traceroute 8.8.8.8", ""]]],
  ["get router info ospf", "get router info ospf neighbor | interface | database", "OSPF neighbours, interfaces and LSDB.", [["get router info ospf neighbor", ""]]],
  ["get router info bgp", "get router info bgp summary | network | neighbors <ip> [advertised-routes|received-routes]", "BGP peers, the BGP table and per-neighbour routes.", [["get router info bgp summary", ""], ["get router info bgp neighbors 10.255.0.2 advertised-routes", ""]]],
  ["diagnose sys sdwan", "diagnose sys sdwan health-check | member | service", "SD-WAN health checks (latency, jitter, loss, alive), members, and which member each rule picks.", [["diagnose sys sdwan health-check", ""], ["diagnose sys sdwan service", ""]]],
  ["diagnose vpn", "diagnose vpn ike gateway list | diagnose vpn tunnel list [name <tunnel>]\ndiagnose vpn ike log-filter dst-addr4 <ip> / diagnose debug application ike -1", "IPsec phase 1 (IKE SAs) and phase 2 (IPsec SAs, selectors, counters), and the IKE negotiation debug.", [["diagnose vpn ike gateway list", ""], ["diagnose vpn tunnel list", ""], ["diagnose vpn ike log-filter dst-addr4 203.0.113.20\ndiagnose debug application ike -1\ndiagnose debug enable", "Watch a negotiation"]]],
  ["get system ha status", "get system ha status | diagnose sys ha checksum cluster | execute ha manage <id> <user>", "HA cluster state, sync checksums, and logging in to the secondary.", [["get system ha status", ""], ["diagnose sys ha checksum cluster", ""]]],
  ["diagnose test authserver", "diagnose test authserver ldap|radius <server> <user> <password>", "Tests a user against an LDAP or RADIUS server without a login.", [["diagnose test authserver ldap AD-LDAP jperez Lab2026!", ""]]],
  ["diagnose firewall auth", "diagnose firewall auth list | clear", "Authenticated users the FortiGate knows.", [["diagnose firewall auth list", ""]]],
  ["execute log display", "execute log filter category <n> / execute log display", "Shows logs stored on the FortiGate.", [["execute log display", ""]]],
  ["execute dhcp lease-list", "execute dhcp lease-list", "DHCP leases the FortiGate gave out.", [["execute dhcp lease-list", ""]]],
  ["execute backup config", "execute backup config tftp|ftp|usb ...", "Saves the configuration.", [["execute backup config tftp fgt.conf 10.10.10.50", ""]]],
  ["diagnose sys top", "diagnose sys top", "Processes by CPU and memory.", [["diagnose sys top", ""]]],
];

const FSIEM = [
  ["rule new", "rule new \"<name>\" where key=value ... group a,b count|distinct <attr> >= N window <seconds> [sev N]", "Writes a correlation rule. Values take * globs, a|b alternatives, ~text (contains) and a leading ! (not).", [["rule new \"Kerberos password spray\" where eventType=Win-Security-4771 failureCode=0x18 group srcIpAddr distinct user >= 8 window 1800 sev 8", ""]]],
  ["rule delete", "rule delete \"<name>\"", "Deletes a rule you wrote.", [["rule delete \"Kerberos password spray\"", ""]]],
  ["rules", "rules | rule \"<name>\" enable|disable | threshold <n> | exception key=value", "Lists rules and tunes them.", [["rules", ""], ["rule \"Excessive Logon Failures\" exception srcIpAddr=10.20.40.30", "Exclude a scanner"]]],
  ["analytics", "analytics key=value ... [group-by=attr] [last=N]", "Searches events by attribute (eventType, srcIpAddr, user, reptDevName ...).", [["analytics eventType=Win-Security-4625 group-by=user", ""]]],
  ["incidents", "incidents [status=Active|Cleared] | incident <id> [assign <user> | clear \"<reason>\"]", "Incidents raised by enabled rules.", [["incidents status=Active", ""], ["incident 7165 assign jose", ""]]],
  ["cmdb", "cmdb", "Devices discovered from the logs they send.", [["cmdb", ""]]],
];

const FEDR = [
  ["inventory", "inventory", "Collectors and their state.", [["inventory", ""]]],
  ["policies", "policies | policy \"<name>\" prevention|simulation", "Security policies and their mode.", [["policy \"Execution Prevention\" prevention", ""]]],
  ["events", "events [host=<id>] | event <id> | forensics <id>", "Security events, their details and the process tree.", [["events host=RECEPCION", ""], ["forensics 41877", ""]]],
  ["classify", "classify <id> malicious|suspicious|pup|likely-safe|safe", "Sets an event's classification.", [["classify 41877 malicious", ""]]],
  ["exception", "exception <id> [all|host]", "Stops a process and rule pair from raising events.", [["exception 41902 host", ""]]],
  ["remediate", "remediate <id> kill|delete|registry", "Acts on the endpoint.", [["remediate 41877 kill", ""]]],
  ["isolate", "isolate <host> | unisolate <host>", "Cuts a host off the network except for FortiEDR.", [["isolate RECEPCION", ""]]],
];

const FAZ = [
  ["devices", "devices | authorize <device> [adom]", "Log devices and their authorization.", [["authorize FGT-SR root", ""]]],
  ["logview", "logview [traffic|utm|event] key=value ... [last=N]", "Searches logs.", [["logview traffic srcip=10.10.10.100 last=20", ""]]],
  ["fortiview", "fortiview sources|destinations|threats|policies", "Top lists.", [["fortiview threats", ""]]],
  ["handlers", "handlers | handler create|enable|disable ...", "Event handlers that raise alerts.", [["handlers", ""]]],
  ["alerts", "alerts | incident create <event id> [assign=<user>] | incidents", "Alerts and incidents.", [["alerts", ""]]],
  ["get system status", "get system status", "Platform and version.", [["get system status", ""]]],
];

const FMG = [
  ["devices", "devices | authorize <device>", "Managed devices.", [["authorize FGT-SR", ""]]],
  ["dbconsole", "dbconsole <device>", "Edits the device's database copy with FortiOS commands; exit leaves.", [["dbconsole FGT-SR", ""]]],
  ["install", "install preview <device> | install <device>", "Shows and pushes the difference to the device.", [["install preview FGT-SR", ""]]],
  ["retrieve", "retrieve <device> | revisions <device>", "Pulls the device's config; lists saved revisions.", [["retrieve FGT-SR", ""]]],
];

const FSW = [
  ["get system status", "get system status", "Switch model, version and FortiLink state.", [["get system status", ""]]],
  ["show switch interface", "show switch interface", "Ports, their native VLAN and what's connected.", [["show switch interface", ""]]],
];

const BOOKS = { windows: WIN, linux: LINUX, ios: IOS, fortigate: FORTIOS, fortisiem: FSIEM, fortiedr: FEDR, fortianalyzer: FAZ, fortimanager: FMG, fortiswitch: FSW };
const norm = (s) => String(s).toLowerCase().replace(/\s+/g, " ").trim();

function page(e) {
  const [name, syn, desc, ex] = e;
  const ind = (t) => String(t).split("\n").map((l) => "    " + l).join("\n");
  const wrap = (t) => { const out = []; let line = ""; for (const w of t.split(" ")) { if ((line + " " + w).trim().length > 76) { out.push(line); line = w; } else line = (line + " " + w).trim(); } if (line) out.push(line); return out.join("\n"); };
  return ["NAME", ind(name), "", "SYNOPSIS", ind(syn), "", "DESCRIPTION", ind(wrap(desc)), "", "EXAMPLES", ...ex.map(([c, w]) => ind(c) + (w ? "\n" + ind("    " + w) : "")).join("\n\n").split("\n")].join("\n");
}

export function manKind(d) {
  if (!d) return null;
  if (d.kind === "router") return "ios";
  if (d.kind === "host" || d.kind === "server") return d.os === "windows" ? "windows" : "linux";
  return BOOKS[d.kind] ? d.kind : null;
}

// `help` (not on the FortiGate, whose CLI uses ?) and `man <command>`; null = not ours
export function manHelp(d, line) {
  const kind = manKind(d);
  if (!kind) return null;
  const book = BOOKS[kind];
  const t = String(line).trim();
  const m = /^man(?:\s+(.*))?$/i.exec(t);
  if (m) {
    if (!m[1]) return `What manual page do you want?\nFor example: man ${book[0][0]}\nPages here: ${book.map((e) => e[0]).join(", ")}`;
    const q = norm(m[1]);
    const e = book.find((x) => norm(x[0]) === q) || book.find((x) => norm(x[0]).startsWith(q)) || book.find((x) => q.startsWith(norm(x[0]))) || book.find((x) => norm(x[1]).startsWith(q)) || book.find((x) => norm(x[0]).includes(q));
    return e ? page(e) : `No manual entry for ${m[1]}\nPages here: ${book.map((x) => x[0]).join(", ")}`;
  }
  if (kind !== "fortigate" && /^(help|\?)$/i.test(t)) {
    const names = book.map((e) => e[0]);
    const w = Math.max(...names.map((n) => n.length)) + 2;
    const cols = Math.max(1, Math.floor(78 / w));
    const rows = [];
    for (let i = 0; i < names.length; i += cols) rows.push(names.slice(i, i + cols).map((n) => n.padEnd(w)).join("").trimEnd());
    return `Commands (type man <command> for what it does and examples):\n\n${rows.join("\n")}`;
  }
  return null;
}
