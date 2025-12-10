# Red vs Blue PROJECT 
## Introduction
As part of our master’s Research Project, we designed and built a complete Red vs Bluse project using Proxmox Virtual Environment (VE). Our objective was to simulate real-world attack and defense operations inside a fully isolated virtual network. The project required us to build a isolated Enterprise Network network, configure routers and firewalls, deploy a Wazuh , and carry out both offensive (Red Team) and defensive (Blue Team) tasks. Within the team, I focused on building and configuring the entire lab environment, including Proxmox deployment, VM setup, Wazuh SIEM configuration, and full network validation. As part of the Red Team, I performed reconnaissance, vulnerability scanning, and exploitation attempts, identifying misconfigurations such as anonymous FTP access and weak credential protection.
--
## Proxmox Lab Setup: Creating an Isolated Enterprise Network
We built our cybersecurity lab on Proxmox VE to provide isolation, virtualization, and network segmentation. To emulate a real enterprise network, we configured two virtual bridges:

- **vmbr0 (WAN)** :External-facing network  
- **vmbr1 (LAN)** :Internal private network  

This setup allowed us to safely execute attack simulations without exposing any actual systems.

#### Virtual Machines Deployed
1. **VyOS Router** – Routing between WAN and LAN  
2. **pfSense Firewall** – Network perimeter and segmentation  
3. **Ubuntu Server** – Hosting Wazuh SIEM  
4. **Windows 10 Endpoint** – Primary Red Team target  
5. **Kali Linux** – Red Team attacking machine  
---
### VyOS Router Setup
The VyOS router acted as the main gateway for the entire lab network.

#### Interface Configuration
- **eth0 (WAN):** 203.0.116.2/25 
- **eth1 (LAN):** 178.18.4.1/24

#### Features Implemented
- **NAT masquerading** for private LAN systems  
- **Static routing** to interconnect all VMs  
- **Connectivity verification** using ping and traceroute

VyOS served as the backbone that enabled communication between the WAN, LAN, and all internal hosts.

---

### Ubuntu Server Setup (Base Configuration)
Before installing Wazuh, the Ubuntu server was configured with a persistent static network setup:

- **Static IP:** 178.18.4.2
- **Gateway:** 178.18.4.1
- **DNS Resolver:** 8.8.8.8 

Netplan was updated to store these settings. Once complete, connectivity to VyOS was tested and confirmed.

---

### pfSense Firewall Setup
pfSense functioned as the primary firewall and perimeter defense system.

#### Interface Assignments
- **WAN:** 178.18.4.3  
- **LAN:** 192.168.103.1

#### Firewall Configuration
- Manual interface assignments for full control  
- Automatic outbound NAT enabled  
- Segmentation between WAN, LAN, and internal hosts  

pfSense acted as the key defensive gateway for both Blue Team monitoring and network segmentation.

---

### Windows 10 Endpoint Setup
The Windows 10 machine served as the main attack target and endpoint monitored via the SIEM.

#### Network Configuration
- **Static IP:** 192.168.103.2 
- **Gateway:** 192.168.103.1

#### Services Enabled for Attack Simulation
- **FTP**
- **SMB**
- **SSH**
- **RDP**
- **HTTP**

These services created a realistic and exploitable attack surface for Red Team operations.

---

### Wazuh SIEM Configuration: What We Implemented
After configuring the isolated network, we installed the complete Wazuh, which became the central hub for Blue Team monitoring and detection.

### Installed Components
- **Wazuh Manager** – Log collection and alerting  
- **Filebeat** – Log forwarding to the dashboard  
- **Wazuh Dashboard (Kibana)** – Visual interface for event analysis 
- **Installation Location:** All components were installed and configured on the Ubuntu Server.

### Agent Deployment and Integrations
- **Wazuh Agent installed on Windows 10** – deployed and configured on the Windows endpoint  
- **Sysmon integration** for deep endpoint telemetry on our Windows, capturing key Event IDs:
  - **Event ID 1:** Process creation  
  - **Event ID 3:** Network connections  
  - **Event ID 11:** File modifications  
- **pfSense log forwarding** to Wazuh  
- Continuous pipeline validation to ensure reliable communication between agents, firewall, and SIEM 

### Essential Ports Opened in pfsense
- **1514/TCP** – Wazuh log events  
- **1515/TCP** – Agent registration and communication  
- **5601/TCP** – Wazuh Dashboard access  
- **DNS/HTTP/HTTPS** – Required for general system functionality

All unnecessary ports were blocked to maintain a secure environment.

---

## Red Team Summary – Offensive Security Testing
Using Kali Linux, we conducted a series of offensive tests on the target environment at 192.168.35.5. We also installed and configured WireGuard to securely support both Red Team and Blue Team techniques, enabling controlled access and communication within the isolated lab environment.

### Reconnaissance
- Performed an aggressive full‑port scan using a command 
***nmap -p- -sS -A -T4 192.168.35.5*******
- Identified OS as **Windows 10**
- Captured service banners for vulnerability matching
-  Detected major services:
  - **21** – FTP (legacy FileZilla-like)
  - **22** – OpenSSH 7.7
  - **80** – Microsoft IIS 10.0
  - **139/445** – SMB/NetBIOS (SMBv1 enabled; message signing disabled)
- Conducted **Gobuster** directory enumeration
- Performed OS and service fingerprinting

### Exploitation Attempts
#### FTP (Port 21) 
- Identified vulnerability related to MS09‑053 NLST buffer overflow 
  - Attempted exploit: 
  - ****exploit/windows/ftp/ms09_053_ftpd_nlst*
  - Configured *RHOSTS=192.168.35.5*, *LHOST=10.0.2.7*, *LPORT=4444*
  - Result: Exploit failed, no session created
- Performed brute-force attempts using
 - ****auxiliary/scanner/ftp/ftp_login* 
 - No valid or anonymous credentials recovered
#### SSH (Port 22) 
- Enumerated users with
 - **auxiliary/scanner/ssh/ssh_enumusers* 
 - *we used metasploit name list & THREADS=10* 
 - No valid users identified
- Brute-forced with rockyou.txt
 - No successful credentials
#### HTTP (Port 80) 
- Ran Gobuster with *.txt*, *.zip*, *.bak*, *.conf* extensions 
 - Found */index.html* 
 - confirmed IIS 10.0 banner using: *curl -I http://192.168.35.5* 
 - Identified the target as TEAM E
#### SMB (Port 139/445)
- Enumeration revealed: *SMBv1 enabled Message signing disabled* 
- Attempted NTLM relay testing, blocked by *Rex::BindFailed* 
- *MS17‑010 (EternalBlue)* tested but unsuccessful
#### Port 2016
Standard vectors (FTP 21, SSH 22, HTTP 80, SMB 139/445) did not yield successful exploitation. Following an instructor hint, we investigated the unusual open port 2016.
- Connected via *FTP* using anonymous login 
 -*username : anonymous*
 -*password : anonymous*
- Executed *ls* and found **ford.txt** and downloaded for offline analysis 
- File contained ciphertext and key string *VG7tVa8y43ighm* 
- Initial online decoders failed and recognized the encryption as a ROT cipher 
- Successfully decrypted to recover: **fordfusion_2016**

### Failed/Blocked Attacks
- Several Metasploit modules failed to produce a shell  
- SMB exploitation unsuccessful  
- SSH brute-force yielded no valid users  
- NTLM relay attempts blocked by pfSense  

**Summary**
We did an red team attacks on another team’s Windows 10 target, carrying out reconnaissance, service enumeration, and multiple exploitation attempts. Although most attacks , such as FTP, SMB, and SSH exploits, were unsuccessful, we identified an overlooked port (2016) offering anonymous FTP access. Through this entry point, we downloaded and decrypted an encrypted file, revealing fordfusion_2016. This finding highlighted misconfigured services, weak credential protections, and notable security gaps within the target environment, providing meaningful insight into potential attack vectors and system weaknesses.

---

## Blue Team Summary – Defensive Monitoring and Findings 
Using Wazuh, Sysmon, pfSense firewall logs, and Ubuntu system logs, we monitored all activity targeting the Windows 10 endpoint. Another team attempted multiple attacks on our system, and our responsibility was to detect, analyze, and respond to their actions in real time. Due to issues with the Wazuh Dashboard, we relied heavily on **CLI-based log analysis** to monitor events and maintain visibility.

### Detected Activities
- Detected heavy **SYN scanning**, clearly indicating that the attacking team performed an aggressive **Nmap reconnaissance scan** against our Windows system  
- Identified multiple **SSH and FTP brute‑force attempts** originating from the attacker’s machine  
- Observed **enumeration activity** through PowerShell commands  
- Logged unauthorized attempts to access **anonymous FTP**, including a successful login through **FTP port 123** where the attacker downloaded files from the Windows machine  
- Sysmon flagged suspicious **process creation**, **network connection attempts**, and **file modification** events during the attack period

### MITRE ATT&CK Mapped Detections
- **T1087 – Account Discovery**  
- Indicators matching scanning, exploitation, and credential probing techniques  
- Additional signals suggesting privilege exploration and attempted lateral movement  

### Defensive Actions Taken
- Blocked vulnerable ports including *FTP, SSH, and port 123* to prevent unauthorized access  
- Strengthened *pfSense firewall rules* to restrict malicious traffic and scanning attempts  
- Disabled insecure and unused services on the Windows endpoint  
- Changed default and weak credentials to improve system security  
- Ensured *SIEM log forwarding* remained fully functional despite issues with the dashboard  
- Continued *real-time monitoring* to detect and respond to any new threats  

**Summary:**  
Our Blue Team effectively detected and responded to offensive actions from the opposing team. By leveraging Wazuh CLI logs, Sysmon telemetry, and firewall monitoring, we successfully identified hostile activity, correlated alerts, and implemented defensive measures to secure the environment.


---

## Key Techniques Implemented

### Red Team Techniques
- we performed Nmap scanning for host, port, and service discovery  
- Conducted Gobuster directory enumeration on the web server  
- Probed FTP and SMB services for misconfigurations and vulnerabilities  
- Executed brute‑force password attempts on multiple services  
- Collected OS fingerprints and service banners for vulnerability matching  
- Attempted NTLM spoofing and relay‑based exploitation  
- Decrypted captured data by applying ROT cipher analysis  

### Blue Team Techniques
- Monitored centralized logs using Wazuh SIEM  
- Analyzed Sysmon events related to processes, network activity, and file modifications  
- Inspected pfSense firewall logs to track external attacker traffic  
- Mapped detected behaviors to MITRE ATT&CK techniques  
- Performed incident response triage to validate and classify threats  
- Hardened network and endpoint configurations to reduce attack surface  
---

## Lessons Learned
Throughout the project, we gained deep insights into both offensive and defensive cybersecurity operations. Key lessons include:

- **Hands-on Experience Reinforces Theory:** Working in a fully isolated lab environment allowed us to apply theoretical knowledge of cybersecurity tools and frameworks in practice, deepening our understanding of real-world security operations.
- **Proper Network Segmentation is Critical:** Even small misconfigurations, such as exposed ports or improperly routed traffic, can create vulnerabilities. Segmenting networks into LAN, WAN, and DMZ zones improves security and limits potential attack surfaces.  
- **SIEM Visibility is Essential:** Complete and accurate log collection is vital. Missing logs create blind spots that can allow attackers to operate undetected. Configuring agents, log forwarding, and dashboards correctly is crucial for effective monitoring.  
- **Endpoint Enhances Detection:** Tools like Sysmon provide granular insight into process creation, network connections, file changes, and user activity. This data is essential for correlating events, detecting malicious behavior, and performing forensic investigations.  
- **Defense Requires Continuous Validation:** Security is not static. Firewall rules, access controls, SIEM alerts, and endpoint configurations need ongoing testing, tuning, and monitoring to remain effective against evolving threats.  
- **Importance of Red and Blue Team Collaboration:** Conducting simulated attacks and defenses highlights gaps in both offensive strategies and defensive measures. Communication and coordination between teams improve overall security posture.  
- **Documentation and Change Management:** Keeping detailed records of configurations, changes, and observed incidents is critical for troubleshooting, knowledge sharing, and ensuring repeatability of experiments in a lab environment.    
- **Incident Response Skills are Vital:** Monitoring, detecting, and responding to attacks in real time taught the importance of quick, methodical decision-making, prioritizing alerts, and mitigating risks without disrupting legitimate activity.  

### Challenges Encountered

During the project, we faced several technical and operational challenges while building, attacking, and defending our isolated cybersecurity environment:

- **Connectivity Issues:** The Windows 10 endpoint frequently lost internet access due to misconfigured pfSense firewall and NAT rules. Restoring proper connectivity required careful review of interface assignments, gateway settings, and routing rules.  
**Ubuntu Crashes:** The Ubuntu server crashed during system upgrades, forcing a full rebuild of the server to restore stability.  
- **Log Forwarding Problems:** Filebeat initially failed to forward logs reliably, causing gaps in visibility for both endpoint and firewall events. Debugging and correcting agent configurations were essential to reestablish continuous logging.  
- **Dashboard Overload:** The Wazuh Dashboard sometimes became unresponsive due to high log volume and alert accumulation. This required cleanup, reinstallation, and optimization of the log pipeline to ensure proper visualization and timely alerting.  
- **Wazuh Misconfiguration:** Repeated attempts to reinstall Wazuh incorrectly caused misconfigurations, breaking the Wazuh Manager and Dashboard, and preventing login access until the Wazuh stack was fully rebuilt from scratch.  
- **Agent Integration and Event Capture:** Configuring Sysmon and Wazuh agents on Windows correctly was challenging, as improper configuration could lead to missing event IDs or incomplete telemetry, reducing detection coverage.  
- **Firewall and Security Rule Conflicts:** Adjusting firewall rules to allow legitimate traffic while blocking Red Team attacks required careful testing. Overly strict rules sometimes caused unintended service outages, requiring iterative tuning.  

These challenges strengthened our troubleshooting skills and broadened our understanding of real SOC workflows.

---

# Reflections on Teamwork and Decision-Making
Teamwork was critical to the success of this project. 
- We used the **Mattermost project management tool** to effectively organize and segregate tasks, assign due dates, and maintain clear responsibilities across team members. 
- This helped streamline our workflow, avoid duplication, and coordinate both offensive and defensive operations. 
- However, we faced challenges due to miscommunication: one team member performed an Ubuntu upgrade that crashed the server, and repeated Wazuh installations caused configuration issues because we hadn’t properly updated the status in Mattermost. 
- Once these problems were identified, we improved our communication, followed the tool’s tracking process, and completed all tasks efficiently. 
- This experience highlighted the importance of structured collaboration, clear communication, and thorough documentation in complex cybersecurity projects.

---

# How This Project Contributes to My Career Development

- This project has been pivotal in shaping my cybersecurity career by providing hands-on experience with real-world tools and operations. Building a complete Red vs Blue lab allowed me to gain practical expertise in network security, cloud security, SOC operations, incident response, and penetration testing-skills that are directly relevant to professional cybersecurity roles.
- By deploying and configuring Proxmox, VyOS, pfSense, Wazuh SIEM, Sysmon, Windows endpoints, and Kali Linux, I developed a deep understanding of how enterprise networks and monitoring systems function.
- I learned to think like an attacker through Red Team exercises—performing reconnaissance, vulnerability scanning, exploitation attempts, and analyzing system weaknesses.
- On the Blue Team side, I strengthened my skills in threat detection, log analysis, incident response, and correlating alerts using MITRE ATT&CK.
- The project challenged me with real troubleshooting scenarios, including network connectivity issues, SIEM crashes, and log forwarding failures, honing my problem-solving, critical thinking, and technical troubleshooting abilities.
- Beyond technical expertise, I improved teamwork, communication, and documentation skills, and learned to effectively use a project management tool to coordinate tasks, track progress, and manage deadlines—experience that is highly valuable in software and cybersecurity teams.

Overall, this project has prepared me for roles as a SOC analyst, security engineer, or penetration tester, providing both the practical skills and professional confidence needed to succeed in today’s cybersecurity landscape.

---
## Conclusion
The Red vs Blue cybersecurity lab successfully simulated a real-world enterprise environment, allowing me to implement, attack, defend, and analyze systems in a controlled setting. This hands-on experience provided valuable insight into both offensive and defensive security operations and reinforced the importance of monitoring, configuration, and teamwork in cybersecurity.

