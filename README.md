# Red-vs-Blue-Team-Project 🔗🔗🔗🔗🔗🔗🔗🔗

## Red vs Blue Team Capstone Project  😍😍😍😍😍😍😍😍😍😍😍

- As the Red Team, the objective is to attack a vulnerable VM within the environment, ultimately gaining root access to the machine. 🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥

- As the Blue Team, the goal is to use Kibana to review logs taken during the Day 1 engagement to extract hard data and visualizations for an assessment report.

This serves as an outline for the Capstone Project. 😁😁😁😁😁😁

### Depiction of the Topology

The following machines are part of the network:  ✌✌✌✌✌✌✌✌✌✌✌✌✌✌✌✌✌
Kali: 192.168.1.90
ELK: 192.168.1.100
Target: 192.168.1.105

(Network Diagram link)

### RED TEAM

The webserver has several vulnerabilities, with the top three being: 😎😎😎😎😎😎😎😎

| Vulnerability     | Description | Impact |
|----------|---------------------|----------------------|
| **Sensitive Data Exposure** | The secret_folder directory and connect_to_corp_server files were exposed, compromising the credentials of the Web DAV folder.             | Malicious actors can now gain access to company servers and files.    |
| **Unauthorized File Upload**         | Users are able to upload payloads to the web server.                    | This vulnerability allows attackers to upload scripts such as PHP to the server, exposing the machine to a number of attacks enabled by malicious files.                     |
| **Remote Code Execution**    | As a consequence of the file upload vulnerability, attackers can upload web shells.                |   Malicious code can be injected and executed to gain access to critical data, root access, and compromise any sensitive data, including theft or deletion.                   |

### EXPLOITS
- Exploitation: **Sensitive Data Exposure**
	- *Tools & Processes*
		- ***nmap*** command to determine IP address of the machine and open ports.
		- ***dirb*** command is used to find existing and/or hidden web objects.
	- *Achievements*
		- The secret_folder directory was discovered through this exploited vulnerability.
		- Login prompt reveals that authorized user is Ashton.
		- Directory is password protected, susceptible to a brute-force attack.
	- *Impact*
		- Obtaining the username helps enable a brute force attack, leading to access and potential theft of data.


- Exploitation: **Brute Force Attack**
	- *Tools & Processes*
		- *gunzip* rockyou.gz to unzip the wordlist for use during password cracking.
		- Utilizing a Hydra attack to run: ***hydra -l ashton -P /usr/share/wordlists/rockyou.txt -s 80 -f -vV 192.168.1.105 http-get /company_folders/secret_folder***. This command will be executed using the rockyou.txt file previously unzipped.
	- *Achievements*
		- Once the attack is complete, the username ashton and password leopoldo are returned.
	- *Impact*
		- Credentials for login access to the WebDAV server have been obtained, and data is now at risk.

- Exploitation: **Password Hash Crack**
	- *Tools & Processes*
		- Using login credentials, access to the WebDAV folder was obtained, and a hashed password found within the folder
		- [Password hash cracking tool](https://crackstation.net) for cracking the password hash.
	- *Achievements*
		- Password is revealed to be: linux4u
	- *Impact*
		- Full user credentials were obtained to gain access to company folders and files.

### BLUE TEAM
A significant amount of data is available in the logs. Specifically, evidence of the following was obtained upon inspection:

- Traffic from attack VM to target, including an unusually high volume of requests.
- Access to sensitive data in the secret_folder directory.
- Brute-force attack against the HTTP server.
- POST request corresponding to the upload of shell.php.

**Unusual Request Volume**: Logs indicate an unusual number of requests and failed responses between the Kali VM and the target. Note that 401, 301, 200, 207, and 404 are the top responses.

| HTTP Status Code  | Meaning  | Count  |
| :------------: | :------------: | :------------: |
| 401  |Unauthorized   |16,067   |
| 301  |Moved Permanently   | 2  |
| 200  |OK   |  536 |
| 207  | Multi-Status(WebDAV;RFC 4918)  |10   |
| 404  | Not Found   | 4  |

Also important to note the connection spike in the Connections over time [Packetbeat Flows] ECS, as well as the spike in errors in the Errors vs successful transactions [Packetbeat] ECS

(Connections over Time Spike link)

### Access to Sensitive Data (Secret_Folder)

On the dashboard, a look at the Top 10 HTTP requests panel shows that the /company_folders/secret_folder was requested 31,430 times.

(Top 10 HTTP Requests link)

### WebDAV Connection & Reverse Shell Upload

The logs also indicate that an unauthorized actor was able to access protected data in the webdav directory. A graphing of the status codes and HTTP queries below can identify the increase in requests.

(Top HTTP Status Codes & Query link)

### Mitigation Steps

- Blocking the Port Scan
	- The local firewall can be used to throttle incoming connections.
	- ICMP traffic can be filtered.
	- An IP allowed list can be enabled.
	- Regularly run port scans to detect and audit any open ports.
	
- High Volume of Traffic from Single Endpoint
	- Rate-limiting traffic from a specific IP address would reduce the web server's susceptibility to DoS conditions, as well as provide a hook against which to trigger alerts against suspiciously fast series of requests that may be indicative of scanning.
- Access to sensitive data in the secret_folder directory
	- The secret_folder directory should be protected with stronger authentication.
	- Data inside of secret_folder should be encrypted at rest.
	- Filebeat should be configured to monitor access to the secret_folder directory and its contents.
	- Access to secret_folder should be whitelisted, and access from IPs not on this whitelist logged.
- Brute-Force attack against the HTTP server
	- The fail2ban utility can be enabled to protect against brute force attacks.
	- Create a policy that locks out accounts after 10 failed attempts.
	- Create a policy that increases password complexity (requirements).
- Identifying Reverse Shell Uploads
	- Set write permissions to read only on webdav to prevent payload deliveries.
	- Isolation of uploads to a dedicated storage partition.
	- Installation and configuration of Filebeat.
	
**Authors: Apil Adhakari  and Jatin Singh Tomar **   🙏🙏🙏🙏🙏🙏🙏🙏🙏🙏🙏🙏

