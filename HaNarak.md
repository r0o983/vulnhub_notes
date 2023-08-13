# Ha:Narak主机渗透实现

- 靶机地址：https://www.vulnhub.com/entry/ha-narak,569/
- 下载地址：https://download.vulnhub.com/ha/narak.ova



## 信息收集：

### 主机发现：

- 使用`netdiscover -i eth1 `来进行扫描主机网段，`-i` 指定网卡名称，本机IP地址：`192.168.2.2` 

- ```shell
   Currently scanning: 172.26.163.0/16   |   Screen View: Unique Hosts         
   
   15 Captured ARP Req/Rep packets, from 3 hosts.   Total size: 900            
   _____________________________________________________________________________
     IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
   -----------------------------------------------------------------------------
   192.168.2.1     00:50:56:c0:00:01      5     300  VMware, Inc.              
   192.168.2.5     00:0c:29:24:c2:9a      8     480  VMware, Inc.              
   192.168.2.254   00:50:56:e4:fb:db      2     120  VMware, Inc. 
  ```



### 端口扫描

- tcp扫描

- ```SHELL
  └─$ sudo nmap --min-rate 10000 -sT 192.168.2.5 -p- -oA Nmap-scan/sT  
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-13 04:39 EDT
  Nmap scan report for 192.168.2.5
  Host is up (0.0025s latency).
  Not shown: 65533 closed tcp ports (conn-refused)
  PORT   STATE SERVICE
  22/tcp open  ssh
  80/tcp open  http
  MAC Address: 00:0C:29:24:C2:9A (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 16.86 seconds
  ```

- udp扫描

- ```SHELL
  └─$ sudo nmap --min-rate 10000 -sU 192.168.2.5 -p- -oA Nmap-scan/sU
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-13 04:40 EDT
  Warning: 192.168.2.5 giving up on port because retransmission cap hit (10).
  Nmap scan report for 192.168.2.5
  Host is up (0.0013s latency).
  All 65535 scanned ports on 192.168.2.5 are in ignored states.
  Not shown: 65457 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
  MAC Address: 00:0C:29:24:C2:9A (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 79.47 seconds
  
  ```



### 服务端口及操作系统探测

- ```shell
  └─$ sudo nmap --min-rate 10000 -sC -sV -O -p22,80 192.168.2.5 -oA Nmap-scan/sC    
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-13 04:48 EDT
  Nmap scan report for 192.168.2.5
  Host is up (0.00045s latency).
  
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey: 
  |   2048 71:bd:59:2d:22:1e:b3:6b:4f:06:bf:83:e1:cc:92:43 (RSA)
  |   256 f8:ec:45:84:7f:29:33:b2:8d:fc:7d:07:28:93:31:b0 (ECDSA)
  |_  256 d0:94:36:96:04:80:33:10:40:68:32:21:cb:ae:68:f9 (ED25519)
  80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
  |_http-server-header: Apache/2.4.29 (Ubuntu)
  |_http-title: HA: NARAK
  MAC Address: 00:0C:29:24:C2:9A (VMware)
  Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
  Device type: general purpose
  Running: Linux 3.X|4.X
  OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
  OS details: Linux 3.2 - 4.9
  Network Distance: 1 hop
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
  
  OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 14.79 seconds
  
  ```



### 默认漏洞脚本扫描

- ```shell
  └─$ sudo nmap --script=vuln -p22,80 192.168.2.5 -oA Nmap-scan/Script
  [sudo] password for kali: 
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-13 04:49 EDT
  Nmap scan report for 192.168.2.5
  Host is up (0.00043s latency).
  
  PORT   STATE SERVICE
  22/tcp open  ssh
  80/tcp open  http
  |_http-dombased-xss: Couldn't find any DOM based XSS.
  | http-csrf: 
  | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.2.5
  |   Found the following possible CSRF vulnerabilities: 
  |     
  |     Path: http://192.168.2.5:80/
  |     Form id: 
  |_    Form action: images/666.jpg
  | http-internal-ip-disclosure: 
  |_  Internal IP Leaked: 127.0.1.1
  |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
  | http-enum: 
  |   /images/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
  |_  /webdav/: Potentially interesting folder (401 Unauthorized)
  MAC Address: 00:0C:29:24:C2:9A (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 37.43 seconds
  
  ```

- 



### web扫描

```shell
└─$ gobuster dir -u http://192.168.2.5/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.2.5/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/08/13 04:52:04 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 311] [--> http://192.168.2.5/images/]
/webdav               (Status: 401) [Size: 458]
/server-status        (Status: 403) [Size: 276]
Progress: 218416 / 220561 (99.03%)
===============================================================
2023/08/13 04:52:39 Finished
=============================================================
```

