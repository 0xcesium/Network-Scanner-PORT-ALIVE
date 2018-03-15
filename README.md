# Network-Scanner-PORT-ALIVE [![python](https://img.shields.io/badge/Python-2.7-green.svg?style=style=flat-square)](https://www.python.org/downloads/) [![version](https://img.shields.io/badge/Version-Gamma-blue.svg?style=style=flat-square)](https://twitter.com/133_cesium) [![license](https://img.shields.io/badge/License-GPL_3-orange.svg?style=style=flat-square)]

Version 4.1

Installing project and dependencies : Scapy, Pexpect

```
sudo apt-get install python-scapy
#pip install pexpect
pip install paramiko
wget -q https://raw.githubusercontent.com/C3s1um133/Network-Scanner-PORT-ALIVE/master/neighbors_parser.py
chmod +x neighbors_parser.py
```

## Network scanner in Python 2.7 with Scapy using ARP for optimization.

This tool is looking for online hosts in a /24 network, remotely (an IP needs to be mentionned through the "--ip A.B.C.D" option) or locally.

Then, it will activate a search for well-known ports upon those hosts.

It's able to check a MS17-010 vulnerability on a group of remote host if 445 is found open.

```
user@host# ./neighbors_parser.py --help
usage: neighbors_parser.py [-h] [-v] [-b] [-i Adresse IP] [-w WORDLIST]
                           [-u USERNAME] [-m MODE] [-l INTEGER] [-d]

Discovery and attack only, made by Cesium133.

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -b, --bruteforce      Argument optionnel pour déclencher le mode attaque.
  -i Adresse IP, --ip Adresse IP
                        Machine cible.
  -w WORDLIST, --wordlist WORDLIST
                        Ajout d'un dictionnaire.
  -u USERNAME, --username USERNAME
                        Username distant à BF.
  -m MODE, --mode MODE  Alphabet de bruteforce [ lower | upper | digits |
                        alphabet | hex | all ].
  -l INTEGER, --longueur INTEGER
                        Longueur des mots de passe souhaitée.
  -d, --debug           Mode Debug pour le suivi de log.

GPL(v3) License.
```

## Generic usage example

```
user@host# python neighbors_parser.py --bruteforce --username foo --mode alphabet --debug  
WARNING: No route found for IPv6 destination :: (no default route?)
2017-10-03 15:26:56 INFO  [IP] 10.0.2.15

[*] Scan du réseau local:
--------------------------

[ARP] 10.0.2.0/24 sur eth0
--------------------------
2017-10-03 15:27:02 INFO  [ONLINE] 52:54:00:12:35:02  10.0.2.2
2017-10-03 15:27:03 INFO  [ONLINE] 52:54:00:12:35:03  10.0.2.3
2017-10-03 15:27:03 INFO  [ONLINE] 52:54:00:12:35:04  10.0.2.4

[*] Scan de port sur les machines ARPées:
------------------------------------------
2017-10-03 15:27:09 INFO  [PORT] En écoute : 445 sur la cible --> 10.0.2.3
2017-10-03 15:27:09 INFO  [PORT] En écoute : 445 sur la cible --> 10.0.2.2
2017-10-03 15:27:09 INFO  [PORT] En écoute : 445 sur la cible --> 10.0.2.4

[*] Résumé du scan de ports:
------------------------------
{'10.0.2.4': [445], '10.0.2.3': [445], '10.0.2.2': [445]}

[~] Pas de ports à bruteforcer [21/22/2222].

[*] Phase de capture/reconnaissance brutale:
--------------------------------------------

[SMB/CIFS] Vuln MS17-010 -> Cible avec SMB ouvert : 10.0.2.4.
2017-10-03 15:27:11 DEBUG Generate negotiate request
2017-10-03 15:27:11 DEBUG Generate session setup andx request
2017-10-03 15:27:11 DEBUG Generate tree connect andx request
2017-10-03 15:27:11 DEBUG Connecting to \\10.0.2.4\IPC$ with UID = (8,)
2017-10-03 15:27:11 DEBUG Generate peeknamedpipe request
2017-10-03 15:27:11 INFO  [~] Non détecté! (Windows 7 Professional 7601 Service Pack 1)

[SMB/CIFS] Vuln MS17-010 -> Cible avec SMB ouvert : 10.0.2.3.
2017-10-03 15:27:11 DEBUG Generate negotiate request
2017-10-03 15:27:11 DEBUG Generate session setup andx request
2017-10-03 15:27:11 DEBUG Generate tree connect andx request
2017-10-03 15:27:11 DEBUG Connecting to \\10.0.2.3\IPC$ with UID = (8,)
2017-10-03 15:27:11 DEBUG Generate peeknamedpipe request
2017-10-03 15:27:11 INFO  [~] Non détecté! (Windows 7 Professional 7601 Service Pack 1)

[SMB/CIFS] Vuln MS17-010 -> Cible avec SMB ouvert : 10.0.2.2.
2017-10-03 15:27:11 DEBUG Generate negotiate request
2017-10-03 15:27:11 DEBUG Generate session setup andx request
2017-10-03 15:27:11 DEBUG Generate tree connect andx request
2017-10-03 15:27:11 DEBUG Connecting to \\10.0.2.2\IPC$ with UID = (8,)
2017-10-03 15:27:11 DEBUG Generate peeknamedpipe request
2017-10-03 15:27:11 INFO  [~] Non détecté! (Windows 7 Professional 7601 Service Pack 1)

[+] # Job done #
```
