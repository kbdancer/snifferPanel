#!/usr/bin/env python
# coding=utf-8
# code by 92ez.com

from scapy.all import *
import sys
import os

def checkInstall():
	if not os.path.isfile('/usr/sbin/hostapd'):
		install = raw_input('[?]  hostapd not found in /usr/sbin/hostapd, install now? [y/n] ')
		if install == 'y':
			os.system('apt-get -y install hostapd')
		else:
			sys.exit('[x] hostapd not found in /usr/sbin/hostapd')
			return
	else:
		print '[√] hostapd has been installed.'

	if not os.path.isfile('/usr/bin/dnsmap'):
		install = raw_input('[?]  dnsmap not found in /usr/bin/dnsmap, install now? [y/n] ')
		if install == 'y':
			os.system('apt-get -y install dnsmap')
		else:
			sys.exit('[x] dnsmap not found in /usr/bin/dnsmap')
			return
	else:
		print '[√] dnsmap has been installed.'

	if not os.path.isfile('/usr/bin/gcc'):
		install = raw_input('[?]  dnsmap not found in /usr/bin/gcc, install now? [y/n] ')
		if install == 'y':
			os.system('apt-get -y install gcc')
		else:
			sys.exit('[x] gcc not found in /usr/bin/gcc')
			return
	else:
		print '[√] gcc has been installed.'

	if not os.path.isfile('/usr/bin/make'):
		install = raw_input('[?]  make not found in /usr/bin/make, install now? [y/n] ')
		if install == 'y':
			os.system('apt-get -y install make')
		else:
			sys.exit('[x] make not found in /usr/bin/make')
			return
	else:
		print '[√] make has been installed.'

	if not os.path.isfile('/usr/bin/create_ap'):
		install = raw_input('[?]  create_ap not found in /usr/bin/create_ap, install now? [y/n] ')
		if install == 'y':
			os.system('mkdir /tmp/Git && cd /tmp/Git')
			os.system('git clone https://github.com/oblique/create_ap.git && cd create_ap')
			os.system('make install')
		else:
			sys.exit('[x] create_ap not found in /usr/bin/create_ap')
			return
	else:
		print '[√] create_ap has been installed.'

	if not os.path.isfile('/usr/bin/pip'):
		install = raw_input('[?]  pip not found in /usr/bin/pip, install now? [y/n] ')
		if install == 'y':
			os.system('cd /tmp && wget https://bootstrap.pypa.io/get-pip.py')
			os.system('python /tmp/get-pip.py')
		else:
			sys.exit('[x] pip not found in /usr/bin/pip')
			return
	else:
		print '[√] pip has been installed.'

	try:
		__import__('scapy')
		print '[√] module scapy been installed.'
	except:
		sys.exit('[x] No module named scapy')
		return

def dealPackage(packet):
	
	lines = packet.sprintf("{Raw:%Raw.load%}").replace("'","").split(r"\r\n")
	
	if len(lines[-1]) > 1 and len(lines) > 1:
		print '-'*90
		for line in lines:
			print line
	# a_request = []

	# host = ''
	# uri = ''
	# rtype = ''
	# ua = ''
	# referer = 'null'
	# cookie = 'null'
	# for line in lines:
	#	 if 'HTTP/1' in line:
	#		 rtype = line.split()[0].replace("'","")
	#		 uri = line.split()[1]
	#	 if 'Host' in line:
	#		 host = line.split(': ')[1]
	#	 if 'User-Agent' in line:
	#		 ua = line.split(': ')[1]
	#	 if 'Referer' in line:
	#		 referer = line.split('Referer: ')[1]
	#	 if 'Cookie' in line:
	#		 cookie = line.split('Cookie: ')[1]

def dosniff():
	sniff(iface = 'eth0',prn = dealPackage,lfilter=lambda p: "GET" in str(p) or "POST" in str(p),filter="tcp")

if __name__ == '__main__':
	print "================================================="
	print "|Create by MonkeyChain			   	|"
	print "|Blog www.92ez.com Email non3gov@gmail.com	|"
	print "|You should know what you are doing.	  	|"
	print "================================================="

	print '\n[*] Checking required...\n'

	checkInstall()

	print '\n[*] Checking required finished !'
	print '[*] Start sniff !\n'
	dosniff()