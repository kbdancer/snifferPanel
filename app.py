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

	if not os.path.isfile('/usr/bin/create_ap'):
		install = raw_input('[?] create_ap not found in /usr/bin/create_ap, install now? [y/n] ')
		if install == 'y':
			os.system('cd /tmp && git clone https://github.com/oblique/create_ap.git && cd create_ap && make install')
		else:
			sys.exit('[x] create_ap not found in /usr/bin/create_ap')
	else:
		print '[√] create_ap has been installed.'

	if not os.path.isfile('/usr/bin/pip'):
		install = raw_input('[?]  pip not found in /usr/bin/pip, install now? [y/n] ')
		if install == 'y':
			os.system('cd /tmp && wget https://bootstrap.pypa.io/get-pip.py')
			os.system('python /tmp/get-pip.py')
		else:
			sys.exit('[x] pip not found in /usr/bin/pip')
	else:
		print '[√] pip has been installed.'

	# update pip and python modules

	try:
		os.system('pip install -U pip')
	except:
		sys.exit('[x] update pip failed.')

	try:
		__import__('scapy')
		print '[√] module scapy been installed.'
	except:
		install = raw_input('[?] module scapy not found in python, install now? [y/n] ')
		if install == 'y':
			os.system('pip install -U scapy')
		else:
			sys.exit('[x] No module named scapy')

	try:
		os.system('pip install -U email')
	except:
		sys.exit('[x] update email failed.')

def doCreate():
	net_iface = 'eth0'
	ap_iface = 'wlan0'
	ap_ssid = 'hysund_dev'
	ap_key = 'hysunddev1102'
	ap_getway = '192.168.0.1'
	ap_dns = '8.8.8.8'
	try:
		os.system('create_ap %s %s %s %s -g %s --dhcp-dns %s --no-virt' % (ap_iface,net_iface,ap_ssid,ap_key,ap_getway,ap_dns))
	except Exception,e:
		sys.exit('[x] Create AP failed! Please check!')

def dosniff():
	try:
		subprocess.Popen(['python',sys.path[0]+'/sniff.py'])
	except Exception,e:
		sys.exit('[x] do sniff failed.Exception is %s' % e)

if __name__ == '__main__':
	print "================================================="
	print "|Create by MonkeyChain			   	|"
	print "|Blog www.92ez.com Email non3gov@gmail.com	|"
	print "|You should know what you are doing.	  	|"
	print "================================================="

	print '\n[*] Checking required...\n'
	checkInstall()
	print '\n[*] Required checked!\n'

	print '[*] Start sniffing!'
	dosniff()

	print '[*] Creating an AP!'
	doCreate()