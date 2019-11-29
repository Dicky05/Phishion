import whois
import dns.resolver
from datetime import datetime
from urllib.parse import urlparse
import urllib.request
import shutil
import re
import sys
import xmltodict
import json
import socket
import csv
from termcolor import colored

print(colored('        _     _     _     _             ', 'grey', attrs=['bold']))
print(colored('  ____ | |___(_)___| |___(_) ___  _____ ', 'grey', attrs=['bold']))
print(colored(' /  _ \|  _  | /  _)  _  | |/ _ \/  _  |', 'grey', attrs=['bold']))
print(colored(' | (_) | | | | | (_| | | | | (_) | | | |', 'grey', attrs=['bold']))
print(colored(' |  __/|_| |_|_|__ |_| |_| |\___/|_| |_|', 'grey', attrs=['bold']))
print(colored(' |_|-----------(___/-PHISHING-DETECTION-', 'grey', attrs=['bold']))

while(True):
	url = input(colored('\n INPUT URL: ', 'grey', attrs=['bold']))
	print(colored(' =======================================', 'grey', attrs=['bold']))
	regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
	check_url = re.match(regex, url) is not None
	
	if check_url == True:
		break
	else:
		print(colored(' Your Input is Not URL', 'red'))

print(colored(' 1. LINEAR', 'grey'))
print(colored(' 2. POLYNOMIAL', 'grey'))
print(colored(' 3. RBF', 'grey'))
pilih_kernel = input(colored(' Pilih Kernel 	: ', 'grey', attrs=['bold']))
kernel = int(pilih_kernel)
print(colored(' =======================================', 'grey', attrs=['bold']))

t1 = datetime.now()
obj = urlparse(url)
hostname = obj.hostname
try:
	pywhois = whois.whois(hostname)
except:
	next

reader = csv.reader(open('data_testing.csv'))
lines = list(reader)

#Having IP Address
print(colored('\n USING IP ADDRESS', 'grey', attrs=['bold']))
is_valid = re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", hostname)
if is_valid == None:
	lines[1][0] = '-1'
	print(colored(' [-1]', 'green'),'Legitimate')
else:
	lines[1][0] = '1'
	print(colored(' [1]', 'red'),'Phising')

#Panjang URL
print(colored(' URL LENGTH', 'grey', attrs=['bold']))
if len(url)<54:
	lines[1][1] = '-1'
	print(colored(' [-1]', 'green'),'Legitimate')																																																																																																																																																																																																																																																																																
elif len(url)<75:
	lines[1][1] = '0'
	print(colored(' [0]', 'yellow'),'Suspicious')
else:
	lines[1][1] = '1'
	print(colored(' [1]', 'red'),'Phising')

#URL Shortening Services
print(colored(' URL SHORTENING SERVICES', 'grey', attrs=['bold']))
urlss = [
      'bit.ly',
      'goo.gl',
      'tinyurl.com',
      'buff.ly',
      'adf.ly',
      'ow.ly',
      'polr.me',
      'is.gd',
      'soo.gd',
      's2r.co'
]
for tinyurl in urlss:
  find_tinyurl = hostname.find(tinyurl)
  if find_tinyurl !=-1:
  	break

if find_tinyurl !=-1:
	lines[1][2] = '1'
	print(colored(' [1]', 'red'),'Phising')
else:
	lines[1][2] = '-1'
	print(colored(' [-1]', 'green'),'Legitimate')

#Simbol "@"
print(colored(' SIMBOL "@"', 'grey', attrs=['bold']))
if url.find('@')!=-1:
	lines[1][3] = '1'
	print(colored(' [1]', 'red'),'Phising')
else:
	lines[1][3] = '-1'
	print(colored(' [-1]', 'green'),'Legitimate')

#Simbol "//"
print(colored(' SIMBOL "//"', 'grey', attrs=['bold']))
if url.find('//')>7:
	lines[1][4] = '1'
	print(colored(' [1]', 'red'),'Phising')
else:
	lines[1][4] = '-1'
	print(colored(' [-1]', 'green'),'Legitimate')

#Simbol "-"
print(colored(' SIMBOL "-"', 'grey', attrs=['bold']))		
if hostname.find('-')!=-1:
	lines[1][5] = '1'
	print(colored(' [1]', 'red'),'Phising')
else:
	lines[1][5] = '-1'
	print(colored(' [-1]', 'green'),'Legitimate')

#Sub Domain
print(colored(' SUB DOMAIN', 'grey', attrs=['bold']))																		
negara_TLD = [
			'.ac.',
			'.co.',
			'.desa.',
			'.or.',
			'.net.',
			'.web.',
			'.sch.',
			'.go.'
]
for tld in negara_TLD:
	find_tld = hostname.find(tld)
	if find_tld !=-1:
		break

if hostname.count('.')==1:
	lines[1][6] = '-1'
	print(colored(' [-1]', 'green'),'Legitimate [a]')
elif find_tld !=-1:
	titik = hostname.count('.')-1
	if titik==1:
		lines[1][6] = '-1'
		print(colored(' [-1]', 'green'),'Legitimate [b]')
	elif titik ==2:
		lines[1][6] = '0'
		print(colored(' [0]', 'yellow'),'Suspicious [a]')
	else:
		lines[1][6] = '1'
		print(colored(' [1]', 'red'),'Phising [a]')
elif hostname.count('.')==2:
	lines[1][6] = '0'
	print(colored(' [0]', 'yellow'),'Suspicious [b]')
else:
	lines[1][6] = '1'
	print(colored(' [1]', 'red'),'Phising [b]')

#Domain Registration Length
print(colored(' DOMAIN REGISTRATION LENGTH', 'grey', attrs=['bold']))
try:
	cd = pywhois.creation_date
	ud = pywhois.updated_date
	ed = pywhois.expiration_date

	try:
		if ud == None:
			tahun1 = cd.year
			tahun3 = ed.year
			drl = tahun3-tahun1
		elif type(ud) == list:
			string = str(ud)
			d = string[19:23]
			tahun3 = ed.year
			drl = tahun3 - int(d)
		else:
			tahun2 = ud.year
			tahun3 = ed.year
			drl = tahun3-tahun2
	except:
		s = ed[8:12]
		tahun1 = cd.year
		drl = int(s)-tahun1

	try:
		if drl <= 1:
			lines[1][7] = '1'
			print(colored(' [1]', 'red'),'Phising [a]')
		else:
			lines[1][7] = '-1'
			print(colored(' [-1]', 'green'),'Legitimate')
	except:
		lines[1][7] = '1'
		print(colored(' [1]', 'red'),'Phising [b]')
except:
	lines[1][7] = '1'
	print(colored(' [1]', 'red'),'Phising [c]')

#HTTPS Token
print(colored(' HTTPS TOKEN', 'grey', attrs=['bold']))
if hostname.find('https')!=-1:
	lines[1][8] = '1'
	print(colored(' [1]', 'red'),'Phising')
else:
	lines[1][8] = '-1'
	print(colored(' [-1]', 'green'),'Legitimate')

#SITE, DRC, IFR
try:
	page = urllib.request.urlopen(url)

	f = open('page_source.txt', 'wb')
	shutil.copyfileobj(page, f)

	print(colored(' SUBMITTING INFORMATION TO EMAIL', 'grey', attrs=['bold']))
	with open('page_source.txt', 'r') as site:
		if 'mail()' in site.read():
			lines[1][9] = '1'
			print(colored(' [1]', 'red'),'Phising [a]')
		elif 'mailto:' in site.read():
			lines[1][9] = '1'
			print(colored(' [1]', 'red'),'Phising [b]')
		else:
			lines[1][9] = '-1'
			print(colored(' [-1]', 'green'),'Legitimate')

	print(colored(' DISABLE RIGHT CLICK', 'grey', attrs=['bold']))
	with open('page_source.txt', 'r') as drc:
		if 'contextmenu' in drc.read():
			lines[1][10] = '1'
			print(colored(' [1]', 'red'),'Phising [a]')
		else:
			lines[1][10] = '-1'
			print(colored(' [-1]', 'green'),'Legitimate')

	print(colored(' IFRAME REDIRECTION', 'grey', attrs=['bold']))
	with open('page_source.txt', 'r') as ifr:
		if '<iframe' in ifr.read():
			lines[1][11] = '1'
			print(colored(' [1]', 'red'),'Phising [a]')
		else:
			lines[1][11] = '-1'
			print(colored(' [-1]', 'green'),'Legitimate')
except:
	print(colored(' SUBMITTING INFORMATION TO EMAIL', 'grey', attrs=['bold']))
	lines[1][9] = '1'
	print(colored(' [1]', 'red'),'Phising [c]')
	print(colored(' DISABLE RIGHT CLICK', 'grey', attrs=['bold']))
	lines[1][10] = '1'
	print(colored(' [1]', 'red'),'Phising [b]')
	print(colored(' IFRAME REDIRECTION', 'grey', attrs=['bold']))
	lines[1][11] = '1'
	print(colored(' [1]', 'red'),'Phising [b]')

#Age of Domain
print(colored(' AGE OF DOMAIN', 'grey', attrs=['bold']))
dn = datetime.now()
try:
	cd = pywhois.creation_date
	try:
		tahun1 = dn.year
		tahun2 = cd.year
		bulan1 = dn.month
		bulan2 = cd.month
		tahunaod = (tahun1-tahun2)*12
		bulanaod = bulan1-bulan2
		aod = tahunaod-bulanaod
	except:
		next

	try:
		if aod >= 6:
			lines[1][12] = '-1'
			print(colored(' [-1]', 'green'),'Legitimate')
		else:
			lines[1][12] = '1'
			print(colored(' [1]', 'red'),'Phising [a]')
	except:
		lines[1][12] = '1'
		print(colored(' [1]', 'red'),'Phising [b]')
except:
	lines[1][12] = '1'
	print(colored(' [1]', 'red'),'Phising [c]')

#DNS Records
print(colored(' DNS RECORDS', 'grey', attrs=['bold']))
def get_records():
    ids = [
        'CNAME',
        'MX',
        'NS',
        'PTR',
        'SRV',
        'SOA',
        'TXT',
    ]
    for a in ids:
    	try:
    		answers = dns.resolver.query(hostname, a)
    		return answers
    	except:
    		pass
    		
dns_record = get_records()

if dns_record is None:
	lines[1][13] = '-1'
	print(colored(' [-1]', 'red'),'Phising')
else:
	lines[1][13] = '1'
	print(colored(' [1]', 'green'),'Legitimate')

#Website Traffic
xml = urllib.request.urlopen('http://data.alexa.com/data?cli=10&dat=s&url={}'.format(url)).read()
 
result= xmltodict.parse(xml)
 
data = json.dumps(result).replace("@","")
data_tojson = json.loads(data)

print(colored(' WEBSITE TRAFFIC', 'grey', attrs=['bold']))
try:
	url = data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["URL"]
	rank= data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["TEXT"]

	if int(rank) < 100000:
		lines[1][14] = '0'
		print(colored(' [0]', 'green'),'Legitimate')
	else:
		lines[1][14] = '-1'
		print(colored(' [-1]', 'yellow'),'Suspicious')
except:
	lines[1][14] = '1'
	print(colored(' [1]', 'red'),'Phising')

#Statistical-Reports Based Features
print(colored(' STATISTICAL-REPORTS BASED FEATURES', 'grey', attrs=['bold']))
ipaddrs = socket.gethostbyname(hostname)

top_domains = [
      'esy.es',
      'hol.es',
      '000webhostapp.com',
      '16mb.com',
      'bit.ly',
      'for-our.info',
      'beget.tech',
      'blogspot.com',
      'weebly.com',
      'raymannag.ch',
]
for domain in top_domains:
  find_domain = hostname.find(domain)
  if find_domain !=-1:
  	break

with open('top_ips.csv', 'r') as top_ips:
  if str(ipaddrs) in top_ips.read():
  	lines[1][15] = '1'
  	print(colored(' [1]', 'red'),'Phising [a]')
  elif find_domain !=-1:
  	lines[1][15] = '1'
  	print(colored(' [1]', 'red'),'Phising [b]')
  else:
  	lines[1][15] = '-1'
  	print(colored(' [-1]', 'green'),'Legitimate')

with open('data_testing.csv', 'w') as f:
	writer = csv.writer(f)
	writer.writerows(lines)
f.close()

import numpy as np
import pandas as pd
from sklearn.svm import SVC
import pickle

# Load model
if kernel == 1:
	loaded_model = pickle.load(open('model_l.sav', 'rb'))
elif kernel == 2:
	loaded_model = pickle.load(open('model_p.sav', 'rb'))
elif kernel == 3:
	loaded_model = pickle.load(open('model_r.sav', 'rb'))
else:
	loaded_model = pickle.load(open('model_p.sav', 'rb'))

x_predict = pd.read_csv('data_testing.csv')
b = np.array(x_predict)
y_predict = b[0:,:16]

prediksi = loaded_model.predict(y_predict)
score = loaded_model.decision_function(y_predict)
non_phish = ((1-score)/2)*100
phish = (100-non_phish)

print(colored('\n RESULT:', 'grey', attrs=['bold']))
print(colored(' =======================================', 'grey', attrs=['bold']))
print(colored(' PHISHING PERCENTAGE : %.2f' % phish, 'grey',attrs=['bold']),colored('%','grey', attrs=['bold']))
if prediksi == 1:
	print('',colored(prediksi,'red', attrs=['bold']),colored(' PHISHING', 'red', attrs=['bold']))
else:
	print('',colored(prediksi, 'green', attrs=['bold']),colored(' NON PHISHING', 'green', attrs=['bold']))

t2 = datetime.now()
total =  t2 - t1
print(colored('\n Scanning Completed in: ', 'grey'), colored(total, 'grey'))