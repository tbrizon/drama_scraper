import re
import requests
import time
import sys
import argparse
import json
import pprint
import os

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def delay_print(s, x):
	for c in s:
		sys.stdout.write(c)
		sys.stdout.flush()
		time.sleep(x)

def ask_input(new, url, fd, name):
	b = bcolors()
	size_new = len(new)
	delay_print(b.BOLD + b.OKGREEN+ "scraping vectors on {} ".format(url), 0.01)
	delay_print("...\n" + b.ENDC,0.07)
	delay_print(b.OKGREEN + "\n{} new vectors, do you want to list them ? [y][n] ".format(size_new), 0.01)
	x = input(b.OKGREEN + "\n")
	if x == 'y' or x == 'Y':
		if size_new > 40:
			delay_print(b.BOLD + b.OKBLUE + ''.join(new) + '\n\n'+b.ENDC, 0.001)
		else:
			delay_print(b.BOLD + b.OKBLUE + ''.join(new) + '\n\n'+b.ENDC, 0.01)
		delay_print(b.OKGREEN + "do you want to continue with this vectors ?", 0.02)
		x = input("[y][n] ")
		if x == 'n' or x == 'N':
			return (0)
	if x == 'n' or x == 'y':
		delay_print(b.OKGREEN+"you can exit by presing [q]\n",0.02)
		delay_print("vectors gonna be write in ./data/XSS_scraped_all.vectors, you can personalise your path if you want to by entering your path.\n", 0.015)
		delay_print("WARNING : new vectors will always get compared in the file XSS_scraped_all.vectors (atm)\n", 0.015)
		delay_print("if you want the default path press enter\n",0.02)
		x = input("" + b.OKGREEN)
		print(b.ENDC)
		if x == '':
			delay_print(b.OKGREEN + "writting on ./data/XSS_scraped_all.vectors\n" + '\n', 0.01)
			fd.write(''.join(new))
			delay_print(b.OKGREEN + "do you want to print a copy in a ./data/XSS_{}_scraped.vectors file (to separate vectors from different url) ? ".format(name), 0.015)
			cp = input("[y][n] \n")
			if cp == 'y':
				cp = open('./data/XSS_{}_scraped.vectors'.format(name), 'w+')
				cp.write(''.join(new))
				delay_print("writing ...", 0.040)
		if x == 'q':
			delay_print(b.WARNING + "exit ..." + b.ENDC, 0.1)
			return (0)
		elif x != '':
			delay_print(b.BOLD + b.OKGREEN + "writting on " + x + '\n', 0.01)
			fd = open(x, 'w+')
			fd.write(''.join(new))
		delay_print(b.WARNING + b.BOLD + "\ncheck out your file, it should be filled correctly\nsee ya !"+'\n'+b.ENDC, 0.02)
	else:
		delay_print(b.WARNING + "command not found, abort..." + b.ENDC, 0.03)

def adjust(dest_fd, content_lst):
	data = dest_fd.readlines()
	content = set()
	if type(content_lst[0]) == list:
		for x in range(len(content_lst)):
			content |= set(content_lst[x])
	else:
		content |= set(content_lst)
	content.discard('\n')
	new = [diff for diff in content if diff not in data]
	return (new)

def	decode(content_lst):
	encoding = {
		'&lt;' : '<',
		'&gt;' : '>',
		'&amp;' : '&',
		'&quot;' : '"',
		'&#39;' : "'"
		}

		
	for x in range(len(content_lst)):
		for y in range(len(content_lst[x])):
			for encode, decode in encoding.items():
				content_lst[x][y] = content_lst[x][y].replace(encode, decode)
			content_lst[x][y] += '\n'

def scraper_portswigger(url, dest_fd):
	vectors_interaction = []
	vectors_no_interaction = []
	vectors = requests.get(url)
	a = vectors.text.strip('var data = ')
	size = len(a)
	vectors = json.loads(a[:size - 1])
	for item_key, item_value in vectors.items():
			for tags in item_value['tags']:
				if tags['interaction'] == False:
					vectors_no_interaction.append(tags['code'] + ' # ' + ' '.join(tags['browsers']) +  '\n')
				else:
					vectors_interaction.append(tags['code'] + ' # ' + ' '.join(tags['browsers']) + '[interaction needed]'+ '\n')
	vectors =  vectors_interaction + vectors_no_interaction
	vectors = adjust(dest_fd, vectors)
	return (vectors)

def	scraper_owasp(url, dest_fd):
	patterns = {
	'owasp' : [re.compile('<code>(.*)\s</code>') ,
				re.compile('<code class="language-plaintext highlighter-rouge">(.*)</code>'),
				re.compile('<code class="language-plaintext highlighter-rouge">(.*)\s</code>')]
	}
	scraped = requests.get(url)
	vectors = []
	scraped_str = scraped.text
	for sitename, regex in patterns.items():
		for x in regex:
			vectors.append(x.findall(scraped_str))
	decode(vectors)
	del vectors[0]
	vectors = adjust(dest_fd, vectors)
	return (vectors)

def	scraper(name):
	sources = {
		'owasp' :  "https://owasp.org/www-community/xss-filter-evasion-cheatsheet",
		'portswigger' : "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet-data.js"
	}
	dest_fd = open("./data/XSS_scraped_all.vectors", 'a+')
	dest_fd.close()
	dest_fd = open("./data/XSS_scraped_all.vectors", 'r+')
	try:
		if name not in sources.keys():
			raise ZeroDivisionError
		url = sources[name]
		if name == 'portswigger':
			vectors = scraper_portswigger(url, dest_fd)
		if name == 'owasp':
			vectors = scraper_owasp(url, dest_fd)
		ask_input(vectors,url,dest_fd,name)
	except ZeroDivisionError:
		print("only owasp ({}) and portswigger ({}) are available".format(sources['owasp'], sources['portswigger']))



if __name__ == "__main__":
	argument = argparse.ArgumentParser()
	argument.add_argument("-a", "--all", help="launch the scraper for all the site name available", action="store_true")
	argument.add_argument("-n", "--name", help="laumch the scraper for the site name, if not found, return error", type=str)
	args = argument.parse_args()
	if not os.path.isdir('./data'):
		delay_print(bcolors.OKGREEN + "creating a data directory to collect vectors\n\n" , 0.01)
		os.mkdir('data')
	if args.all == True:
			x = input("scraper to portsigger and owasp ? ")
			if x == '':
				scraper('owasp')
				scraper('portswigger')
	else:
		scraper(args.name)