import sys
import requests 
import urllib3 
import sys 
import json 
import re  
import hashlib  
import os
import subprocess
import argparse
import platform
import urllib
from time import sleep
from six.moves import input
CheckVersion = str(sys.version)

normal_color = "\33[00m"
info_color = "\033[1;33m"
red_color = "\033[1;31m"
green_color = "\033[1;32m"
whiteB_color = "\033[1;37m"
detect_color = "\033[1;34m"
banner_color="\033[1;33;40m"
end_banner_color="\33[00m"
onlyPasswords = False



def checkArgs():
	parser = argparse.ArgumentParser()
	parser.add_argument('-a', "--account", action="store",
						dest='account',
	                    help="user_account")
	parser.add_argument('-n', "--number", action="store",
						dest='user',
	                    help="number_snap")
	parser.add_argument('-k', "--kod", action="store",
						dest='kod',
						help="The name of the country to which the number belongs")
	parser.add_argument('-e', "--email", action="store",
						dest='email',
	                    help="Email address to search.")
	parser.add_argument('-f', "--file", action="store",
						dest='file',
	                    help="File with email accounts to search leaks.")
	parser.add_argument('-d', "--domain", action="store",
						dest='domain',
	                    help="Domain to search email leaks")
	parser.add_argument('-t', "--tor", action="store_true",
	                    help="Use Tor to search leaks in onion sites, need also set the domain or file.")
	parser.add_argument('-oP', "--onlyPasswords", action="store_true",
	                    help="Return only the ouput in format -> user@domain:password.")
	parser.add_argument('-mD', "--makeDict", action="store_true",
                        help="Make a Dictionary with some username masks, only works with -d or with -oP option")
	parser.add_argument('-p', "--pgp", action="store_true",
						dest='pgp',
                        help="Obtain pgp key if exists")
	args = parser.parse_args()
	if (len(sys.argv)==1) or (args.tor==True and (not args.email and not args.file and not args.domain)):
		parser.print_help(sys.stderr)
		sys.exit(1)
	return args


print(info_color +'''

88888888888       8888888888 .d8888b.           
    888           888       d88P  Y88b          
    888           888              888          
    888   8888b.  8888888        .d88P 888  888 
    888      "88b 888        .od888P"  888  888 
    888  .d888888 888       d88P"      Y88  88P 
    888  888  888 888       888"        Y8bd8P  
    888  "Y888888 888       888888888    Y88P   

''')
print('''
++ The developer : Falah - 0xfff080 ++

snapchat : flaah999

-----------------------------------
''')

def check_email(email):
	if not onlyPasswords:
		print(whiteB_color + "----------------------------------------\nالتحقق من حساب البريد الإلكتروني " + email + " ...\n----------------------------------------")
	pattern = "(^[a-zA-Z-0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
	result = re.match(pattern, email)
	if (result):
		if not onlyPasswords:
			try:
				check_firefox_monitor(email)
				print (" ")
				check_pastebinLeaks(email)
				print (" ")
				emailreputation(email)
				print (" ")
				sistema = format(platform.system())
				if (sistema == "Linux"):
        	                        haveibeenpwned(email)
				print (" ")
			except:
				pass
		if (args.tor):
			tor_main(email)
			print (" ")

		#Search this user in possible social media accounts
		try:
			thatsthem(email)
			publicemailrecords(email)
			usersearch(email)
		except:
			pass

	else:
		print(red_color + "Error: " + email + " is not a valid email (bad format email)" + normal_color)
	if not onlyPasswords:
		print(whiteB_color + "----------------------------------------\n----------------------------------------")



def parse_firefox_monitor(response):
    start_breachName = response.text.find("breach-title")
    leaks = False
    while start_breachName != -1:
        leaks = True
        print(whiteB_color +"!!! تم الكشف عن ")
        start_breachName = start_breachName + 14
        end_breachName = response.text.find("</span>", start_breachName)
        print(red_color + "--> " + response.text[start_breachName:end_breachName])
        end_key = end_breachName
        start_index = response.text.find("breach-key", end_key) + 12
        while start_index > 12 and (start_index < response.text.find("breach-title", start_breachName + 12) or response.text.find("breach-title", start_breachName + 12) < 12):
            end_index = response.text.find("</span>", start_index)
            start_key = response.text.find("breach-value", end_index) + 14
            end_key = response.text.find("</span>", start_key)
            value = response.text[start_index:end_index]
            key = response.text[start_key:end_key]
            print("\t\t- " + value + " " + key)
            start_index = response.text.find("breach-key", end_key) + 12
        start_breachName = response.text.find("breach-title", end_breachName)
    if not leaks:
        print(green_color + "This email account not appears on Firefox Monitor")


def check_firefox_monitor(email):
    print(info_color + "--------------------\nChecking on Firefox Monitor...\n--------------------")
    # Extract valid csrf token from request.
    url_form = 'https://monitor.firefox.com'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5"}
    client = requests.Session()
    client.headers.update(headers)
    response = client.get(url_form, proxies=tor_proxy)
    inicio_csrf = response.text.find("_csrf")
    if (inicio_csrf != -1):
        inicio_csrf = response.text.find("value", inicio_csrf)
        if (inicio_csrf != -1):
            inicio_csrf = inicio_csrf + 7
            fin_csrf = response.text.find("\"", inicio_csrf)
            csrfToken = response.text[inicio_csrf:fin_csrf]
            inicio_scannedEmailId = response.text.find("scannedEmailId")
            inicio_scannedEmailId = response.text.find("value",inicio_scannedEmailId)
            inicio_scannedEmailId = inicio_scannedEmailId+7
            fin_scannedEmailId = response.text.find("\"",inicio_scannedEmailId)
            scannedEmailID = response.text[inicio_scannedEmailId:fin_scannedEmailId]
            emailHash = hashlib.sha1(bytes(email, "utf8"))
            emailHash = emailHash.hexdigest().upper()
            # Do the query
            url = "https://monitor.firefox.com/scan"
            params = {"_csrf": csrfToken, "email": email, "pageToken": "", "scannedEmailId": scannedEmailID, "emailHash": emailHash}
            response = client.post(url, params, proxies=tor_proxy)
            client.close()
            parse_firefox_monitor(response)
    else:
        print(red_color + "Error: It was not possible to access firefox monitor (there is a limit of requests per hour)")


def check_pastebinLeaks(email):
	print(info_color + "--------------------\nChecking on pastebin leaks...\n--------------------")
	r = requests.get("https://psbdmp.ws/api/search/" + email)
	resp_json = json.loads(r.text)

	total = resp_json["count"]
	if (total > 0):
		print(whiteB_color + "This email account appears on pastebin in " + red_color + str(
			total) +  whiteB_color + " results listed bellow:" + red_color)
		cont = 0
		while (cont <= (total - 1)):
			link = "\thttps://pastebin.com/" + str(resp_json["data"][cont]["id"])
			print(link)
			cont = cont + 1
	else:
		print(green_color + "This email account not appears on pastebin leaks")


def emailreputation(email):
	print(info_color + "--------------------\nChecking on emailrep.io...\n--------------------")
	response = requests.get('https://emailrep.io/' + email, proxies=tor_proxy)
	emailreputation = json.loads(response.text)
	try:
		reputation = emailreputation["reputation"]
		credentials_leaked = emailreputation["details"]["credentials_leaked"]
		data_breach = emailreputation["details"]["data_breach"]
		last_seen = emailreputation["details"]["last_seen"]
		if (credentials_leaked == True or data_breach == True):
			print(whiteB_color + "This email account has " + red_color + reputation + " reputation\n" +
				whiteB_color + "Credentials leaked? " + red_color + str(
				credentials_leaked) + whiteB_color + "\nHas data breach? " + red_color + str(data_breach) +
				whiteB_color + "\nLast seen: " + red_color + str(last_seen))
		else:
			print(green_color + "This email account has " + reputation + " reputation\nCredentials leaked? " + str(
				credentials_leaked) + "\nHas data breach? " + str(data_breach))
	except:
		print(red_color + "Error: " + emailreputation["reason"])


#Search have I been pwned.
def haveibeenpwned(email):
	print(info_color + "--------------------\nChecking breaches on haveibeenpwned.com...\n--------------------")

	email = email.replace("@","%40") #Replace @ with url encode character
	url = "https://haveibeenpwned.com/unifiedsearch/" + email
	headers = {
		'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5"}
	client = requests.Session()
	client.headers.update(headers)
	response = client.get(url, proxies=None)
	total = 0
	try:
		resp_json = json.loads(response.text)

		inicio = 0
		total = 0
		while (inicio != -1):
			inicio = response.text.find("BreachDate", inicio)
			if (inicio != -1):
				total = total + 1
			inicio = response.text.find("BreachDate", inicio+1)

		print(whiteB_color+"Total leaks detected on haveIbeenpwned: " + red_color + str(total))
		cont = 0

		while (cont < total):
			print(whiteB_color +"Leak Detected!!!" + "\n" + red_color + "--> " + resp_json["Breaches"][cont]["Name"] + "\n\t" + red_color + "- Breach Date:" + resp_json["Breaches"][cont]["BreachDate"]+"\n\t- Is Verified? "+ str(resp_json["Breaches"][cont]["IsVerified"]))
			cont = cont + 1
	except:
		pass

	if (total == 0):
		print (green_color + "No breaches detected in have I been pwned")

#Search account into publicemailrecords.
def publicemailrecords(email):
	flag = 0
	url = 'http://publicemailrecords.com/find_emails'
	headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5"}
	client = requests.Session()
	client.headers.update(headers)
	params = {"email": email}
	response = client.post(url, params, proxies=tor_proxy)

	#print (response.text)

	inicio = response.text.find("Best estimate address")
	if (inicio != -1):
		inicio = response.text.find(":", inicio)
		inicio = inicio + 1
		fin = response.text.find(",", inicio)
		if (fin != -1):
			location = response.text[inicio:fin]

	inicio = response.text.find('id="hidden-address" value="')
	if (inicio != -1):
		inicio = inicio + 29
		fin = response.text.find(", HI", inicio)
		if (fin != -1):
			address = response.text[inicio:fin]
			address = address.replace("n?", "nº")

	inicio = 0
	while (inicio != -1):
		inicio = response.text.find("<h2>", inicio)
		if (inicio != -1):
			inicio2 = response.text.find("results")
			if (inicio2 == -1):
				inicio = inicio + 4
				fin = response.text.find("</h2>", inicio)
				if (fin != -1):
					owner = response.text[inicio:fin]
					flag = 1
			else:
				inicio = response.text.find("<h2>", inicio+1)


	if (flag == 1):
		print(info_color + "--------------------\nChecking personal information about this email account in publicemailrecords.com ...\n--------------------")
		print(green_color + "The owner of this email account is: " + owner)
		print(green_color + "The location of " + owner + " is: " + address)
		print(" ")

	client.close()


def usersearch(email):
	fin = email.find("@")
	user = email[0:fin]

	print(info_color + "--------------------\nChecking social media possible accounts for this email address in usersearch.org ...\n--------------------")

	url = 'https://usersearch.org/results_normal.php'
	headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5"}
	client = requests.Session()
	client.headers.update(headers)
	params = {"ran":"5ef471c71ae996.70559847","username": user}
	response = client.post(url, params, proxies=tor_proxy)

	inicio = response.text.find('<div class="results-button-wrapper"')
	while (inicio != -1):
		inicio = response.text.find("http", inicio)
		if (inicio != -1):
			fin = response.text.find("target", inicio)
			if (fin != -1):
				socialmedia = response.text[inicio:fin-2]
				print(whiteB_color + "It's possible that the user has the following social media account: " + green_color + socialmedia)
		inicio = response.text.find('<div class="results-button-wrapper"', fin)

	gitlab(email)

def thatsthem(email):
	email = email.replace("@","%40") #Replace @ with url encode character
	url = 'https://thatsthem.com/email/' + email
	headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5"}
	client = requests.Session() #Make a Dictionary with some username masks, only works with -d or with -oP option
	client.headers.update(headers)
	response = client.get(url, proxies=None)

	flag = 0
	inicio = 0
	while (flag < 3):
		inicio = response.text.find('<span itemprop="name">', inicio+1)
		flag = flag + 1

	inicio = response.text.find('<span itemprop="name">', inicio+1)
	if (inicio != -1):
		inicio = response.text.find(">",inicio)
		fin = response.text.find("</", inicio)
		if (fin != -1):
			owner = response.text[inicio+1:fin]

	inicio = response.text.find('itemprop="streetAddress">')
	if (inicio != -1):
		inicio = response.text.find(">", inicio)
		fin = response.text.find("<", inicio)
		if (fin != -1):
			address = response.text[inicio+1:fin]


	inicio = response.text.find('itemprop="addressLocality">')
	if (inicio != -1):
		inicio = response.text.find(">", inicio)
		fin = response.text.find("<", inicio)
		if (fin != -1):
			city = response.text[inicio+1:fin]

	inicio = response.text.find('itemprop="postalCode">')
	if (inicio != -1):
                inicio = response.text.find(">", inicio)
                fin = response.text.find("<", inicio)
                if (fin != -1):
                        postalcode = response.text[inicio+1:fin]
                        print(info_color + "--------------------\nChecking personal information about this email account in thatsthem.com ...\n--------------------")
                        print(green_color + "The owner of this email account is: " + owner)
                        print(green_color + "The location of " + owner + " is: " + address + " from " + city + ", " + str(postalcode))
                        print(" ")






###### Tor leaks fonts
def pwndb_main(source, is_domain):
	session = requests.session()
	session.proxies = tor_proxy
	leaks = pwndb_find_leaks(source, session, is_domain)
	if leaks:
		leaks.pop(0)
	return leaks


def pwndb_find_leaks(source, session, is_domain):
    url = "http://pwndb2am4tzkvold.onion/"
    username = source
    domain = "%"
    if "@" in source:
        username = source.split("@")[0]
        domain = source.split("@")[1]
        if not username:
            username = '%'
    request_data = {'luser': username, 'domain': domain, 'luseropr': 1, 'domainopr': 1, 'submitform': 'em'}
    r = session.post(url, data=request_data)
    return parse_pwndb_response(r.text, is_domain)


def parse_pwndb_response(text, is_domain):
	if "Array" not in text:
		return None
	leaks = text.split("Array")[1:]
	dataLeak = []
	for leak in leaks:
		try:
			if is_domain:
				if onlyPasswords:
					dataLeak.append(leak.split("[luser] =>")[1].split("[")[0].strip() + "@" +
						leak.split("[domain] =>")[1].split("[")[0].strip() + ":" +
						leak.split("[password] =>")[1].split(")")[0].strip())
				else:
					data = leak.split("[luser] =>")[1].split("[")[0].strip() + "@" + leak.split("[domain] =>")[1].split("[")[0].strip()
					if not data in dataLeak:
						dataLeak.append(data.lower())
			else:
				data = leak.split("[password] =>")[1].split(")")[0].strip()
				dataLeak.append(data)
		except:
			pass
	return dataLeak


def tor_main(email):
	try:
		if  not onlyPasswords:
			print(info_color + "--------------------\nChecking leaks on tor...\n--------------------")
		passwords = pwndb_main(email, False)
		if  not onlyPasswords:
			if not passwords:
				print (green_color + "No leaks found" + normal_color)
			for i in passwords:
				print (whiteB_color + "This is a password leaked for this email account: " + red_color + str(i) + normal_color)
				if (args.makeDict):
					makeDict(email+":"+str(i))
		else:
			for i in passwords:
				print (email+ ":" + str(i))
	except:
		print (red_color + "You have problems with your connection to the tor proxy or pwndb is not accessible." + normal_color)

def makeDict(email):
	nuevofichero = open("dict.txt" , "a+")
	nuevofichero.write(email+"\n")

	inicio = email.find("-")
	if (inicio == -1):
		fin = email.find("@")
		if (fin != -1):
			nombre = email[0:fin] #get email name before @.
			inicio = email.find(":")
			if (inicio != -1):
				inicio = inicio + 1
				fin = len(email)+1
				password = email[inicio:fin]

				#write in our dict
				nuevofichero.write(nombre+":"+password+"\n")

				inicial = nombre[0:1]
				inicio = nombre.find(".")
				if (inicio != -1):
					inicio = inicio + 1
					fin = len(nombre)
					if (fin != -1):
						nuevonombre = inicial+nombre[inicio:fin]
						nuevofichero.write(nuevonombre+":"+password+"\n")

				inicio = nombre.find(".")
				if (inicio != -1):
					nuevonombre = nombre[0:inicio]
					inicio = inicio + 1
					inicial = nombre[inicio:inicio+1]
					nuevonombre = nuevonombre + inicial
					nuevofichero.write(nuevonombre+":"+password+"\n")

				inicial = nombre[0:1]
				inicio = nombre.find(".")
				if (inicio != -1):
					inicio = inicio + 1
					fin = len(nombre)
					if (fin != -1):
						nuevonombre = nombre[inicio:fin] + inicial
						nuevofichero.write(nuevonombre+":"+password+"\n")

	nuevofichero.close()

def searchpgp(email):
	print(info_color + "--------------------\nChecking PGP key for this email account...\n--------------------")
	email = email.replace("@","%40") #Replace @ with url encode character
	url = 'http://keys.gnupg.net/pks/lookup?search='+email+'&fingerprint=on&op=index'
	headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5"}
	client = requests.Session() #Make a Dictionary with some username masks, only works with -d or with -oP option
	client.headers.update(headers)
	response = client.get(url, proxies=None)

	inicio = response.text.find("href=")

	found = 0

	if (inicio != -1):
		inicio = inicio + 6
		fin = response.text.find("\"", inicio)
		if (fin != -1):
			print (green_color + "[+] PGP Key found!")
			found = 1
			link = response.text[inicio:fin]
			link = link.replace("&amp;", "&")
			url= "http://keys.gnupg.net" + link
			client = requests.Session() #Make a Dictionary with some username masks, only works with -d or with -oP option
			client.headers.update(headers)
			get_page = urllib.request.urlopen(url)
			response = get_page.readlines()

			flag = 0

			for line in response:
				line = line.decode("utf-8")
				line = line[0:len(line)-1]
				line = str(line)
				if (flag == 1):
					inicio = line.find("pre>")
					if (inicio != -1):
						flag = 0
					else:
						print (red_color + line)
				else:
					inicio = line.find("pre>")
					if (inicio != -1):
						flag = flag + 1

	if (found == 0):
		print (green_color + "[+] No PGP Key found!")

def gitlab(email):
	fin = email.find("@")
	user = email[0:fin]

	url = 'https://gitlab.com/users/'+str(user)+'/exists'
	headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5"}
	client = requests.Session() #Make a Dictionary with some username masks, only works with -d or with -oP option
	client.headers.update(headers)
	response = client.get(url, proxies=None)
	for obj in response:
		inicio = obj.find(b"true")
		if (inicio != -1):
			print(whiteB_color + "It's possible that the user has the following Gitlab account: " + green_color + 'https://gitlab.com/users/'+str(user))

if __name__ == "__main__":

	flag = 0 #to check if it's necessary create a dict after.
	args = checkArgs()
	onlyPasswords = args.onlyPasswords
	if (args.tor):
		sistema = format(platform.system())
		if (sistema == "Linux"):
			tor_service = os.system("service tor status >> /dev/null")
			if(tor_service != 0):
				print(red_color + "Tor service no started. You need started this to execute this option.")
				exit(1)

	else:
	  	tor_proxy = None
	if (args.email):
		email = args.email
		if (args.tor):
			if (sistema == "Linux"):
				os.system("killall -HUP tor")
		check_email(email)
	if (args.file):
		try:
			if  not onlyPasswords:
				print(whiteB_color + "--->Reading file with email accounts...<---")
			with open(sys.argv[2]) as myfile:
				lines = myfile.readlines()
			for email in lines:
				os.system("killall -HUP tor")
				email = email[0:len(email) - 1]
				check_email(email)
		except IOError:
			print(red_color + "Error: The file not exist or bad format.")
	if (args.domain):
		domain = args.domain
		try:
			if not args.tor:
				print(red_color + "Error: This functionality need tor to work.")
				exit(1)
				domain = args.domain
			if (domain[0] != '@'):
			    	domain = '@' + domain
			if  not onlyPasswords:
			        print(whiteB_color + "--->Searching email accounts leaks on " + domain + " domain...<---")
			email_list = pwndb_main(domain, True)
			if not email_list:
			        print(green_color + "No leaks found for this domain" + normal_color)
			elif onlyPasswords:
				for line in email_list:
					print(line)
					if (args.makeDict):
						makeDict(line)
			else:
				print(whiteB_color + "Found " + str(len(email_list)) + " accounts with leaks in selected domain: \n" + red_color + ' || '.join(email_list))
				for email in email_list:
				            os.system("killall -HUP tor")
				            #check email
				            check_email(email)
			if (args.pgp):
				searchpgp(email)

		except IOError:
		        	print(red_color + "Error: Unknow error.")
	if (args.pgp):
		searchpgp(email)




link = {
        'https://www.facebook.com',
        'https://twitter.com',
        'https://www.instagram.com',
        'https://www.youtube.com/user',
        'https://www.producthunt.com/@',
        'https://www.pinterest.com',
        'https://www.flickr.com/people',
        'https://vimeo.com',
        'https://soundcloud.com',
        'https://disqus.com',
        'https://medium.com/@',
        'https://about.me',
        'https://flipboard.com',
        'https://slideshare.net',
        'https://open.spotify.com/user',
        'https://www.scribd.com',
        'https://www.patreon.com',
        'https://bitbucket.org',
        'https://gitlab.com',
        'https://www.github.com',
        'https://www.goodreads.com',
        'https://www.instructables.com/member',
        'https://www.codecademy.com',
        'https://en.gravatar.com',
        'https://pastebin.com/u',
        'https://foursquare.com',
        'https://tripadvisor.com/members',
        'https://www.wikipedia.org/wiki/User:',
        'https://news.ycombinator.com/user?id=',
        'https://www.codementor.io',
        'https://www.trip.skyscanner.com/user',
        'https://blogspot.com',
        'https://wordpress.com',
        'https://tumblr.com',
        'https://livejournal.com',
        'https://slack.com',
        'https://ask.fm',
        'https://www.snapchat.com/add',
        'https://www.tiktok.com/@',
        'https://haraj.com.sa/users',
        'https://t.me/',


    }


for link2 in link :

    link3 = link2+"/"+args.account

    try :

        openurl = urllib.request.urlopen(link3)

        print (green_color + link3 + " -> yes")


    except urllib.error.URLError as msg :
        
                print (red_color + link3 + " -> no")
def ketik(s):
	for ASU in s + '\n':
		sys.stdout.write(ASU)
		sys.stdout.flush()
		sleep(50. / 1000)

os.system('clear')

print (' ')
print (' ')
ketik (banner_color +" The email and the number are verified only if it is linked to the account (Snapchat - Instagram)  ....")
sleep(0.5)
print (' ')
#____________________________

url = "https://accounts.snapchat.com/accounts/merlin/login"
headers = {
    "Host": "accounts.snapchat.com",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0",
    "Accept": "*/*",
    "X-XSRF-TOKEN": "L0PSXRCFmp0MlPTr9wqgtQ",
    "Accept-Encoding": "gzip, deflate",
    "Content-Type": "application/json",
    "Content-Length": "51",
    "Connection": "close",
    "Cookie": "xsrf_token=L0PSXRCFmp0MlPTr9wqgtQ; web_client_id=46457498-d640-4f0e-9e50-11497f019e06"
}
data = '{"email":'+email+',"app":"BITMOJI_APP"}'

response = requests.request("POST", url, data=data, headers=headers)


if "hasSnapchat" in response.text:
    print(green_color  +'snapchat email | ' + email + ' --> yes')
    with open('Available_accounts', 'a') as x:
        x.write('snapchat email | ' +email + '\n')
elif "" in response.text:
    print(red_color +'snapchat email | ' + email + ' --> no')
    with open('Unavailable_accounts.txt', 'a') as x:
        x.write('snapchat email | ' + email + '\n')


#________________________________________________
url = "https://accounts.snapchat.com/accounts/validate_phone_number"
headers = {
    "Host": "accounts.snapchat.com",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0",
    "Accept": "*/*",
    "Accept-Language": "ar,en-US;q=0.7,en;q=0.3",
    "Accept-Encoding": "gzip, deflate",
    "Referer": "https://accounts.snapchat.com/",
    "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
    "Origin": "https://accounts.snapchat.com",
    "Content-Length": "79",
    "Connection": "close",
    "Cookie": "xsrf_token=v6zFgDFj8T7ofkai_gggDQ"
}

data = 'phone_country_code=' + args.kod + '&phone_number=' + args.user + '&xsrf_token=v6zFgDFj8T7ofkai_gggDQ'

response = requests.request("POST", url, data=data, headers=headers)


if "error_message" in response.text:
    print(green_color +'snapchat number | ' + args.user + ' --> yes ')
    with open('Available_accounts', 'a') as x:
        x.write('snapchat number | ' +args.user + '\n')
elif "phone_number" in response.text:
    print(red_color +'snapchat number | ' + args.user + ' --> No ')
    with open('Unavailable_accounts.txt', 'a') as x:
        x.write('snapchat number | ' + args.user + '\n')
#______________________________________
url = "https://www.instagram.com/accounts/web_create_ajax/attempt/"
headers = {
    "Host": "www.instagram.com",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0",
    "Accept": "*/*",
    "Accept-Language": "ar,en-US;q=0.7,en;q=0.3",
    "Accept-Encoding": "gzip, deflate",
    "Referer": "https://www.instagram.com/accounts/emailsignup/",
    "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
    "Origin": "https://www.instagram.com",
    "Content-Length": "27",
    "X-CSRFToken": "lkMyp8xyam1m271B5x5blIAHwH7rlkFc",
    "Connection": "close",
    "Cookie": "ig_cb=1;ig_did=69205DC3-D787-47E5-B250-1C4A7ADC3A05;csrftoken=lkMyp8xyam1m271B5x5blIAHwH7rlkFc;mid=XoSg-AAEAAHRshuq4BlxladvlcbE;ds_user_id=33024309194;datr=HmBKXyPTk86RJpmkaUQ7eM5w;urlgen=1kCJgw:MPX9SmvVnDS1eUDVTYmjEgq8SIQ"
}
data = 'email='+email+''

response = requests.request("POST", url, data=data, headers=headers)


if "email_is_taken" in response.text:
    print(green_color +'instagram email | ' + email + ' --> yes')
    with open('Available_accounts', 'a') as x:
        x.write('instagram email | '+ email + '\n')
elif "username_required" in response.text:
    print(red_color +'instagram email | ' + email + ' --> No')
    with open('Unavailable_accounts.txt', 'a') as x:
        x.write('instagram email | '+ email + '\n')

#------------------------------
url = "https://www.instagram.com/accounts/account_recovery_send_ajax/"
headers = {
    "Host": "www.instagram.com",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0",
    "Accept": "*/*",
    "Accept-Language": "ar,en-US;q=0.7,en;q=0.3",
    "Accept-Encoding": "gzip, deflate",
    "Referer": "https://www.instagram.com/accounts/password/reset/",
    "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
    "Origin": "https://www.instagram.com",
    "Content-Length": "27",
    "X-CSRFToken": "lkMyp8xyam1m271B5x5blIAHwH7rlkFc",
    "Connection": "close",
    "Cookie": "ig_cb=1;ig_did=69205DC3-D787-47E5-B250-1C4A7ADC3A05;csrftoken=lkMyp8xyam1m271B5x5blIAHwH7rlkFc;mid=XoSg-AAEAAHRshuq4BlxladvlcbE;ds_user_id=33024309194;datr=HmBKXyPTk86RJpmkaUQ7eM5w;urlgen=1kCJgw:MPX9SmvVnDS1eUDVTYmjEgq8SIQ"
}
data = 'email_or_username='+args.user+'&recaptcha_challenge_field='

response = requests.request("POST", url, data=data, headers=headers)


if "email_or_sms_sent" in response.text:
    print(green_color +'instagram number | ' + args.user + ' --> yes ')
    with open('Available_accounts', 'a') as x:
        x.write('instagram number | ' +args.user + '\n')
elif "fail" in response.text:
    print(red_color +'instagram number | ' + args.user + ' --> No ')
    with open('Unavailable_accounts.txt', 'a') as x:
        x.write('instagram number | ' +args.user + '\n')

#___________________________________
def number():
 with urllib.request.urlopen (
"http://146.148.112.105/caller/index.php/UserManagement/search_number?number=" + args.user + "&country_code="+args.kod+"" ) as url:
  data = json.loads ( url.read ( ).decode ( ) )
 print ( data )
if __name__ == '__main__':
 number()

