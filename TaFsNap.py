import requests, json
import sys
from bs4 import BeautifulSoup
user = input('number_snap -> ')
kod = input('The name of the country to which the number belongs -> ')
print('''


  _____      _       _____  
 |_ " _| U  /"\  u  |" ___| 
   | |    \/ _ \/  U| |_  u 
  /| |\   / ___ \  \|  _|/  
 u |_|U  /_/   \_\  |_|     
 _// \\_  \\    >>  )(\\,-  
(__) (__)(__)  (__)(__)(_/  
                            sNap 👻
                            
                
---------------------------------------

++ The developer : Falah - 0xfff080 ++

snapchat : flaah999

-----------------------------------



''')


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


data = 'phone_country_code='+kod+'&phone_number='+user+'&xsrf_token=v6zFgDFj8T7ofkai_gggDQ'


response = requests.request("POST", url, data=data, headers=headers)



if "error_message" in response.text:
                print('' + user + ' --> There is an account associated with it ! ')
                with open('Authenticated_numbers.txt', 'a') as x:
                    x.write(user + '\n')
elif "phone_number" in response.text:   
                print('' + user + ' --> There is no account associated with it ! ')
                with open('Undocumented_numbers.txt', 'a') as x:
                    x.write(user + '\n')
