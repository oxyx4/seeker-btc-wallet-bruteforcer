import time
import datetime as dt
import smtplib
import os
import colorama
from colorama import Fore, Back, Style
import multiprocessing
from time import sleep
from multiprocessing import Pool
import binascii, hashlib, base58, ecdsa
import pandas as pd
from pynput.keyboard import Listener

icon="""
			 ██████ ▓█████ ▓█████  ██ ▄█▀▓█████  ██▀███  
			▒██    ▒ ▓█   ▀ ▓█   ▀  ██▄█▒ ▓█   ▀ ▓██ ▒ ██▒
			░ ▓██▄   ▒███   ▒███   ▓███▄░ ▒███   ▓██ ░▄█ ▒
			  ▒   ██▒▒▓█  ▄ ▒▓█  ▄ ▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄  
			▒██████▒▒░▒████▒░▒████▒▒██▒ █▄░▒████▒░██▓ ▒██▒
			▒ ▒▓▒ ▒ ░░░ ▒░ ░░░ ▒░ ░▒ ▒▒ ▓▒░░ ▒░ ░░ ▒▓ ░▒▓░
			░ ░▒  ░ ░ ░ ░  ░ ░ ░  ░░ ░▒ ▒░ ░ ░  ░  ░▒ ░ ▒░
			░  ░  ░     ░      ░   ░ ░░ ░    ░     ░░   ░ 
			      ░     ░  ░   ░  ░░  ░      ░  ░   ░     


"""


def loadbar(iteration, total, prefix='', suffix='', decimals=1, length=100, fill='>'):
    percent = ('{0:.' + str(decimals) + 'f}').format(100 * (iteration/float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print (f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    if iteration == total:
        print()


def ripemd160(x):
    d = hashlib.new('ripemd160')
    d.update(x)
    return d


r = 0


def seek(r, df_handler):
	global num_threads
	LOG_EVERY_N = 1000
	start_time = dt.datetime.today().timestamp()
	i = 0
	print(Fore.GREEN + "[+] " + "Core " + str(r) +" Started Searching For Private Key..")
	while True:
		i=i+1
		priv_key = os.urandom(32)
		fullkey = '80' + binascii.hexlify(priv_key).decode()
		sha256a = hashlib.sha256(binascii.unhexlify(fullkey)).hexdigest()
		sha256b = hashlib.sha256(binascii.unhexlify(sha256a)).hexdigest()
		WIF = base58.b58encode(binascii.unhexlify(fullkey+sha256b[:8]))
		sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
		vk = sk.get_verifying_key()
		publ_key = '04' + binascii.hexlify(vk.to_string()).decode()
		hash160 = ripemd160(hashlib.sha256(binascii.unhexlify(publ_key)).digest()).digest()
		publ_addr_a = b"\x00" + hash160
		checksum = hashlib.sha256(hashlib.sha256(publ_addr_a).digest()).digest()[:4]
		publ_addr_b = base58.b58encode(publ_addr_a + checksum)
		priv = WIF.decode()
		pub = publ_addr_b.decode()
		time_diff = dt.datetime.today().timestamp() - start_time
		if (i % LOG_EVERY_N) == 0:
			print('[/] Core :'+str(r)+" K/s = "+ str(i / time_diff))
			print ('[+] Worker '+str(r)+':'+ str(i) + '.-  # '+pub + ' # -------- # '+ priv+' # ')
		pub = pub + '\n'
		filename = 'adresses.txt'
		with open(filename) as f:
			for line in f:
				if pub in line:
					msg = "\n [+] Key found: Public: " + str(pub) + " ---- Private: " + str(priv) + "YEI"
					text = msg
					print(text)
					with open('Wallets.txt','a') as f:
						f.write(priv)
						f.write('     ')
						f.write(pub)
						f.write('\n')
						f.close()
					time.sleep(30)
					print ('[+] Key found' +dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), pub, priv)
					break
					



contador=0
if __name__ == '__main__':
	colorama.init()
	print('\033[31m' + icon)
	print('\033[39m') 
	print()
	os.system("pause")
	cores = input("[/] Number of cores (CPU) : ")
	coresf=int(cores)
	jobs = []
	df_handler = pd.read_csv(open('adresses.txt', 'r'))
	for r in range(coresf):
		p = multiprocessing.Process(target=seek, args=(r,df_handler))
		jobs.append(p)
		p.start()



