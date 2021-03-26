import socket
import dns.resolver
from datetime import datetime
from javarandom import Random

def gen_seed():
        year = datetime.today().year
        month = datetime.today().month
        month = month
        mask = 0xffffffffffffffff
        print(f"Current seed year={year},month={month}")
        j = year^month^0
        j2 = j*2&mask
        j3 = j2 * ((year&mask)^j2)&mask
        j4 = j3 * ((month&mask)^j3)&mask
        j5 = j4 * (0^j4)&mask
        seed = (j5 + 1949)&mask
        return seed

def gen_domain():
    r = Random(seed=gen_seed())
    for i in range(5000):
        domain = "" 
        for i2 in range(15):
            domain += chr(r.nextInt(25)+97)
        if i%3 == 0:
            domain += ".ru"
        elif i%2 == 0:
            domain += ".com"
        else:
            domain += ".cn"
        print(domain)
        # try:
        #     dns_found = socket.gethostbyname(domain)
        #     # dns_found = socket.getaddrinfo(domain,80,type=socket.SOCK_STREAM)
        #     print(dns_found[3],domain)
        # except Exception as E:
        #     pass

gen_domain()

