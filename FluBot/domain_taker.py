import requests
from base64 import b64decode
import re
import time

req_time = 0
domains = set()
f = open("flubot_dist_domains.txt","r")
d = f.readlines()
for domain in d:
    domains.add(domain[:-1])

def dec2(bArr,bArr2,z):
    bArr = bytearray(b64decode(bArr))
    bArr3 = bArr2
    b = 0
    for i in range(0,len(bArr)):
        l = i % len(bArr3)
        if l == 0 and i != 0:
            for i2 in range(0,len(bArr3)):
                if z:
                    bArr3[i2] = bArr3[i2] ^ b
                else:
                    bArr3[i2] = bArr3[i2] ^ bArr[i-1]
        b = bArr[i]
        bArr[i] = bArr3[l] ^ bArr[i]
    return bArr

encryption_key = "lmxthsejly"


def get_url():
    global domains
    burp0_url = "http://mbhpikampombehi.com/poll.php"
    # burp0_url = "http://xjnwqdospderqtk.ru/poll.php"
    burp0_headers = {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 8.0.0; Google Pixel Build/OPR6.170623.017)", "Connection": "close", "Accept-Encoding": "gzip, deflate"}
    burp0_data = {"Gpxskr0h8N5OrpRC7XYfKUhWB4+p92Hl8PweqLg9Nv1bm5bkdopMJHlA3dKOChyBmetPZ2IwfLxwNH9nqwY4cUr93qN9UYKDcrFsNUI9B0wQ27WcAaQXOUlELFQGXdnlNbVvERhpD5kwE0UgMbo02pOfFz5fXsY/1w Hcs70DPHH/WC9FZAhVxhxWlio2Z7mMUVfMClQl1qQUppaLYOXP/CiEDJYWMcL//92Xk5AgYea2/fSVao/BSpFtvXQPvJD 6FsyecGJNbKcE9gqpHW5SYFkn4Ie45M/IiDA0pSefx2h3NMVvt79JEw1UJhFOoR7HVGi6RumhhO668di2UuPg""=\r\nKygsKzs Ng=="}
    d = "Gpxskr0h8N5OrpRC7XYfKUhWB4+p92Hl8PweqLg9Nv1bm5bkdopMJHlA3dKOChyBmetPZ2IwfLxwNH9nqwY4cUr93qN9UYKDcrFsNUI9B0wQ27WcAaQXOUlELFQGXdnlNbVvERhpD5kwE0UgMbo02pOfFz5fXsY/1w+Hcs70DPHH/WC9FZAhVxhxWlio2Z7mMUVfMClQl1qQUppaLYOXP/CiEDJYWMcL//92Xk5AgYea2/fSVao/BSpFtvXQPvJD+6FsyecGJNbKcE9gqpHW5SYFkn4Ie45M/IiDA0pSefx2h3NMVvt79JEw1UJhFOoR7HVGi6RumhhO668di2UuPg==\r\nKygsKzs+Ng=="
    r = requests.post(burp0_url, headers=burp0_headers, data=d)
    if r.status_code != 200:
        print(r.content)
        return
    sms_text = dec2(r.content,bytearray(encryption_key.encode("utf-8")),False).decode("utf-8")
    re_result = re.findall(".*(http.*/.*/)",sms_text)
    if len(re_result) > 0:
        old_size = len(domains)
        domains.add(re_result[0])
        new_size = len(domains)
        if new_size > old_size:
            print(re_result[0])
            f = open("./uniq_domains.txt","a")
            f.write(re_result[0]+"\n")
            f.close()



def main():
    global req_time,domains
    while True:
        get_url()
        req_time += 1
        for i in range(200):
            time.sleep(1)
main()
