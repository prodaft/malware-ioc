from Crypto.Cipher import AES
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--file", help="file to be decrypted", type=str)
parser.add_argument("--id", help="Personel ID", type=str)

args = parser.parse_args()

if args.file == None:
    parser.print_help()
    exit()
f = open(args.file, "rb")
content = f.read()
f.close()

IV = content[:16]
hash_map = {
    "a": "x",
    "b": "w",
    "c": "z",
    "d": "v",
    "e": "u",
    "f": "y",
    "g": "t",
    "h": "s",
    "i": "r",
    "j": "q",
    "k": "p",
    "l": "o",
    "m": "n",
    "n": "m",
    "o": "l",
    "p": "k",
    "q": "j",
    "r": "i",
    "s": "h",
    "t": "g",
    "u": "f",
    "v": "d",
    "w": "b",
    "x": "a",
    "y": "c",
    "z": "e",
}

hash_map_reverse = {v: k for k, v in hash_map.items()}
KEY = ""
for k in args.id.lower():
    if k in hash_map_reverse.keys():
        KEY += hash_map_reverse[k]
    else:
        KEY += k


KEY = KEY.encode("utf-8")[::]

aes = AES.new(KEY, AES.MODE_CFB, IV=IV)

enc_data = content[16:]

dec = aes.decrypt(enc_data)

f = open(args.file + ".dec", "wb")
f.write(dec)
f.close()
