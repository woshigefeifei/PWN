from pwn import *
sh=remote("node4.buuoj.cn",27038)
#sh=process("./timu")
sh.interactive()
