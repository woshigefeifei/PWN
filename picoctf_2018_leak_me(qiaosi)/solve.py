from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",29598)

sh.sendline(b'a')
payload=b"a_reAllY_s3cuRe_p4s$word_f85406"
sh.sendline(payload)

sh.interactive()
