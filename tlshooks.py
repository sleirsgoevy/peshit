def install_tls_hooks(x, v):
    tls = x.offset_table[9]
    addr, _ = v.alloc(36, 0xc0000000, '.tls2')
    if tls == None:
        tls_bytes = b'\0\0\0\0\0\0\0\0'+(addr + 24).to_bytes(4, 'little')+b'\0\0\0\0\0\0\0\0\0\0\0\0'
        callbacks = []
    else:
        assert tls[1] == 24
        tls_bytes = v[tls[0]:tls[0]+24]
        callbacks_addr = int.from_bytes(tls_bytes[12:16], 'little')
        callbacks = []
        while any(v[callbacks_addr:callbacks_addr+4]):
            callbacks.append(int.from_bytes(v[callbacks_addr:callbacks_addr+4], 'little'))
            callbacks_addr += 4
    v[addr:addr+24] = tls_bytes
    arm_addr = addr + 32
    v[addr+12:addr+16] = arm_addr.to_bytes(4, 'little')
    x.offset_table[9] = (addr, 24)
    return arm_addr, callbacks
