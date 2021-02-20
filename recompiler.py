import capstone, pefile, vmem, io, json, collections, cfstyle, traceback

TRACE = False
TRACEBACKS = True

def read_instr_at(cs, v, addr):
    addr0 = addr
    b = b''
    while len(b) <= 16:
        try: return next(cs.disasm(b, addr0))
        except StopIteration: pass
        try: b += bytes((v[addr],))
        except IndexError: return None
        addr += 1
    return None

cf_add_style_instrs = ('add',)
cf_sub_style_instrs = ('sub', 'cmp', 'lock cmpxchg', 'neg')
cf_xor_style_instrs = ('xor', 'and', 'test', 'or')

def get_labels(cs, x, v, preseed0):
    preseed = []
    for i in x.sections:
        if i[3] & 0x20000000: # executable
            preseed.append(i[1]) # vma
    preseed.extend(preseed0)
    preseed.sort()
    preseed_set = set(preseed)
    labels = set()
    label_list = []
    cf_uses = set()
    cfg = collections.defaultdict(list)
    cf_styles = {}
    for i in preseed:
        cur_cf_style = 'none'
        while i not in labels:
            iii = i
            labels.add(i)
            label_list.append(i)
            ii = read_instr_at(cs, v, i)
            if ii == None: break
            cf_styles[i] = cur_cf_style
            i += len(ii.bytes)
            if (ii.mnemonic[0] == 'j' or ii.mnemonic == 'call') and ii.op_str.startswith('0x'):
                if ii.mnemonic in ('ja', 'jb', 'jae', 'jbe'): cf_uses.add(iii)
                dst = int(ii.op_str, 16)
                if dst not in preseed_set:
                    preseed.append(dst)
                    preseed_set.add(dst)
            if ii.mnemonic in cf_add_style_instrs:
                cur_cf_style = 'add'
            elif ii.mnemonic in cf_sub_style_instrs:
                cur_cf_style = 'sub'
            elif ii.mnemonic in cf_xor_style_instrs:
                cur_cf_style = 'xor'
            elif ii.mnemonic in ('jmp', 'call'):
                try: dst = int(ii.op_str, 16)
                except ValueError: pass
                else: cfg[dst].append(iii)
            elif ii.mnemonic.startswith('j'):
                dst = int(ii.op_str, 16)
                cfg[dst].append(iii)
                cfg[i].append(iii)
            elif ii.mnemonic != 'ret':
                cfg[i].append(iii)
    return label_list, cfstyle.calculate_cf_style(cfg, cf_uses, cf_styles)

arm_crt = '''\
.p2align 2
.extern emu_unsupported_c
.extern emu_dispatch_indir
.global emu_do_callback
.global emu_callback_ret

emu_unsupported:
mov r0, lr
sub r0, r0, #1
b emu_unsupported_c

emu_do_callback:
push {r2, r3}
ldr r2, =0x179
push {r2}
mov r2, r4
mov r3, lr
ldr r4, =16383
bl __chkstk
mov lr, r3
mov r4, r2
mov r2, sp
ldr r3, =65532
sub r3, r2, r3
mov sp, r3
push {r1, r4, r5, r6, r7, r8, r9, r10, r11, lr}
mov r8, r2
bl emu_dispatch_indir
bl emu_trace_callback_entry //debug
bx r0
emu_callback_ret:
bl emu_trace_callback_exit //debug
mov r0, r4
pop {r1, r4, r5, r6, r7, r8, r9, r10, r11, lr}
mov r2, sp
ldr r3, =65544
add r2, r3
mov sp, r2
bx lr

emu_call_native:
push {fp, lr}
mov fp, sp
sub sp, r1
sub sp, #16
mov r3, sp
tst r3, #7
beq 1f
sub sp, #4
1:
cbz r1, 3f
mov r3, sp
add r1, r3
2:
ldr ip, [r0], #4
str ip, [r3], #4
cmp r1, r3
bne 2b
3:
mov ip, r2
pop {r0, r1, r2, r3}
blx ip
mov sp, fp
pop {fp, pc}

emu_entry:
//bl iat_fixup //XXX
ldr r4, =16384
bl __chkstk
mov r0, sp
mov r8, r0
sub r0, r0, #65536
mov sp, r0
bl ENTRY

emu_rep_stosd:
str r4, [r11], #4
sub r5, r5, #1
cbz r5, 1f
b emu_rep_stosd
1:
bx lr

emu_lock_cmpxchg:
//r0 = lea dst
//r1 = src
ldrex r2, [r0]
cmp r4, r2
it eq
moveq r2, r1
strex r3, r2, [r0]
cbz r3, 1f
b emu_lock_cmpxchg
1:
it ne
movne r4, r2
bx lr

emu_trace:
mrs r1, cpsr
push {r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, lr}
mov r1, sp
bl emu_trace_c
pop {r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, lr}
msr cpsr_f, r1
bx lr

__chkstk:
cbz r4, 3f
lsl r4, r4, #2
sub r12, sp, r4
sub r4, sp, #2048
sub r4, #2048
cmp r4, r12
bcc 2f
1:
str r4, [r4]
sub r4, #2048
sub r4, #2048
cmp r4, r12
bcs 1b
2:
str r12, [r12]
sub r4, sp, r12
3:
bx lr
'''

if not TRACE:
    arm_crt = '\n'.join(i for i in arm_crt.split('\n') if not i.endswith('//debug'))

def asciz(s):
    s += '\0'
    while len(s) % 4: s += '\0'
    return '.ascii '+json.dumps(s).replace('\\u00', '\\x')

reg_mapping = {
    'eax': 'r4',
    'ecx': 'r5',
    'edx': 'r6',
    'ebx': 'r7',
    'esp': 'r8',
    'ebp': 'r9',
    'esi': 'r10',
    'edi': 'r11',
}

regs_16bit = {'ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di'}
regs_8bit = {'al', 'ah', 'cl', 'ch', 'dl', 'dh', 'bl', 'bh'}

def guess_bitness(instr):
    instr = instr.replace(',', ' , ')
    if 'byte' in instr.split() or set(instr.split()) & regs_8bit: return 8
    elif 'word' in instr.split() or set(instr.split()) & regs_16bit: return 16
    else: return 32

def read_mem(f, addr, reg, ldrop='ldr'):
    log2 = {1: 0, 2: 1, 4: 2, 8: 3}
    try: addr = int(addr, 16)
    except ValueError: pass
    else:
        print('ldr %s, =0x%x'%(reg, addr), file=f)
        print(ldrop, '%s, [%s]'%(reg, reg), file=f)
        return
    if addr in reg_mapping:
        print(ldrop, '%s, [%s]'%(reg, reg_mapping[addr]), file=f)
        return
    addr = addr.replace(' - ', ' + -')
    if addr.count(' + ') == 2:
        left, middle, right = addr.split(' + ')
        right = int(right, 0)
        if '*' in middle:
            middle, scale = middle.split('*')
            scale = log2[int(scale)]
            print('add r2, %s, %s, lsl %d'%(reg_mapping[left], reg_mapping[middle], scale), file=f)
        else:
            print('add r2, %s, %s'%(reg_mapping[left], reg_mapping[middle]), file=f)
        if right in range(-255, 4096):
            print('%s %s, [r2, #%s]'%(ldrop, reg, hex(right)), file=f)
        else:
            print('ldr r3, ='+hex(right), file=f)
            print('add r2, r3', file=f)
            print('%s %s, [r2]'%(ldrop, reg), file=f)
        return
    if ' + ' in addr:
        left, right = addr.split(' + ', 1)
        if left in reg_mapping: 
            try: right = int(right, 0)
            except ValueError: pass
            else:
                if right in range(-255, 4096):
                    print(ldrop, '%s, [%s, #%s]'%(reg, reg_mapping[left], hex(right)), file=f)
                else:
                    print('ldr r2, ='+hex(right), file=f)
                    print('add r2, r2, '+reg_mapping[left], file=f)
                    print(ldrop, '%s, [r2]'%reg, file=f)
                return
    try:
        lea(f, addr, 'r2')
        print(ldrop, '%s, [r2]'%reg, file=f)
    except AssertionError as e:
        assert False, "read_mem fallback failed: %s"%e

def read_tls(f, addr, reg):
    try: addr = int(addr, 16)
    except ValueError: pass
    else:
        print('mrc p15, #0, %s, c13, c0, #2'%reg, file=f)
        if addr in range(-255, 4096):
            print('ldr %s, [%s, #%s]'%(reg, reg, hex(addr)), file=f)
        else:
            print('ldr r2, =%s'%hex(addr), file=f)
            print('ldr %s, [%s, r2]'%(reg, reg), file=f)

def write_tls(f, addr, reg):
    try: addr = int(addr, 16)
    except ValueError: pass
    else:
        print('mrc p15, #0, r2, c13, c0, #2', file=f)
        if addr in range(-255, 4096):
            print('str %s, [r2, #%s]'%(reg, hex(addr)), file=f)
        else:
            print('ldr r3, =%s'%hex(addr), file=f)
            print('str %s, [r2, r3]'%reg, file=f)

def write_mem(f, addr, reg):
    log2 = {1: 0, 2: 1, 4: 2, 8: 3}
    try: addr = int(addr, 16)
    except ValueError: pass
    else:
        print('ldr r2, =0x%x'%addr, file=f)
        print('str %s, [r2]'%reg, file=f)
        return
    addr = addr.replace(' - ', ' + -')
    if addr.count(' + ') == 2:
        left, middle, right = addr.split(' + ')
        right = int(right, 0)
        if '*' in middle:
            middle, scale = middle.split('*')
            scale = log2[int(scale)]
            print('add r2, %s, %s, lsl %d'%(reg_mapping[left], reg_mapping[middle], scale), file=f)
        else:
            print('add r2, %s, %s'%(reg_mapping[left], reg_mapping[middle]), file=f)
        if right in range(-255, 4096):
            print('str %s, [r2, #%s]'%(reg, hex(right)), file=f)
        else:
            print('ldr r3, ='+hex(right), file=f)
            print('add r2, r3', file=f)
            print('str %s, [r2]'%reg, file=f)
        return
    if ' + ' in addr:
        left, right = addr.split(' + ', 1)
        if left in reg_mapping: 
            try: right = int(right, 0)
            except ValueError: pass
            else:
                if right in range(-255, 4096):
                    print('str %s, [%s, #%s]'%(reg, reg_mapping[left], hex(right)), file=f)
                else:
                    print('ldr r2, ='+hex(right), file=f)
                    print('add r2, r2, '+reg_mapping[left], file=f)
                    print('str %s, [r2]'%reg, file=f)
                return
    if addr in reg_mapping:
        print('str %s, [%s]'%(reg, reg_mapping[addr]), file=f)
        return
    assert False, "write_mem failed"

def read_arg(f, arg, reg, fake=False, bitness=32):
    try: arg = int(arg, 16)
    except ValueError: pass
    else:
        arg <<= (32 - bitness)
        arg &= 0xffffffff
        if arg in range(-255, 4096):
            return '#0x%x'%arg
        else:
            print('ldr %s, =0x%x'%(reg, arg), file=f)
            return reg
    if arg in reg_mapping: return reg_mapping[arg]
    if arg.startswith('dword ptr ['):
        if not fake:
            read_mem(f, arg.split('[', 1)[1].split(']', 1)[0], reg)
        return reg
    if arg.startswith('dword ptr fs:['):
        if not fake:
            read_tls(f, arg.split('[', 1)[1].split(']', 1)[0], reg)
        return reg
    if arg.startswith('word ptr ['):
        read_mem(f, arg.split('[', 1)[1].split(']', 1)[0], reg, ldrop='ldrh')
        print('lsl %s, #16'%reg, file=f)
        return reg
    if arg.startswith('byte ptr ['):
        read_mem(f, arg.split('[', 1)[1].split(']', 1)[0], reg, ldrop='ldrb')
        print('lsl %s, #24'%reg, file=f)
        return reg
    if arg in regs_8bit:
        big_reg = reg_mapping['e' + arg[0] + 'x']
        if arg[1] == 'l':
            print('lsl %s, %s, #24'%(reg, big_reg), file=f)
        else:
            print('lsr %s, %s, #8'%(reg, big_reg), file=f)
            print('lsl %s, #24'%reg, file=f)
        return reg
    if arg in regs_16bit:
        big_reg = reg_mapping['e' + arg]
        print('lsl %s, %s, #16'%(reg, big_reg), file=f)
        return reg
    assert False, "read_arg failed"

def write_arg(f, arg, reg):
    if arg.startswith('dword ptr ['):
        write_mem(f, arg.split('[', 1)[1].split(']', 1)[0], reg)
        return
    if arg.startswith('dword ptr fs:['):
        write_tls(f, arg.split('[', 1)[1].split(']', 1)[0], reg)
        return
    if '[' in arg:
        assert False, "write_arg failed (unknown memory addressing mode)"
    if arg in regs_8bit:
        assert reg in ('r0', 'r1', 'r2', 'r3')
        big_reg = reg_mapping['e' + arg[0] + 'x']
        if arg[1] == 'l':
            print('lsl %s, #24'%reg, file=f)
            print('ldr r2, =0xffffff00', file=f)
        else:
            print('lsl %s, #16'%reg, file=f)
            print('ldr r2, =0xffff00ff', file=f)
        print('and %s, r2'%big_reg, file=f)
        print('orr %s, %s'%(big_reg, reg), file=f)
        return
    if arg not in reg_mapping or reg != reg_mapping[arg]:
        assert False, "write_arg failed (register wtf)"

def load_into_reg(f, arg, reg):
    data = read_arg(f, arg, reg)
    if data != reg:
        print('mov %s, %s'%(reg, data), file=f)

def get_as_reg(f, arg, reg):
    data = read_arg(f, arg, reg)
    if data.startswith('#'):
        print('mov %s, %s'%(reg, data), file=f)
        return reg
    return data

def lea(f, addr, reg):
    log2 = {1: 0, 2: 1, 4: 2, 8: 3}
    addr = addr.replace(' - ', ' + -')
    try: addr = int(addr, 0)
    except ValueError: pass
    else:
        print('ldr %s, =%s'%(reg, hex(addr)), file=f)
        return
    if ' + ' in addr:
        left, right = addr.split(' + ', 1)
        left_scale = None
        if '*' in left:
            left, left_scale = left.split('*')
            left_scale = int(left_scale)
        if left in reg_mapping:
            try: right = int(right, 0)
            except ValueError: pass
            else:
                if right in range(-255, 4096) and left_scale == None:
                    print('add %s, %s, #%s'%(reg, reg_mapping[left], hex(right)), file=f)
                else:
                    print('ldr %s, =%s'%(reg, hex(right)), file=f)
                    if left_scale == None:
                        print('add %s, %s'%(reg, reg_mapping[left]), file=f)
                    else:
                        print('add %s, %s, %s, lsl #%d'%(reg, reg, reg_mapping[left], log2[left_scale]), file=f)
                return
            if '*' in right:
                right, scale = right.split('*')
                scale = int(scale)
                assert right in reg_mapping, "lea failed"
                print('add %s, %s, %s, lsl #%d'%(reg, reg_mapping[left], reg_mapping[right], log2[scale]), file=f)
                return
    if '*' in addr:
        left, right = addr.split('*', 1)
        assert left in reg_mapping, "lea wtf"
        print('lsl %s, %s, #%d'%(reg, reg_mapping[left], log2[int(right)]), file=f)
        return
    if addr in reg_mapping:
        print('mov %s, %s'%(reg, reg_mapping[addr]), file=f)
        return
    assert False, "lea: unsupported addressing mode"

def emit(f, cs, x, v, labels, cf_style, wrapper_names):
    wrapper_names = iter(wrapper_names)
    for i, l in enumerate(labels):
        print('.global x86_%x'%l, file=f)
        print('x86_%x:'%l, file=f)
        ii = read_instr_at(cs, v, l)
        ok = True
        if ii == None:
            print('bl emu_fault', file=f) # no way to recover
            ok = False
        else:
            if TRACE:
                print('ldr r0, ='+hex(l), file=f)
                print('bl emu_trace', file=f)
            try:
                bitness = guess_bitness(ii.op_str)
                instr = ii.mnemonic
                print('// %x: %s %s'%(l, instr, ii.op_str), file=f)
                try: cur_cf_style = cf_style[l]
                except KeyError: assert False, "unknown CF style"
                if instr in ('add', 'sub', 'xor', 'and', 'or'):
                    if instr == 'xor': instr = 'eor'
                    if instr == 'or': instr = 'orr'
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    arg1r = read_arg(f, arg1, 'r0', bitness=bitness)
                    arg2r = read_arg(f, arg2, 'r1', bitness=bitness)
                    print('%ss %s, %s, %s'%(instr, arg1r, arg1r, arg2r), file=f)
                    write_arg(f, arg1, arg1r)
                elif instr in ('cmp', 'test'):
                    if instr == 'test': instr = 'tst'
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    arg1r = read_arg(f, arg1, 'r0', bitness=bitness)
                    arg2r = read_arg(f, arg2, 'r1', bitness=bitness)
                    print('%s %s, %s'%(instr, arg1r, arg2r), file=f)
                elif instr == 'mov':
                    assert bitness == 32, 'TODO: <32-bit move'
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    if '[' in arg1:
                        write_arg(f, arg1, get_as_reg(f, arg2, 'r0'))
                    elif '[' in arg2:
                        read_arg(f, arg2, read_arg(f, arg1, 'r0'), bitness=bitness)
                    else:
                        try: arg2i = int(arg2, 0)
                        except ValueError: print('mov %s, %s'%(reg_mapping[arg1], reg_mapping[arg2]), file=f)
                        else: print('ldr %s, =%s'%(reg_mapping[arg1], arg2i), file=f)
                elif instr == 'call':
                    try: target = int(ii.op_str, 16)
                    except ValueError:
                        load_into_reg(f, ii.op_str.strip(), 'r0')
                        print('ldr r1, ='+hex(l+len(ii.bytes)), file=f)
                        print('str r1, [r8, #-4]!', file=f)
                        print('bl emu_dispatch_indir', file=f)
                        print('bx r0', file=f)
                    else:
                        assert target in cf_style and cf_style[target] == 'none', "call to CF-aware code"
                        print('ldr r1, ='+hex(l+len(ii.bytes)), file=f)
                        print('str r1, [r8, #-4]!', file=f)
                        print('b x86_%x'%target, file=f)
                    ok = False
                elif instr == 'push':
                    print('str %s, [r8, #-4]!'%get_as_reg(f, ii.op_str.strip(), 'r0'), file=f)
                elif instr == 'je':
                    target = int(ii.op_str, 16)
                    assert target in cf_style and cf_style[target] in ('none', cur_cf_style), "TODO: CF style mismatch"
                    print('beq x86_%x'%target, file=f)
                elif instr == 'jne':
                    target = int(ii.op_str, 16)
                    assert target in cf_style and cf_style[target] in ('none', cur_cf_style), "TODO: CF style mismatch"
                    print('bne x86_%x'%target, file=f)
                elif instr == 'jb':
                    target = int(ii.op_str, 16)
                    cc = {'add': 'cs', 'sub': 'cc'}[cur_cf_style]
                    assert target in cf_style and cf_style[target] in ('none', cur_cf_style), "TODO: CF style mismatch"
                    print('b'+cc+' x86_%x'%target, file=f)
                elif instr == 'ja':
                    target = int(ii.op_str, 16)
                    assert cur_cf_style == 'sub', "TODO: ja with %s-style CF"%cur_cf_style
                    assert target in cf_style and cf_style[target] in ('none', cur_cf_style), "TODO: CF style mismatch"
                    print('bhi x86_%x'%target, file=f)
                elif instr == 'jbe':
                    target = int(ii.op_str, 16)
                    assert cur_cf_style == 'sub', "TODO: jbe with %s-style CF"%cur_cf_style
                    assert target in cf_style and cf_style[target] in ('none', cur_cf_style), "TODO: CF style mismatch"
                    print('bls x86_%x'%target, file=f)
                elif instr == 'jae':
                    target = int(ii.op_str, 16)
                    cc = {'add': 'cc', 'sub': 'cs'}[cur_cf_style]
                    assert target in cf_style and cf_style[target] in ('none', cur_cf_style), "TODO: CF style mismatch"
                    print('b'+cc+' x86_%x'%target, file=f)
                elif instr in ('jl', 'jle', 'jg', 'jge'):
                    target = int(ii.op_str, 16)
                    assert target in cf_style and cf_style[target] in ('none', cur_cf_style), "TODO: CF style mismatch"
                    if len(instr) == 2: instr += 't'
                    print('b'+instr[1:]+' x86_%x'%target, file=f)
                elif instr == 'lea':
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    assert arg2.startswith('['), "invalid lea"
                    lea(f, arg2.split('[', 1)[1].split(']', 1)[0], reg_mapping[arg1])
                elif instr == 'syscall':
                    print('mov r0, r4', file=f)
                    print('bl wrapper_'+next(wrapper_names), file=f)
                elif instr == 'nop': pass
                elif instr == 'leave':
                    print('mov r8, r9', file=f)
                    print('ldr r9, [r8], #4', file=f)
                elif instr == 'ret':
                    print('ldr r0, [r8], #4', file=f)
                    try: stdcall = int(ii.op_str, 0)
                    except ValueError: pass
                    else: print('add r8, r8, #'+hex(stdcall), file=f)
                    print('bl emu_dispatch_indir', file=f)
                    print('bx r0', file=f)
                    ok = False
                elif instr == 'pop':
                    arg = ii.op_str.strip()
                    arg_r = read_arg(f, arg, 'r0', fake=True, bitness=bitness)
                    print('ldr %s, [r8], #4'%arg_r, file=f)
                    write_arg(f, arg, arg_r)
                elif instr == 'not':
                    arg = ii.op_str.strip()
                    arg_r = read_arg(f, arg, 'r0', bitness=bitness)
                    print('rsb %s, %s, #-1'%(arg_r, arg_r), file=f)
                    write_arg(f, arg, arg_r)
                elif instr == 'neg':
                    arg = ii.op_str.strip()
                    arg_r = read_arg(f, arg, 'r0', bitness=bitness)
                    print('rsbs %s, %s, #0'%(arg_r, arg_r), file=f)
                    write_arg(f, arg, arg_r)
                elif instr == 'jmp':
                    try: target = int(ii.op_str, 16)
                    except ValueError:
                        load_into_reg(f, ii.op_str.strip(), 'r0')
                        print('mrs r1, cpsr', file=f)
                        print('push {r1}', file=f)
                        print('bl emu_dispatch_indir', file=f)
                        print('pop {r1}', file=f)
                        print('msr cpsr_f, r1', file=f)
                        print('bx r0', file=f)
                    else:
                        assert target in cf_style and cf_style[target] in ('none', cur_cf_style), "TODO: CF style mismatch"
                        print('b x86_%x'%target, file=f)
                    ok = False
                elif instr == 'rep stosd':
                    print('bl emu_rep_stosd', file=f)
                elif instr == 'lock cmpxchg':
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    if arg1 in reg_mapping:
                        print('cmp r4,', reg_mapping[arg1], file=f)
                        print('moveq %s, %s'%(reg_mapping[arg1], reg_mapping[arg2]), file=f)
                        print('movne r4,', reg_mapping[arg1], file=f)
                    else:
                        assert arg1.startswith('dword ptr ['), "wtf??"
                        lea(f, arg1.split('[', 1)[1].split(']', 1)[0], 'r0')
                        print('mov r1,', reg_mapping[arg2], file=f)
                        print('bl emu_lock_cmpxchg', file=f)
                elif instr == 'xchg':
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    if arg2 in reg_mapping:
                        arg1, arg2 = arg2, arg1
                    assert arg1 in reg_mapping, "invalid xchg"
                    if arg2 in reg_mapping:
                        print('mov r0', reg_mapping[arg1], file=f)
                        print('mov %s, %s'%(reg_mapping[arg1], reg_mapping[arg2]), file=f)
                        print('mov '+reg_mapping[arg2]+', r0', file=f)
                    else:
                        lea(f, arg2.split('[', 1)[1].split(']', 1)[0], 'r0')
                        print('ldrex r1, [r0]', file=f)
                        print('strex r2, '+reg_mapping[arg1]+', [r0]', file=f)
                        print('cbz r2, x86_%x_xchg'%l, file=f)
                        print('b x86_%x'%l, file=f)
                        print('x86_%x_xchg:'%l, file=f)
                        print('mov '+reg_mapping[arg1]+', r1', file=f)
                elif instr in ('sete', 'setne'):
                    print('mov r0, #0', file=f)
                    cc = instr[3:]
                    if cc == 'e': cc = 'eq'
                    print('it', cc, file=f)
                    print('mov'+cc+' r0, #1', file=f)
                    print('lsl r0, #24', file=f)
                    write_arg(f, ii.op_str, 'r0')
                elif instr == 'movzx':
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    bitness1 = guess_bitness(arg1)
                    bitness2 = guess_bitness(arg2)
                    assert bitness2 < bitness1, "invalid movzx"
                    arg2r = read_arg(f, arg2, read_arg(f, arg1, 'r0', fake=True), bitness=bitness2)
                    print('lsr %s, #%d'%(arg2r, bitness1 - bitness2), file=f)
                    write_arg(f, arg1, arg2r)
                elif instr == 'fninit': pass # TODO: stub
                elif instr == 'cmove':
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    assert arg1 in reg_mapping and arg2 in reg_mapping, "weird cmove args"
                    print('it eq', file=f)
                    print('moveq %s, %s'%(reg_mapping[arg1], reg_mapping[arg2]), file=f)
                else:
                    assert False, "unknown mnemonic %s"%ii.mnemonic
            except Exception:
                instr = (ii.mnemonic+' '+ii.op_str).strip()
                if TRACEBACKS: instr += '\n' + traceback.format_exc()
                print('bl emu_unsupported', file=f) # no way to recover
                print(asciz(instr.strip()), file=f)
                ok = False
        if ok and (i + 1 < len(labels) and labels[i+1] != l + len(ii.bytes)):
            print('b x86_%x'%(l + len(ii.bytes)), file=f)
            ok = False
        if not ok:
            print('.ltorg', file=f)

def transpile(x, v, preseed, entry, wrapper_names):
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    labels, cf_style = get_labels(cs, x, v, preseed)
    indir_bl = {i for i, j in cf_style.items() if j != 'none'}
    f = io.StringIO()
    emit(f, cs, x, v, labels, cf_style, wrapper_names)
    return arm_crt.replace('ENTRY', 'x86_%x'%entry)+f.getvalue(), indir_bl

if __name__ == '__main__':
    import sys
    x = pefile.PeFile(open(sys.argv[1], 'rb').read())
    v = vmem.VirtualMemory(x.sections, x.mem_align)
    print(transpile(x, v, []))
