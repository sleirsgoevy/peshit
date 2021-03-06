import capstone, pefile, vmem, io, json, collections, cfstyle, traceback, x87, sys

TRACE = True
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

cf_add_style_instrs = ('add', 'lock add', 'lock xadd', 'adc')
cf_sub_style_instrs = ('sub', 'cmp', 'lock cmpxchg', 'neg')
cf_xor_style_instrs = ('xor', 'and', 'test', 'or')
cf_shift_style_instrs = ('shl', 'sal', 'shr', 'sar', 'ror')
cf_fuckup_style_instrs = ('idiv', 'div')
cf_bt_style_instrs = ('bt',)
cf_nyi_style_instrs = ('rol',)
CF_FUCKUP = {'bt', 'fstsw', 'fpu_emu', 'nyi'}
cf_ccodes = {'a', 'b', 'ae', 'be', 'g', 'l', 'ge', 'le'}

def translate_cf_style(cur_cf_style, instr, op_str):
    if instr in cf_add_style_instrs:
        cur_cf_style = 'add'
    elif instr in cf_sub_style_instrs:
        cur_cf_style = 'sub'
    elif instr in cf_xor_style_instrs:
        cur_cf_style = 'xor'
    elif instr in ('mul', 'imul'):
        cur_cf_style = 'imul'
    elif instr in cf_shift_style_instrs:
        cur_cf_style = 'shift'
    elif instr in cf_fuckup_style_instrs:
        cur_cf_style = 'noone'
    elif instr in cf_bt_style_instrs:
        cur_cf_style = 'bt'
    elif instr in cf_nyi_style_instrs:
        cur_cf_style = 'nyi'
    elif instr in ('inc', 'dec', 'lock inc', 'lock dec'):
        cur_cf_style = 'inc'
    elif instr in ('fist', 'fistp') and op_str.startswith('word ptr ['):
        cur_cf_style = 'fpu_emu'
    elif instr in ('jmp', 'call', 'ret', 'bnd ret'):
        cur_cf_style = 'noone'
    return cur_cf_style

def get_labels(cs, x, v, preseed0):
    preseed = []
    for i in x.sections:
        if i[3] & 0x20000000: # executable
            preseed.append(i[1]) # vma
    preseed.extend(preseed0)
    preseed.sort()
    preseed1 = list(preseed)
    preseed_set = set(preseed)
    labels = set()
    label_list = []
    cf_uses = set()
    ef_uses = set()
    cfg = collections.defaultdict(list)
    d_cfg = collections.defaultdict(list)
    b_cfg = collections.defaultdict(list)
    instrs = {}
    cf_styles = {}
    for i in preseed:
        cur_cf_style = 'none'
        while i not in labels:
            if len(labels) % 1000 == 0:
                report_progress(len(labels))
            iii = i
            labels.add(i)
            label_list.append(i)
            ii = read_instr_at(cs, v, i)
            if ii == None: break
            cf_styles[i] = cur_cf_style
            instrs[i] = (ii.mnemonic, ii.op_str)
            i += len(ii.bytes)
            if ((ii.mnemonic[0] == 'j' or ii.mnemonic.startswith('bnd j')) and ii.mnemonic not in ('jmp', 'bnd jmp')) or ii.mnemonic.startswith('set') or ii.mnemonic.startswith('cmov'):
                ef_uses.add(iii)
            if ii.mnemonic in ('adc', 'sbb'): cf_uses.add(iii)
            if (ii.mnemonic[0] == 'j' or ii.mnemonic.startswith('bnd j') or ii.mnemonic == 'call') and ii.op_str.startswith('0x'):
                if ii.mnemonic[0] == 'j' and ii.mnemonic[1:] in cf_ccodes: cf_uses.add(iii)
                if ii.mnemonic.startswith('bnd j') and ii.mnemonic[5:] in cf_ccodes: cf_uses.add(iii)
                dst = int(ii.op_str, 16)
                if dst not in preseed_set:
                    preseed.append(dst)
                    preseed_set.add(dst)
            if ii.mnemonic.startswith('cmov') and ii.mnemonic[4:] in cf_ccodes: cf_uses.add(iii)
            if ii.mnemonic in cf_add_style_instrs:
                cur_cf_style = 'add'
            elif ii.mnemonic in cf_sub_style_instrs:
                cur_cf_style = 'sub'
            elif ii.mnemonic in cf_xor_style_instrs:
                cur_cf_style = 'xor'
            elif ii.mnemonic in ('mul', 'imul'):
                cur_cf_style = 'imul'
            elif ii.mnemonic in cf_shift_style_instrs:
                cur_cf_style = 'shift'
            elif ii.mnemonic in cf_fuckup_style_instrs:
                cur_cf_style = 'noone'
            elif ii.mnemonic in cf_bt_style_instrs:
                cur_cf_style = 'bt'
            elif ii.mnemonic in cf_nyi_style_instrs:
                cur_cf_style = 'nyi'
            elif ii.mnemonic in ('inc', 'dec', 'lock inc', 'lock dec'):
                cur_cf_style = 'inc'
            elif ii.mnemonic in ('fist', 'fistp') and ii.op_str.startswith('word ptr ['):
                cur_cf_style = 'fpu_emu'
            # cutting the CFG on CF-style changes is intentional
            elif ii.mnemonic in ('jmp', 'call'):
                try: dst = int(ii.op_str, 16)
                except ValueError: pass
                else: cfg[dst].append(iii)
                cur_cf_style = 'noone'
            elif ii.mnemonic.startswith('j'):
                dst = int(ii.op_str, 16)
                cfg[dst].append(iii)
                cfg[i].append(iii)
            elif ii.mnemonic in ('ret', 'bnd ret'):
                cur_cf_style = 'noone'
            else:
                cfg[i].append(iii)
            if ii.mnemonic in ('jmp', 'call'):
                try: dst = int(ii.op_str, 16)
                except ValueError: pass
                else:
                    d_cfg[iii].append(dst)
                b_cfg[iii].append(i)
            elif ii.mnemonic.startswith('j'):
                dst = int(ii.op_str, 16)
                d_cfg[iii].append(dst)
                d_cfg[iii].append(i)
            elif ii.mnemonic in ('ret', 'bnd ret'):
                b_cfg[iii].append(i)
            else:
                d_cfg[iii].append(i)
    #cf_styles = x87.calculate_states(d_cfg, b_cfg, instrs, preseed1, translate_cf_style, 'noone')
    return label_list, cfstyle.calculate_cf_style(cfg, cf_uses, ef_uses, cf_styles), x87.calculate_fpu_states(d_cfg, b_cfg, instrs, preseed1)

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

emu_rep_movsd:
ldr r0, [r10], #4
str r0, [r11], #4
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

emu_idiv:
//r0 = divisor
bl emu_unsupported
.ascii "idiv 64\\0"

emu_div:
//r0 = divisor
tst r0, r0
beq emu_sigfpe
mov r1, #65536
vmov s18, r1
vcvt.f64.u32 d9, s18
vmul.f64 d9, d9, d9
vmov s22, r6
vcvt.f64.u32 d11, s22
vmul.f64 d11, d11, d9
vmov s18, r4
vcvt.f64.u32 d9, s18
vadd.f64 d9, d9, d11
vmov s22, r0
vcvt.f64.u32 d11, s22
vdiv.f64 d9, d9, d11
vcvt.u32.f64 s18, d9
vmov r1, s18
umull r2, r3, r0, r1
subs r2, r2, r4
sbcs r3, r3, r6
bcs emu_div_inc
adds r2, r2, r0
adcs r3, r3, #0
bcs emu_div_not_dec
emu_div_inc:
add r1, r1, #2
emu_div_dec:
sub r1, r1, #1
emu_div_not_dec:
umull r2, r3, r0, r1
subs r2, r4, r2
sbcs r3, r6, r3
bne emu_sigfpe
cmp r2, r0
bcs emu_sigfpe
mov r6, r2
mov r4, r1
bx lr

emu_sigfpe:
mov r0, #0
udiv r0, r0, r0

emu_load_xword:
//r0 = tbyte ptr
//d9 = ans
ldr r1, [r0, #2]
ldr r2, [r0, #6]
mov r3, r2
and r3, #0xc0000000
lsl r2, #6
lsr r2, #2
lsr ip, r1, #28
orr r2, ip
lsl r1, #4
orr r2, r3
vmov d9, r1, r2
bx lr

emu_store_xword:
//r0 = tbyte ptr
//d9 = ans
vmov r1, r2, d9
lsr r1, #4
lsl ip, r2, #28
orr r1, ip
mov r3, r2
and r3, #0x80000000
eor r2, #0x40000000
lsl r2, #1
asr r2, #4
lsr r2, #1
eor r2, #0x40000000
orr r2, r3
str r2, [r0, #6]
str r1, [r0, #2]
bx lr

emu_trace:
mrs r1, cpsr
push {r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, lr}
mov r1, sp
bl emu_trace_c
pop {r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, lr}
msr cpsr_f, r1
bx lr

emu_trace_get_fpu_regs:
vstr d0, [r0]
vstr d1, [r0, #8]
vstr d2, [r0, #16]
vstr d3, [r0, #24]
vstr d4, [r0, #32]
vstr d5, [r0, #40]
vstr d6, [r0, #48]
vstr d7, [r0, #56]
vstr d8, [r0, #64]
vstr d9, [r0, #72]
bx lr

emu_trace_get_fpu_fpscr:
vmrs r0, fpscr
bx lr

//fpu sw layout: busy C3 t_o_p C2 C1 C0 sum stack inexact undf ovf /0 denormal_operand invalid

emu_fxam:
//d10 = arg
//r0 = (fake sw) << 16
mov r0, #0
vmov r2, r3, d10
//C1 = sign
tst r3, #0x80000000
beq emu_fxam_nonneg
orr r0, #0x02000000
eor r3, #0x80000000
emu_fxam_nonneg:
// zero?
orrs r2, r3
beq emu_fxam_zero
// nan?
ldr r2, =0x7ff00000
cmp r3, r2
bhi emu_fxam_nan
// inf?
beq emu_fxam_inf
// denorm?
cmp r3, #0x00100000
bcc emu_fxam_denorm
// probably normal
orr r0, #0x04000000
bx lr
emu_fxam_nan:
orr r0, #0x01000000
bx lr
emu_fxam_inf:
orr r0, #0x05000000
bx lr
emu_fxam_zero:
orr r0, #0x40000000
bx lr
emu_fxam_denorm:
orr r0, #0x44000000
bx lr

emu_fsin:
//d9 = arg
//d9 = ans
push {fp, lr}
mrs fp, cpsr
vmov r0, r1, d0
push {r0, r1}
vmov r0, r1, d1
push {r0, r1}
vmov r0, r1, d2
push {r0, r1}
vmov r0, r1, d3
push {r0, r1}
vmov r0, r1, d4
push {r0, r1}
vmov r0, r1, d5
push {r0, r1}
vmov r0, r1, d6
push {r0, r1}
vmov r0, r1, d7
push {r0, r1}
vmov r0, r1, d8
push {r0, r1}
vmov r0, r1, d10
push {r0, r1}
vmov d0, d9
bl emu_fsin_c
vmov d9, d0
pop {r0, r1}
vmov d10, r0, r1
pop {r0, r1}
vmov d8, r0, r1
pop {r0, r1}
vmov d7, r0, r1
pop {r0, r1}
vmov d6, r0, r1
pop {r0, r1}
vmov d5, r0, r1
pop {r0, r1}
vmov d4, r0, r1
pop {r0, r1}
vmov d3, r0, r1
pop {r0, r1}
vmov d2, r0, r1
pop {r0, r1}
vmov d1, r0, r1
pop {r0, r1}
vmov d0, r0, r1
msr cpsr_f, fp
pop {fp, pc}

emu_fstcw:
//r0 = cw << 16
vmrs r1, fpscr
mov r2, #0x003c0000
and r0, r2, r1, lsl #9
mov r2, #0x0c000000
and r2, r2, r1, lsl #2
orr r0, r2
orr r0, #0x03000000
bx lr

emu_fldcw:
//r0 = cw << 16
vmrs r1, fpscr
ldr r2, =0xff3fe1ff
and r1, r2
mov r2, #0x00001e00
and r2, r2, r1, lsr #9
orr r1, r2
mov r2, #0x00c00000
and r2, r2, r1, lsr #2
orr r1, r2
vmsr fpscr, r1
bx lr

emu_fist64:
push {r4, lr}
mov r4, r0
mrs ip, cpsr
vmov r0, r1, d9
lsl r1, #1
lsr r1, #1
ldr r2, =0x43e00000
cmp r1, r2
bcs emu_fist64_overflow
ldr r2, =0x08000000
cmp r1, r2
bcc emu_fist64_zero
vmov r0, r1, d9
sub r1, #0x02000000
vmov d11, r0, r1
vcvt.s32.f64 s22, d11
vmov r3, s22
vcvt.f64.s32 d11, s22
vmov r0, r1, d11
add r1, #0x02000000
vmov d11, r0, r1
vsub.f64 d9, d11
vmov r0, r1, d9
sub r1, #0x01000000
vmov d11, r0, r1
vcvt.s32.f64 s22, d11
vmov r2, s22
add r3, r3, r2, asr #16
lsl r2, #16
vcvt.f64.s32 d11, s22
vmov r0, r1, d11
add r1, #0x01000000
vmov d11, r0, r1
vsub.f64 d9, d11
tst r4, r4
it eq
vcvteq.s32.f64 s18, d9
it ne
vcvtrne.s32.f64 s18, d9
vmov r0, s18
asr r1, r0, #31
adds r0, r2
adc r1, r3
msr cpsr_f, ip
pop {r4, pc}
emu_fist64_overflow:
mov r0, #0
mov r1, #0x80000000
msr cpsr_f, ip
pop {r4, pc}
emu_fist64_zero:
mov r0, #0
mov r1, #0
msr cpsr_f, ip
pop {r4, pc}

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

def report_progress(compiled, total=0, fail=0, last_s=['']):
    if compiled < 0:
        s = ''
    elif total > 0:
        s = '%f%%, %d of %d instructions compiled (%d fails)'%(100 * compiled / total, compiled, total, fail)
    else:
        s = 'get_labels: %d instructions processed'%compiled
    s2 = s + ' '*(len(last_s[0]) - len(s))
    last_s[0] = s
    print(s2, end='\r', file=sys.stderr)

def read_mem(f, addr, ldrop): # TODO: rename to rw_mem
    log2 = {1: 0, 2: 1, 4: 2, 8: 3}
    try: addr = int(addr, 16)
    except ValueError: pass
    else:
        print('ldr r2, =0x%x'%addr, file=f)
        print(ldrop+', [r2]', file=f)
        return
    if addr in reg_mapping:
        print('%s, [%s]'%(ldrop, reg_mapping[addr]), file=f)
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
        if right in range(-255, 256) and not (ldrop.startswith('v') and right % 4):
            print('%s, [r2, #%s]'%(ldrop, hex(right)), file=f)
        else:
            print('ldr r3, ='+hex(right), file=f)
            print('add r2, r3', file=f)
            print(ldrop+', [r2]', file=f)
        return
    if ' + ' in addr:
        left, right = addr.split(' + ', 1)
        if left in reg_mapping: 
            try: right = int(right, 0)
            except ValueError: pass
            else:
                if right in range(-255, 256) and not (ldrop.startswith('v') and right % 4):
                    print(ldrop+', [%s, #%s]'%(reg_mapping[left], hex(right)), file=f)
                else:
                    print('ldr r2, ='+hex(right), file=f)
                    print('add r2, r2, '+reg_mapping[left], file=f)
                    print(ldrop+', [r2]', file=f)
                return
    try:
        lea(f, addr, 'r2')
        print(ldrop+', [r2]', file=f)
    except AssertionError as e:
        assert False, "read_mem fallback failed: %s"%e

def read_tls(f, addr, reg):
    try: addr = int(addr, 16)
    except ValueError: pass
    else:
        print('mrc p15, #0, %s, c13, c0, #2'%reg, file=f)
        if addr in range(-255, 256):
            print('ldr %s, [%s, #%s]'%(reg, reg, hex(addr)), file=f)
        else:
            print('ldr r2, =%s'%hex(addr), file=f)
            print('ldr %s, [%s, r2]'%(reg, reg), file=f)

def write_tls(f, addr, reg):
    try: addr = int(addr, 16)
    except ValueError: pass
    else:
        print('mrc p15, #0, r2, c13, c0, #2', file=f)
        if addr in range(-255, 256):
            print('str %s, [r2, #%s]'%(reg, hex(addr)), file=f)
        else:
            print('ldr r3, =%s'%hex(addr), file=f)
            print('str %s, [r2, r3]'%reg, file=f)

def write_mem(f, addr, strop):
    read_mem(f, addr, ldrop=strop)

def read_arg(f, arg, reg, fake=False, bitness=32):
    try: arg = int(arg, 16)
    except ValueError: pass
    else:
        arg <<= (32 - bitness)
        arg &= 0xffffffff
        if arg in range(-255, 256):
            return '#0x%x'%arg
        else:
            print('ldr %s, =0x%x'%(reg, arg), file=f)
            return reg
    if arg in reg_mapping: return reg_mapping[arg]
    if fake: return reg
    if arg.startswith('dword ptr ['):
        read_mem(f, arg.split('[', 1)[1].split(']', 1)[0], 'ldr '+reg)
        return reg
    if arg.startswith('dword ptr fs:['):
        read_tls(f, arg.split('[', 1)[1].split(']', 1)[0], reg)
        return reg
    if arg.startswith('word ptr ['):
        read_mem(f, arg.split('[', 1)[1].split(']', 1)[0], 'ldrh '+reg)
        print('lsl %s, #16'%reg, file=f)
        return reg
    if arg.startswith('byte ptr ['):
        read_mem(f, arg.split('[', 1)[1].split(']', 1)[0], 'ldrb '+reg)
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
        write_mem(f, arg.split('[', 1)[1].split(']', 1)[0], 'str '+reg)
        return
    if arg.startswith('dword ptr fs:['):
        write_tls(f, arg.split('[', 1)[1].split(']', 1)[0], reg)
        return
    if arg.startswith('word ptr ['):
        print('lsr %s, %s, #16'%(reg, reg), file=f)
        write_mem(f, arg.split('[', 1)[1].split(']', 1)[0], 'strh '+reg)
        return
    if arg.startswith('byte ptr ['):
        print('lsr %s, %s, #24'%(reg, reg), file=f)
        write_mem(f, arg.split('[', 1)[1].split(']', 1)[0], 'strb '+reg)
        return
    if '[' in arg:
        assert False, "write_arg failed (unknown memory addressing mode)"
    if arg in regs_8bit:
        assert reg in ('r0', 'r1')
        big_reg = reg_mapping['e' + arg[0] + 'x']
        if arg[1] == 'l':
            print('lsr %s, #24'%reg, file=f)
            print('ldr r2, =0xffffff00', file=f)
        else:
            print('lsr %s, #16'%reg, file=f)
            print('ldr r2, =0xffff00ff', file=f)
        print('and %s, r2'%big_reg, file=f)
        print('orr %s, %s'%(big_reg, reg), file=f)
        return
    if arg in regs_16bit:
        assert reg in ('r0', 'r1')
        big_reg = reg_mapping['e' + arg]
        print('lsr %s, #16'%reg, file=f)
        print('ldr r2, =0xffff0000', file=f)
        print('and %s, r2'%big_reg, file=f)
        print('orr %s, %s'%(big_reg, reg), file=f)
        return
    if arg in reg_mapping and reg != reg_mapping[arg]:
        print('mov %s, %s'%(reg_mapping[arg], reg), file=f)
        return
    if arg not in reg_mapping or reg != reg_mapping[arg]:
        assert False, "write_arg failed (register wtf)"

def load_into_reg(f, arg, reg):
    data = read_arg(f, arg, reg)
    if data != reg:
        print('mov %s, %s'%(reg, data), file=f)

def get_as_reg(f, arg, reg, bitness=32):
    data = read_arg(f, arg, reg, bitness=bitness)
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
    if addr.count(' + ') == 2:
        left, middle, right = addr.split(' + ')
        if '*' in middle:
            middle, scale = middle.split('*')
            print('add %s, %s, %s, lsl #%d'%(reg, reg_mapping[left], reg_mapping[middle], log2[int(scale)]), file=f)
        else:
            print('add %s, %s, %s'%(reg, reg_mapping[left], reg_mapping[middle]), file=f)
        right = int(right, 0)
        if right in range(-255, 256):
            print('add %s, %s, #%d'%(reg, reg, right), file=f)
        else:
            assert reg != 'r3'
            print('ldr r3, ='+hex(right), file=f)
            print('add %s, r3'%reg, file=f)
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
                if right in range(-255, 256) and left_scale == None:
                    print('add %s, %s, #%s'%(reg, reg_mapping[left], hex(right)), file=f)
                else:
                    midreg = reg if reg != reg_mapping[left] else 'r3'
                    print('ldr %s, =%s'%(midreg, hex(right)), file=f)
                    if left_scale == None:
                        print('add %s, %s, %s'%(reg, midreg, reg_mapping[left]), file=f)
                    else:
                        print('add %s, %s, %s, lsl #%d'%(reg, midreg, reg_mapping[left], log2[left_scale]), file=f)
                return
            if right in reg_mapping:
                print('add %s, %s, %s'%(reg, reg_mapping[left], reg_mapping[right]), file=f)
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

def emit(f, cs, x, v, labels, cf_style, fpu_state, wrapper_names):
    tr_success = 0
    tr_fail = 0
    wrapper_names = iter(wrapper_names)
    def check_jump_to(target):
        assert target in cf_style and cf_style[target] in ('none', 'noone', cur_cf_style) and not (cf_style[target] == 'none' and (cur_cf_style == 'noone' or cur_cf_style in CF_FUCKUP)), "TODO: CF style mismatch"
        #assert fpu_state[target] == cur_fpu_state, "FPU mismatch"
        x87.check_jump(cur_fpu_state, fpu_state[target])
    def condjump(cc, target):
        if not isinstance(cc, tuple): cc = (cc,)
        if abs(target - l) < 0x10000 and not TRACE:
            for i in cc:
                print('b%s x86_%x'%(i, target), file=f)
        else:
            for i in cc[:-1]:
                print('b%s x86_%x_jump'%(i, l), file=f)
            i = {'eq': 'ne', 'ne': 'eq', 'cs': 'cc', 'cc': 'cs', 'hs': 'lo', 'lo': 'hs', 'mi': 'pl', 'pl': 'mi', 'vs': 'vc', 'vc': 'vs', 'hi': 'ls', 'ls': 'hi', 'ge': 'lt', 'lt': 'ge', 'gt': 'le', 'le': 'gt'}[cc[-1]]
            print('b%s x86_%x_not_jump'%(i, l), file=f)
            print('x86_%x_jump:'%l, file=f)
            print('b x86_%x'%target, file=f)
            print('x86_%x_not_jump:'%l, file=f)
    cnt_ok = 0
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
                print('mov r2, #%d'%(fpu_state[l][0] + 1 if ii.mnemonic.startswith('f') else 0), file=f)
                print('bl emu_trace', file=f)
            try:
                bitness = guess_bitness(ii.op_str)
                instr = ii.mnemonic
                print('// %x: %s %s'%(l, instr, ii.op_str), file=f)
                try: cur_cf_style = cf_style[l]
                except KeyError: assert False, "unknown CF style"
                try: cur_fpu_state = fpu_state[l]
                except KeyError: assert False, "unknown FPU state"
                if instr in ('add', 'sub', 'xor', 'and', 'or') or instr == 'adc' and cur_cf_style == 'add' or instr == 'sbb' and cur_cf_style == 'sub' or instr == 'lock add' and ('[' not in ii.op_str or ii.op_str.find('[') > ii.op_str.find(',')):
                    if instr == 'xor': instr = 'eor'
                    if instr == 'or': instr = 'orr'
                    if instr == 'sbb': instr = 'sbc'
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
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    #if '[' in arg1:
                    #    write_arg(f, arg1, get_as_reg(f, arg2, 'r0'))
                    #elif '[' in arg2:
                    #    read_arg(f, arg2, read_arg(f, arg1, 'r0'), bitness=bitness)
                    #else:
                    #    try: arg2i = int(arg2, 0)
                    #    except ValueError: print('mov %s, %s'%(reg_mapping[arg1], reg_mapping[arg2]), file=f)
                    #    else: print('ldr %s, =%s'%(reg_mapping[arg1], arg2i), file=f)
                    write_arg(f, arg1, get_as_reg(f, arg2, read_arg(f, arg1, 'r0', bitness=bitness, fake=True), bitness=bitness))
                elif instr == 'call':
                    try: target = int(ii.op_str, 16)
                    except ValueError:
                        load_into_reg(f, ii.op_str.strip(), 'r0')
                        print('ldr r1, ='+hex(l+len(ii.bytes)), file=f)
                        print('str r1, [r8, #-4]!', file=f)
                        print('bl emu_dispatch_indir', file=f)
                        print('bx r0', file=f)
                    else:
                        assert target in cf_style and cf_style[target] in ('none', 'noone'), "call to CF-aware code"
                        assert cur_fpu_state == fpu_state[target] == x87.DEFAULT_STATE, "FPU ABI violation: caller %r, callee %r"%(cur_fpu_state, fpu_state[target])
                        print('ldr r1, ='+hex(l+len(ii.bytes)), file=f)
                        print('str r1, [r8, #-4]!', file=f)
                        if TRACE:
                            print('ldr r0, =1+x86_%x'%target, file=f)
                            print('bx r0', file=f)
                        else:
                            print('b x86_%x'%target, file=f)
                    ok = False
                elif instr == 'push':
                    assert ii.op_str.strip() != 'esp'
                    print('str %s, [r8, #-4]!'%get_as_reg(f, ii.op_str.strip(), 'r0'), file=f)
                elif instr == 'je':
                    assert cur_cf_style not in CF_FUCKUP
                    target = int(ii.op_str, 16)
                    check_jump_to(target)
                    #assert target in cf_style and cf_style[target] in ('none', 'noone', cur_cf_style), "TODO: CF style mismatch"
                    condjump('eq', target)
                elif instr in ('jne', 'bnd jne'):
                    assert cur_cf_style not in CF_FUCKUP
                    target = int(ii.op_str, 16)
                    check_jump_to(target)
                    #assert target in cf_style and cf_style[target] in ('none', 'noone', cur_cf_style), "TODO: CF style mismatch"
                    condjump('ne', target)
                elif instr in ('js', 'bnd js'):
                    assert cur_cf_style not in CF_FUCKUP
                    target = int(ii.op_str, 16)
                    check_jump_to(target)
                    #assert target in cf_style and cf_style[target] in ('none', 'noone', cur_cf_style), "TODO: CF style mismatch"
                    condjump('mi', target)
                elif instr in ('jns', 'bnd jbs'):
                    assert cur_cf_style not in CF_FUCKUP
                    target = int(ii.op_str, 16)
                    check_jump_to(target)
                    #assert target in cf_style and cf_style[target] in ('none', 'noone', cur_cf_style), "TODO: CF style mismatch"
                    condjump('pl', target)
                elif instr in ('jo', 'bnd jo'):
                    assert cur_cf_style not in CF_FUCKUP
                    target = int(ii.op_str, 16)
                    check_jump_to(target)
                    condjump('vs', target)
                elif instr in ('jno', 'bnd jno'):
                    assert cur_cf_style not in CF_FUCKUP
                    target = int(ii.op_str, 16)
                    check_jump_to(target)
                    condjump('vc', target)
                elif instr in ('jb', 'bnd jb'):
                    target = int(ii.op_str, 16)
                    cc = {'add': 'cs', 'sub': 'cc', 'bt': 'cs'}[cur_cf_style]
                    check_jump_to(target)
                    #assert target in cf_style and cf_style[target] in ('none', 'noone', cur_cf_style), "TODO: CF style mismatch"
                    condjump(cc, target)
                elif instr in ('ja', 'bnd ja'):
                    target = int(ii.op_str, 16)
                    assert cur_cf_style == 'sub', "TODO: ja with %s-style CF"%cur_cf_style
                    check_jump_to(target)
                    #assert target in cf_style and cf_style[target] in ('none', 'noone', cur_cf_style), "TODO: CF style mismatch"
                    condjump('hi', target)
                elif instr in ('jbe', 'bnd jbe'):
                    target = int(ii.op_str, 16)
                    assert cur_cf_style == 'sub', "TODO: jbe with %s-style CF"%cur_cf_style
                    check_jump_to(target)
                    #assert target in cf_style and cf_style[target] in ('none', 'noone', cur_cf_style), "TODO: CF style mismatch"
                    condjump('ls', target)
                elif instr in ('jae', 'bnd jae'):
                    target = int(ii.op_str, 16)
                    cc = {'add': 'cc', 'sub': 'cs', 'bt': 'cc'}[cur_cf_style]
                    check_jump_to(target)
                    #assert target in cf_style and cf_style[target] in ('none', 'noone', cur_cf_style), "TODO: CF style mismatch"
                    condjump(cc, target)
                elif instr in ('jl', 'jle', 'jg', 'jge'):
                    assert cur_cf_style in ('add', 'sub', 'xor'), cur_cf_style
                    target = int(ii.op_str, 16)
                    check_jump_to(target)
                    #assert target in cf_style and cf_style[target] in ('none', 'noone', cur_cf_style), "TODO: CF style mismatch"
                    if cur_cf_style == 'xor':
                        if instr == 'jl':
                            condjump('mi', target)
                        elif instr == 'jge':
                            condjump('pl', target)
                        elif instr == 'jg':
                            print('beq x86_%x_nojump'%l, file=f)
                            condjump('pl', target)
                            print('x86_%x_nojump:'%l, file=f)
                        elif instr == 'jle':
                            condjump(('eq', 'mi'), target)
                    else:
                        if len(instr) == 2: instr += 't'
                        condjump(instr[1:], target)
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
                elif instr in ('ret', 'bnd ret'):
                    cur_fpu_state = x87.ret_hack(f, cur_fpu_state)
                    x87.check_jump(cur_fpu_state, x87.DEFAULT_STATE)
                    print('ldr r0, [r8], #4', file=f)
                    try: stdcall = int(ii.op_str, 0)
                    except ValueError: pass
                    else: print('add r8, r8, #'+hex(stdcall), file=f)
                    print('bl emu_dispatch_indir', file=f)
                    print('bx r0', file=f)
                    ok = False
                elif instr == 'pop':
                    arg = ii.op_str.strip()
                    assert arg != 'esp'
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
                        check_jump_to(target)
                        #assert target in cf_style and cf_style[target] in ('none', 'noone', cur_cf_style), "TODO: CF style mismatch"
                        if TRACE:
                            print('ldr r0, =1+x86_%x'%target, file=f)
                            print('bx r0', file=f)
                        else:
                            print('b x86_%x'%target, file=f)
                    ok = False
                elif instr == 'rep stosd':
                    print('bl emu_rep_stosd', file=f)
                elif instr == 'rep movsd':
                    print('bl emu_rep_movsd', file=f)
                elif instr == 'lock cmpxchg':
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    if arg1 in reg_mapping:
                        print('cmp r4,', reg_mapping[arg1], file=f)
                        print('it eq', file=f)
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
                        print('mov r0, %s'%reg_mapping[arg1], file=f)
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
                    assert cur_cf_style not in CF_FUCKUP
                    print('mov r0, #0', file=f)
                    cc = instr[3:]
                    if cc == 'e': cc = 'eq'
                    print('it', cc, file=f)
                    print('mov'+cc+' r0, #1', file=f)
                    print('lsl r0, #24', file=f)
                    write_arg(f, ii.op_str, 'r0')
                elif instr in ('movzx', 'movsx'):
                    #assert cur_cf_style not in CF_FUCKUP
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    bitness1 = guess_bitness(arg1)
                    bitness2 = guess_bitness(arg2)
                    assert bitness2 < bitness1, "invalid movzx"
                    arg2r = read_arg(f, arg2, read_arg(f, arg1, 'r0', fake=True), bitness=bitness2)
                    print(('a' if instr[3] == 's' else 'l')+'sr %s, #%d'%(arg2r, bitness1 - bitness2), file=f)
                    write_arg(f, arg1, arg2r)
                elif instr == 'fninit': pass # TODO: stub
                elif instr in ('cmove', 'cmovne', 'cmovs', 'cmovns'):
                    assert cur_cf_style not in CF_FUCKUP
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    assert arg1 in reg_mapping and arg2 in reg_mapping, "weird cmov args"
                    cc = {'e': 'eq', 'ne': 'ne', 's': 'mi', 'ns': 'pl'}[instr[4:]]
                    print('it', cc, file=f)
                    print('mov%s %s, %s'%(cc, reg_mapping[arg1], reg_mapping[arg2]), file=f)
                elif instr in ('cmovl', 'cmovle', 'cmovg', 'cmovge'):
                    assert cur_cf_style in ('add', 'sub'), cur_cf_style
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    assert arg1 in reg_mapping and arg2 in reg_mapping, "weird cmov args"
                    cc = instr[4:]
                    if len(cc) == 1: cc += 't'
                    print('it', cc, file=f)
                    print('mov%s %s, %s'%(cc, reg_mapping[arg1], reg_mapping[arg2]), file=f)
                elif instr in ('cmovb', 'cmovae'):
                    assert cur_cf_style in ('add', 'sub'), cur_cf_style
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    assert arg1 in reg_mapping and arg2 in reg_mapping, "weird cmov args"
                    cc = ('cs', 'cc')[(cur_cf_style == 'sub') ^ (instr == 'cmovae')]
                    print('it', cc, file=f)
                    print('mov%s %s, %s'%(cc, reg_mapping[arg1], reg_mapping[arg2]), file=f)
                elif instr in ('cmova', 'cmovbe'):
                    assert cur_cf_style == 'sub', cur_cf_style
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    assert arg1 in reg_mapping and arg2 in reg_mapping, "weird cmov args"
                    cc = {'cmova': 'hi', 'cmovbe': 'ls'}[instr]
                    print('it', cc, file=f)
                    print('mov%s %s, %s'%(cc, reg_mapping[arg1], reg_mapping[arg2]), file=f)
                elif instr == 'imul' and ',' not in ii.op_str:
                    assert bitness == 32
                    arg_r = read_arg(f, ii.op_str, 'r0', bitness=bitness)
                    print('mov r2, r4', file=f)
                    print('smull r4, r6, r2, %s'%arg_r, file=f)
                    if cf_style[l+len(ii.bytes)] not in ('none', 'noone'):
                        print('add r2, r6, #1', file=f)
                        print('cmp r2, #2', file=f)
                elif instr == 'imul':
                    assert bitness == 32 and ',' in ii.op_str, "TODO"
                    if ii.op_str.count(',') == 2:
                        arg1, arg2, imm = map(str.strip, ii.op_str.split(','))
                        arg1r = read_arg(f, arg1, 'r0', bitness=bitness)
                        arg2r = read_arg(f, arg2, 'r0', bitness=bitness)
                        print('ldr r2, ='+str(int(imm, 0)), file=f)
                        if cf_style[l + len(ii.bytes)] in ('none', 'noone'):
                            print('mul %s, r2, %s'%(arg1r, arg2r), file=f)
                        else:
                            print('smull %s, r3, r2, %s'%(arg1r, arg2r), file=f)
                            print('add r3, r3, #1', file=f)
                            print('cmp r3, #2', file=f)
                        write_arg(f, arg1, arg1r)
                    else:
                        arg1, arg2 = map(str.strip, ii.op_str.split(','))
                        arg1r = read_arg(f, arg1, 'r0', bitness=bitness)
                        arg2r = read_arg(f, arg2, 'r1', bitness=bitness)
                        assert l + len(ii.bytes) in cf_style, "wtf"
                        if cf_style[l + len(ii.bytes)] in ('none', 'noone'):
                            if arg1r != arg2r:
                                print('mul %s, %s, %s'%(arg1r, arg2r, arg1r), file=f)
                            else:
                                print('mov r2, '+arg1r, file=f)
                                print('mul %s, r2'%arg1r, file=f)
                        else:
                            if arg1r == arg2r:
                                print('smull %s, r3, %s, %s'%(arg1r, arg1r, arg2r), file=f)
                            else:
                                print('mov r2, '+arg1r, file=f)
                                print('smull %s, r3, r2, %s'%(arg1r, arg2r), file=f)
                            print('add r3, r3, #1', file=f)
                            print('cmp r3, #2', file=f)
                        write_arg(f, arg1, arg1r)
                elif instr in ('shr', 'sar'):
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    bitness1 = guess_bitness(arg1)
                    op = ('l' if instr == 'shr' else 'a')+'srs'
                    assert cur_cf_style in ('none', 'noone', 'add'), "wtf??"
                    if arg2 == 'cl':
                        arg1r = read_arg(f, arg1, 'r0', bitness=bitness1)
                        print('and r2, r5, #%d'%(bitness1 - 1), file=f)
                        print('cbnz r2, x86_%x_do'%l, file=f)
                        print('b x86_%x'%(l+len(ii.bytes)), file=f)
                        print('x86_%x_do:'%l, file=f)
                        print(op, '%s, r2'%arg1r, file=f)
                        if bitness1 != 32:
                            print(op, '%s, #%d'%(arg1r, 32 - bitness1), file=f)
                            if bitness1 != 32: print('lsl %s, #%d'%(arg1r, 32 - bitness1), file=f)
                        write_arg(f, arg1, arg1r)
                    else:
                        arg2 = int(arg2, 0)
                        if arg2 != 0:
                            arg1r = read_arg(f, arg1, 'r0', bitness=bitness1)
                            print(op, '%s, #%d'%(arg1r, arg2 + 32 - bitness1), file=f)
                            if bitness1 != 32: print('lsl %s, #%d'%(arg1r, 32 - bitness1), file=f)
                            write_arg(f, arg1, arg1r)
                elif instr in ('shl', 'sal'):
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    bitness1 = guess_bitness(arg1)
                    assert cur_cf_style in ('none', 'noone', 'add'), "wtf??"
                    if arg2 == 'cl':
                        arg1r = read_arg(f, arg1, 'r0', bitness=bitness1)
                        print('and r2, r5, #%d'%(bitness1 - 1), file=f)
                        print('cbnz r2, x86_%x_do'%l, file=f)
                        print('b x86_%x'%(l+len(ii.bytes)), file=f)
                        print('x86_%x_do:'%l, file=f)
                        print('lsls %s, r2'%arg1r, file=f)
                        write_arg(f, arg1, arg1r)
                    else:
                        arg2 = int(arg2, 0)
                        if arg2 != 0:
                            arg1r = read_arg(f, arg1, 'r0', bitness=bitness1)
                            print('lsls %s, #%d'%(arg1r, arg2 + 32 - bitness1), file=f)
                            write_arg(f, arg1, arg1r)
                elif instr == 'ror':
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    bitness1 = guess_bitness(arg1)
                    assert bitness1 == 32
                    assert cur_cf_style in ('none', 'noone', 'add'), "wtf??"
                    if arg2 == 'cl':
                        arg1r = read_arg(f, arg1, 'r0', bitness=bitness1)
                        print('and r2, r5, #31', file=f)
                        print('cbnz r2, x86_%x_do'%l, file=f)
                        print('b x86_%x'%(l+len(ii.bytes)), file=f)
                        print('x86_%x_do:'%l, file=f)
                        print('rors %s, r2'%arg1r, file=f)
                        write_arg(f, arg1, arg1r)
                    else:
                        arg2 = int(arg2, 0)
                        if arg2 != 0:
                            arg1r = read_arg(f, arg1, 'r0', bitness=bitness1)
                            print('rors %s, %s, #%d'%(arg1r, arg1r, arg2), file=f)
                            write_arg(f, arg1, arg1r)
                elif instr == 'rol':
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    bitness1 = guess_bitness(arg1)
                    assert bitness1 == 32
                    if arg2 == 'cl':
                        arg1r = read_arg(f, arg1, 'r0', bitness=bitness1)
                        print('and r2, r5, #31', file=f)
                        print('rsb r2, r2, #32', file=f)
                        print('ror %s, r2'%arg1r, file=f)
                        write_arg(f, arg1, arg1r)
                    else:
                        arg2 = int(arg2, 0)
                        if arg2 != 0:
                            arg1r = read_arg(f, arg1, 'r0', bitness=bitness1)
                            print('ror %s, %s, #%d'%(arg1r, arg1r, 32-arg2), file=f)
                            write_arg(f, arg1, arg1r)
                elif instr == 'cdq':
                    print('mov r6, r4, asr #31', file=f)
                elif instr == 'idiv':
                    arg_r = read_arg(f, ii.op_str, 'r0', bitness=bitness)
                    print('sub r2, r6, r4, asr #31', file=f)
                    print('cbz r2, x86_%x_fast'%l, file=f)
                    if arg_r != 'r0': print('mov r0, %s'%arg_r, file=f)
                    print('bl emu_idiv', file=f)
                    print('b x86_%x'%(l+len(ii.bytes)), file=f)
                    print('x86_%x_fast:'%l, file=f)
                    print('sdiv r3, r4, %s'%arg_r, file=f)
                    print('mul r2, r3, %s'%arg_r, file=f)
                    print('sub r6, r4, r2', file=f)
                    print('mov r4, r3', file=f)
                elif instr == 'div':
                    arg_r = read_arg(f, ii.op_str, 'r0', bitness=bitness)
                    print('cbz r6, x86_%x_fast'%l, file=f)
                    if arg_r != 'r0': print('mov r0, %s'%arg_r, file=f)
                    print('bl emu_div', file=f)
                    print('b x86_%x'%(l+len(ii.bytes)), file=f)
                    print('x86_%x_fast:'%l, file=f)
                    print('udiv r3, r4, %s'%arg_r, file=f)
                    print('mul r2, r3, %s'%arg_r, file=f)
                    print('sub r6, r4, r2', file=f)
                    print('mov r4, r3', file=f)
                elif instr == 'bt':
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    arg1r = read_arg(f, arg1, 'r0', bitness=bitness)
                    arg2r = read_arg(f, arg2, 'r1', bitness=bitness)
                    if arg2r.startswith('#'):
                        shift = int(arg2r[1:], 0) & (bitness - 1)
                        if shift == 0 and bitness == 32:
                            print('lsrs r0, %s, #1'%arg1r, file=f)
                        else:
                            print('lsls r0, %s, #%d'%(arg1r, bitness - shift), file=f)
                    else:
                        print('and r2, %s, #%d'%(arg2r, bitness-1), file=f)
                        print('lsr r0, %s, r2'%arg1r, file=f)
                        print('lsrs r0, #%d'%(33 - bitness), file=f)
                elif instr == 'mul':
                    arg_r = read_arg(f, ii.op_str, 'r0', bitness=bitness)
                    if arg_r in ('r4', 'r6'):
                        print('mov r0, %s'%arg_r, file=f)
                        arg_r = r0
                    print('umull r4, r6, %s, r4'%arg_r, file=f)
                    assert l + len(ii.bytes) in cf_style
                    if cf_style[l + len(ii.bytes)] not in ('none', 'noone'):
                        print('cmp r6, #1', file=f)
                elif instr == 'lock add':
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    assert arg1.startswith('dword ptr [')
                    lea(f, arg1.split('[', 1)[1].split(']', 1)[0], 'r0')
                    arg2r = read_arg(f, arg2, 'r1', bitness=bitness)
                    print('x86_%x_loop:'%l, file=f)
                    print('ldrex r2, [r0]', file=f)
                    print('adds r2, '+arg2r, file=f)
                    print('strex r3, r2, [r0]', file=f)
                    print('cbz r3, x86_%x_done'%l, file=f)
                    print('b x86_%x_loop'%l, file=f)
                    print('x86_%x_done:'%l, file=f)
                elif instr == 'lock xadd':
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    assert bitness == 32 and arg2 in reg_mapping
                    if '[' not in arg1:
                        print('adds r0, %s, %s'%(reg_mapping[arg1], reg_mapping[arg2]), file=f)
                        print('mov %s, %s'%(reg_mapping[arg2], reg_mapping[arg1]), file=f)
                        print('mov %s, r0'%reg_mapping[arg1], file=f)
                    else:
                        lea(f, arg1.split('[', 1)[1].split(']', 1)[0], 'r0')
                        print('x86_%x_loop:'%l, file=f)
                        print('ldrex r1, [r0]', file=f)
                        print('adds r2, r1, '+reg_mapping[arg2], file=f)
                        print('strex r3, r2, [r0]', file=f)
                        print('cbz r3, x86_%x_ok'%l, file=f)
                        print('b x86_%x_loop'%l, file=f)
                        print('x86_%x_ok:'%l, file=f)
                        print('mov %s, r1'%reg_mapping[arg2], file=f)
                elif instr in ('wait', 'fwait'): pass
                elif instr == 'adc' and cur_cf_style == 'sub':
                    #invert CF
                    print('mov r0, #0', file=f)
                    print('it cc', file=f)
                    print('movcc r0, #0x80000000', file=f)
                    print('adds r0, r0', file=f)
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    arg1r = read_arg(f, arg1, 'r0', bitness=bitness)
                    arg2r = read_arg(f, arg2, 'r1', bitness=bitness)
                    print('adcs %s, %s, %s'%(arg1r, arg1r, arg2r), file=f)
                    write_arg(f, arg1, arg1r)
                elif instr == 'sbb' and cur_cf_style == 'add':
                    #invert CF
                    print('mov r0, #0', file=f)
                    print('it cc', file=f)
                    print('movcc r0, #0x80000000', file=f)
                    print('adds r0, r0', file=f)
                    arg1, arg2 = map(str.strip, ii.op_str.split(','))
                    arg1r = read_arg(f, arg1, 'r0', bitness=bitness)
                    arg2r = read_arg(f, arg2, 'r1', bitness=bitness)
                    print('sbcs %s, %s, %s'%(arg1r, arg1r, arg2r), file=f)
                    write_arg(f, arg1, arg1r)
                elif instr in ('adc', 'sbb'):
                    assert False, "%s unsupported with %s-style CF"%(instr, cur_cf_style)
                elif instr.startswith('f'):
                    x87.emit(f, cf_style, cur_cf_style, fpu_state[l], l, ii, bitness)
                elif instr == 'cwde':
                    print('lsl r4, #16', file=f)
                    print('asr r4, #16', file=f)
                elif instr in ('inc', 'dec') or instr in ('lock inc', 'lock dec') and '[' not in ii.op_str:
                    instr = {'inc': 'add', 'dec': 'sub', 'lock inc': 'add', 'lock dec': 'sub'}[instr]
                    arg_r = read_arg(f, ii.op_str.strip(), 'r0', bitness=bitness)
                    print('%ss %s, %s, #1'%(instr, arg_r, arg_r), file=f)
                    write_arg(f, ii.op_str.strip(), arg_r)
                elif instr in ('lock inc', 'lock dec'):
                    assert bitness == 32
                    instr = {'lock inc': 'add', 'lock dec': 'sub'}[instr]
                    lea(f, ii.op_str.split('[', 1)[1].split(']', 1)[0], 'r0')
                    print('x86_%x_retry:'%l, file=f)
                    print('ldrex r1, [r0]', file=f)
                    print('%ss r1, r1, #1'%instr, file=f)
                    print('strex r2, r1, [r0]', file=f)
                    print('cbz r2, x86_%x_ok'%l, file=f)
                    print('b x86_%x_retry'%l, file=f)
                    print('x86_%x_ok:'%l, file=f)
                elif instr == 'stosd':
                    assert ii.op_str.strip() == 'dword ptr es:[edi], eax'
                    print('str r4, [r11], #4', file=f)
                elif instr == 'movsd':
                    assert ii.op_str.strip() == 'dword ptr es:[edi], dword ptr [esi]'
                    print('ldr r0, [r10], #4', file=f)
                    print('str r0, [r11], #4', file=f)
                else:
                    assert False, "unknown mnemonic %s"%ii.mnemonic
                tr_success += 1
            except Exception:
                tr_fail += 1
                instr = (ii.mnemonic+' '+ii.op_str).strip()
                if TRACEBACKS: instr += '\n' + traceback.format_exc()
                print('bl emu_unsupported', file=f) # no way to recover
                print(asciz(instr.strip()), file=f)
                ok = False
        if ok and (i + 1 < len(labels) and labels[i+1] != l + len(ii.bytes) or TRACE and cnt_ok > 128):
            print('b x86_%x'%(l + len(ii.bytes)), file=f)
            ok = False
        if not ok:
            print('.ltorg', file=f)
            cnt_ok = 0
        else:
            cnt_ok += 1
        if i % 1000 == 0: report_progress(i, len(labels), tr_fail)
    report_progress(-1)
    print('%d instructions OK, %d instructions FAIL'%(tr_success, tr_fail))

def transpile(x, v, preseed, entry, wrapper_names):
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    labels, cf_style, fpu_state = get_labels(cs, x, v, preseed)
    indir_bl = {i for i in cf_style if cf_style[i] not in ('none', 'noone') or fpu_state[i] != x87.DEFAULT_STATE}
    f = io.StringIO()
    emit(f, cs, x, v, labels, cf_style, fpu_state, wrapper_names)
    return arm_crt.replace('ENTRY', 'x86_%x'%entry)+f.getvalue(), indir_bl

if __name__ == '__main__':
    import sys
    x = pefile.PeFile(open(sys.argv[1], 'rb').read())
    v = vmem.VirtualMemory(x.sections, x.mem_align)
    print(transpile(x, v, []))
