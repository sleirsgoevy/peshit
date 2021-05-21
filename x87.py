import recompiler, struct, math

DEFAULT_STATE = (0, 'wtf')

def type_pun(f):
    return int.from_bytes(struct.pack('<d', f), 'little')

pure_instrs = {'fst', 'fadd', 'fsub', 'fmul', 'fdiv', 'fxch', 'fxam', 'fstsw', 'fnstsw', 'fnstsw', 'fsin', 'fcos', 'fptan', 'fstcw', 'fnstcw', 'fldcw', 'fnldcw', 'fist', 'fistt', 'fchs'}
cw_zero_instrs = {'fsin', 'fcos', 'fptan'}
ld_constants = {'fldz': 0, 'fld1': 1, 'fldpi': math.pi}

api_deps = [('msvcrt.dll', 'sin'), ('msvcrt.dll', 'atan2')]

def fpu_delta(instr):
    if not instr.startswith('f'):
        return 0
    if instr.startswith('fld') and instr != 'fldcw' or instr == 'fild':
        return 1
    if instr.endswith('p'):
        return -1
    if instr in pure_instrs:
        return 0
    return ...

def translate_cw_style(style, instr):
    if instr == 'call': return 'wtf'
    if not instr.startswith('f') or instr == 'fstsw': return style
    elif instr == 'fxam': return 'fxam'
    elif instr in cw_zero_instrs: return 'zero'
    return 'wtf'

def translate_state(state, instr, op_str):
    depth, cw_style = state
    d = fpu_delta(instr)
    if d == ...: return DEFAULT_STATE
    if d == None: return (0,)+state[1:]
    depth = max(0, d+state[0])
    cw_style = translate_cw_style(cw_style, instr)
    return (depth, cw_style)

def calculate_states(d_cfg, b_cfg, instrs, preseed, translate_state, default_state):
    q1 = [(i, default_state) for i in preseed]
    q2 = []
    fpu_states = {}
    while q1:
        while q1:
            l, state = q1.pop()
            if l in fpu_states: continue
            fpu_states[l] = state
            if l not in instrs: continue
            state = translate_state(state, instrs[l][0], instrs[l][1])
            q1.extend((i, state) for i in d_cfg[l])
            q2.extend((i, default_state) for i in b_cfg[l])
        q1, q2 = q2, q1
    return fpu_states

def calculate_fpu_states(d_cfg, b_cfg, instrs, preseed):
    return calculate_states(d_cfg, b_cfg, instrs, preseed, translate_state, DEFAULT_STATE)

def check_jump(state1, state2):
    assert state1[0] == state2[0] and state2[1] in (state1[1], 'wtf'), "FPU state mismatch: %r !~= %r"%(state1, state2)

def ret_hack(f, fpu_state):
    assert fpu_state[0] in (0, 1)
    if fpu_state[0] == 1:
        print('vmov d0, d1', file=f)
        return (0,)+fpu_state[1:]
    return fpu_state

def emit(f, cf_style, cur_cf_style, fpu_state, l, ii, bitness):
    fpu_depth, cw_style = fpu_state
    def st(x, bitness=64):
        if isinstance(x, str): x = int(x.split('(', 1)[1].split(')', 1)[0])
        it = fpu_depth - x
        assert it in range(9)
        if bitness == 32: return 's'+str(2*it)
        return 'd'+str(it)
    instr = ii.mnemonic
    if instr in ld_constants:
        print('vldr %s, =0x%x'%(st(-1), type_pun(ld_constants[instr])), file=f)
    elif instr in ('fst', 'fstp'):
        arg = ii.op_str
        if arg.startswith('dword ptr ['):
            print('vcvt.f32.f64 s18, %s'%st(0), file=f)
            recompiler.write_mem(f, arg.split('[', 1)[1].split(']', 1)[0], 'vstr s18')
        elif arg.startswith('qword ptr ['):
            recompiler.write_mem(f, arg.split('[', 1)[1].split(']', 1)[0], 'vstr '+st(0))
        elif arg.startswith('xword ptr ['):
            print('vmov d9, %s'%st(0), file=f)
            recompiler.lea(f, arg.split('[', 1)[1].split(']', 1)[0], 'r0')
            print('bl emu_store_xword', file=f)
        else:
            assert False, "unimplemented"
    elif instr == 'fld':
        arg = ii.op_str
        if arg.startswith('dword ptr ['):
            recompiler.read_mem(f, arg.split('[', 1)[1].split(']', 1)[0], 'vldr '+st(-1, 32))
            print('vcvt.f64.f32 %s, %s'%(st(-1), st(-1, 32)), file=f)
        elif arg.startswith('qword ptr ['):
            recompiler.read_mem(f, arg.split('[', 1)[1].split(']', 1)[0], 'vldr '+st(-1))
        elif arg.startswith('xword ptr ['):
            recompiler.lea(f, arg.split('[', 1)[1].split(']', 1)[0], 'r0')
            print('bl emu_load_xword', file=f)
            print('vmov %s, d9'%st(-1), file=f)
        else:
            assert False, "unimplemented"
    elif instr == 'fild':
        arg = ii.op_str
        if arg.startswith('dword ptr ['):
            recompiler.read_mem(f, arg.split('[', 1)[1].split(']', 1)[0], 'vldr '+st(-1, 32))
            print('vcvt.f64.s32 %s, %s'%(st(-1), st(-1, 32)), file=f)
        elif arg.startswith('qword ptr ['):
            recompiler.read_mem(f, arg.split('[', 1)[1].split(']', 1)[0], 'vldr d9')
            print('vmov r2, s18', file=f)
            print('vcvt.f64.s32 %s, s18'%st(-1), file=f)
            print('vcvt.f64.s32 d9, s19', file=f)
            print('vmov r0, r1, d9', file=f)
            print('add r1, #0x02000000', file=f)
            print('vmov d9, r0, r1', file=f)
            print('vadd.f64 %s, d9'%st(-1), file=f)
            print('lsr r2, #31', file=f)
            print('vmov s18, r2', file=f)
            print('vcvt.f64.s32 d9, s18', file=f)
            print('vmov r2, r3, d9', file=f)
            print('add r3, #0x02000000', file=f)
            print('vmov d9, r2, r3', file=f)
            print('vadd.f64 %s, d9'%st(-1), file=f)
        else:
            assert False, "unimplemented"
    elif instr in ('fadd', 'faddp', 'fsub', 'fsubp', 'fmul', 'fmulp', 'fdiv', 'fdivp'):
        arg = ii.op_str
        print('v%s.f64 %s, %s, %s'%(instr[1:4], st(arg), st(arg), st(0)), file=f)
    elif instr == 'fxch':
        arg = ii.op_str
        print('vmov d9, %s'%st(0), file=f)
        print('vmov %s, %s'%(st(0), st(arg)), file=f)
        print('vmov %s, d9'%st(arg), file=f)
    elif instr == 'fxam':
        print('vmov d10, %s'%st(0), file=f)
    elif instr in ('fstsw', 'fnstsw') and cw_style == 'fxam':
        assert bitness == 16
        print('bl emu_fxam', file=f)
        recompiler.write_arg(f, ii.op_str, 'r0')
    elif instr == 'fsin':
        print('vmov d9, %s'%st(0), file=f)
        print('bl emu_fsin', file=f)
        print('vmov %s, d9'%st(0), file=f)
    elif instr in ('fstsw', 'fnstsw') and cw_style == 'zero':
        assert bitness == 16
        print('mov r0, #0', file=f)
        recompiler.write_arg(f, ii.op_str, 'r0')
    elif instr in ('fstcw', 'fnstcw'):
        assert bitness == 16
        print('bl emu_fstcw', file=f)
        recompiler.write_arg(f, ii.op_str, 'r0')
    elif instr in ('fldcw', 'fnldcw'):
        assert bitness == 16
        recompiler.get_as_reg(f, ii.op_str, 'r0', bitness=bitness)
        print('bl emu_fldcw', file=f)
    elif instr in ('fist', 'fistp'):
        arg = ii.op_str
        if arg.startswith('dword ptr ['):
            print('vcvtr.s32.f64 s18, %s'%st(0), file=f)
            recompiler.write_mem(f, arg.split('[', 1)[1].split(']', 1)[0], 'vstr s18')
        elif arg.startswith('qword ptr ['):
            print('vmov d9, %s'%st(0), file=f)
            print('mov r0, #1', file=f)
            print('bl emu_fist64', file=f)
            print('vmov d9, r0, r1', file=f)
            recompiler.write_mem(f, arg.split('[', 1)[1].split(']', 1)[0], 'vstr d9')
        elif arg.startswith('word ptr ['):
            print('vcvtr.s32.f64 s18, %s'%st(0), file=f)
            print('vmov r0, s18', file=f)
            print('cmp r0, #32768', file=f)
            print('it ge', file=f)
            print('movge r0, #32768', file=f)
            print('ldr r1, =-32768', file=f)
            print('cmp r0, r1', file=f)
            print('it lt', file=f)
            print('movlt r0, #32768', file=f)
            print('lsl r0, #16', file=f)
            recompiler.write_arg(f, arg, 'r0')
        else:
            assert False, "unimplemented"
    elif instr in ('fistt', 'fisttp'):
        arg = ii.op_str
        if arg.startswith('dword ptr ['):
            print('vcvt.s32.f64 s18, %s'%st(0), file=f)
            recompiler.write_mem(f, arg.split('[', 1)[1].split(']', 1)[0], 'vstr s18')
        elif arg.startswith('qword ptr ['):
            print('vmov d9, %s'%st(0), file=f)
            print('mov r0, #0', file=f)
            print('bl emu_fist64', file=f)
            print('vmov d9, r0, r1', file=f)
            recompiler.write_mem(f, arg.split('[', 1)[1].split(']', 1)[0], 'vstr d9')
        elif arg.startswith('word ptr ['):
            print('vcvtr.s32.f64 s18, %s'%st(0), file=f)
            print('vmov r0, s18', file=f)
            print('cmp r0, #32768', file=f)
            print('it ge', file=f)
            print('movge r0, #32768', file=f)
            print('ldr r1, =-32768', file=f)
            print('cmp r0, r1', file=f)
            print('it lt', file=f)
            print('movlt r0, #32768', file=f)
            print('lsl r0, #16', file=f)
            recompiler.write_arg(f, arg, 'r0')
        else:
            assert False, "unimplemented"
    elif instr == 'fchs':
        assert not ii.op_str
        print('vldr d9, =0', file=f)
        print('vsub.f64 %s, d9, %s'%(st(0), st(0)), file=f)
    elif instr in ('fclex', 'fnclex'): pass
    else:
        assert False, "unknown FPU command %s (CW style %s)"%(ii.mnemonic, cw_style)
