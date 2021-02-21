import recompiler, struct

DEFAULT_STATE = (0, 'wtf')

def type_pun(f):
    return int.from_bytes(struct.pack('<d', f), 'little')

pure_instrs = {'fst', 'fadd', 'fsub', 'fmul', 'fdiv', 'fxch', 'fxam', 'fstsw', 'fnstsw'}
ld_constants = {'fldz': 0, 'fld1': 1}

def fpu_delta(instr):
    if not instr.startswith('f'):
        return 0
    if instr.startswith('fld') or instr == 'fild':
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
    return 'wtf'

def translate_state(state, instr):
    depth, cw_style = state
    d = fpu_delta(instr)
    if d == ...: return DEFAULT_STATE
    if d == None: return (0,)+state[1:]
    depth = max(0, d+state[0])
    cw_style = translate_cw_style(cw_style, instr)
    return (depth, cw_style)

def check_jump(state1, state2):
    assert state1[0] == state2[0] and state2[1] in (state1[1], 'wtf'), "FPU state mismatch: %r !~= %r"%(state1, state2)

def ret_hack(f, fpu_state):
    assert fpu_state[0] in (0, 1)
    if fpu_state[0] == 1:
        print('vmov d0, d1', file=f)

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
        else:
            assert False, "unimplemented"
    elif instr in ('fmul', 'fmulp'):
        arg = ii.op_str
        print('vmul.f64 %s, %s'%(st(arg), st(0)), file=f)
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
    else:
        assert False, "unknown FPU command %s (CW style %s)"%(ii.mnemonic, cw_style)
