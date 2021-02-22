import pefile, vmem, iatindir, stubgen, recompiler, cc, indir, tlshooks, x87

arm_crt = r'''
asm("sys_write:\nmov r7, #4\nsvc #0\nbx lr");

int sys_write(int, const void*, int);

void dbg_puts(const char* str)
{
    int l = 0;
    while(str[l])
        l++;
    sys_write(2, str, l);
}

void dbg_putn(unsigned int ii)
{
    char c[9];
    for(int i = 7; i >= 0; i--)
    {
        int x = ii & 15;
        ii >>= 4;
        if(x < 10)
            c[i] = x + '0';
        else
            c[i] = x + 'a' - 10;
    }
    c[8] = 0;
    dbg_puts(c);
}

void emu_unsupported_c(const char* mnemonic)
{
    dbg_puts("Unsupported instruction: ");
    dbg_puts(mnemonic);
    dbg_puts("\n");
    *(void* volatile*)0;
}

void emu_fault(void)
{
    dbg_puts("SIGSEGV while reading instruction.\n");
    *(void* volatile*)0;
}

void emu_indir_invalid(unsigned int addr)
{
    dbg_puts("Indirect branch to invalid address 0x");
    dbg_putn(addr);
    dbg_puts(".\n");
    *(void* volatile*)0;
}

void emu_trace_get_fpu_regs(unsigned int*);
unsigned int emu_trace_get_fpu_fpscr(void);

void emu_trace_c(unsigned int eip, unsigned int regs[12], int do_dump_fpu)
{
    dbg_puts("eip=");
    dbg_putn(eip);
#define D(x, y) dbg_puts(" " #x "="); dbg_putn(regs[y])
    D(translated, 11);
    D(cpsr, 0);
    D(eax, 3);
    D(ecx, 4);
    D(edx, 5);
    D(ebx, 6);
    D(esp, 7);
    D(ebp, 8);
    D(esi, 9);
    D(edi, 10);
#undef D
    if(do_dump_fpu)
    {
        unsigned int fpu_regs[20];
        emu_trace_get_fpu_regs(fpu_regs);
        for(int i = 0; i < 10; i++)
        {
            if(i == do_dump_fpu)
                dbg_puts(" |");
            char buf[5] = {' ', 'd', '0'+i, '=', 0};
            dbg_puts(buf);
            dbg_putn(fpu_regs[2*i+1]);
            dbg_putn(fpu_regs[2*i]);
        }
        dbg_puts(" fpscr=");
        dbg_putn(emu_trace_get_fpu_fpscr());
    }
    dbg_puts("\n");
}

unsigned int emu_trace_callback_entry(unsigned int param)
{
    dbg_puts("<<< callback\n");
    return param;
}

void emu_trace_callback_exit(void)
{
    dbg_puts(">>> callback\n");
}

double emu_fsin_c(double d)
{
    return ((double(*)(double))WINAPI::[sin])(d);
}

unsigned int emu_do_callback(void* fn, void* reserved, ...);
void emu_callback_ret(void);
unsigned int emu_call_native(void* param, unsigned int param_len, void* fn);

void* emu_malloc(unsigned int sz)
{
    //FIXME
    return ((void*(*)(void*, unsigned int, int, int))WINAPI::[VirtualAlloc])(0, sz, 0x1000, 0x40);
}

void emu_cacheflush(void* addr, unsigned int sz)
{
    unsigned int handle = ((unsigned int(*)(void))WINAPI::[GetCurrentProcess])();
    ((void(*)(unsigned int, void*, unsigned int))WINAPI::[FlushInstructionCache])(handle, addr, sz);
}
'''

def castrate(x):
    x.dos_stub[:] = b'MZ' + bytes(62)
    x.pe_header[8:20] = bytes(12)
    x.pe_header[26:40] = bytes(14)
    x.pe_header[44:52] = bytes(8)
    x.pe_header[66:72] = bytes(6)
    x.pe_header[74:80] = bytes(6)
    x.pe_header[94:116] = bytes(22)
    x.sections.sort(key=lambda x:x[1])

def process_winapi(code, import_map):
    sp = code.split('WINAPI::[')
    for i in range(1, len(sp)):
        x, y = sp[i].split(']', 1)
        sp[i] = '(*(void**)' + hex(import_map[x]) + ')' + y
    return ''.join(sp)

def main(f1, f2):
    with open(f1, 'rb') as file:
        x = pefile.PeFile(file.read())
    v = vmem.VirtualMemory(x.sections, x.mem_align)
    imports = iatindir.iatindir(x, v, [('kernel32.dll', 'VirtualAlloc'), ('kernel32.dll', 'FlushInstructionCache')]+x87.api_deps, deps=stubgen.wrapper_deps)
    import_map = {l: j for i, j, k, l in imports}
    imports = [i for i in imports if i[0] != None]
    x86_stub, arm_stub, wrapper_names = stubgen.gen_decls('i686', {l: '*(void**)'+hex(j) for i, j, k, l in imports})
    x86_code, x86_syms = cc.compile_x86(x86_stub, '')
    x86_addr, x86_buf = v.alloc(len(x86_code), 0x60000000, '.glue1')
    x86_buf[:len(x86_code)] = x86_code
    for i, j, k, l in imports:
        if l in stubgen.external_non_funcs: continue
        v[i:i+4] = (x86_addr + x86_syms['_'+l]).to_bytes(4, 'little')
    x86_entry = x.base_addr + int.from_bytes(x.pe_header[40:44], 'little')
    arm_tls_hook, x86_tls_callbacks = tlshooks.install_tls_hooks(x, v)
    indir_tbl, indir_buf = indir.gen_indir_tables(x, v)
    indir_buf_offset = 0
    preseed = [x86_entry]
    arm_asm, indir_bl = recompiler.transpile(x, v, preseed, x86_entry, wrapper_names)
    x.sections[:] = [(i, j, k, l&~0x20000000, m) for i, j, k, l, m in x.sections]
    arm_c_code = arm_crt+arm_stub+'\n'
    arm_c_code += 'unsigned int emu_dispatch_indir(unsigned int addr)\n{\n'
    arm_c_code += '    if(addr == 0x179)\n'
    arm_c_code += '        return 1 | (unsigned int)&emu_callback_ret;\n'
    arm_c_code += '    unsigned int ans = 0;\n'
    for i, j, k in indir_tbl:
        arm_c_code += '    if(addr >= '+hex(i)+'u && addr <= '+hex(j)+'u)\n'
        arm_c_code += '        ans = ((volatile unsigned int*)'+hex(k)+')[addr - '+hex(i)+'u];\n'
    arm_c_code += '    if(ans == 0)\n'
    arm_c_code += '        emu_indir_invalid(addr);\n'
    arm_c_code += '    return ans;\n'
    arm_c_code += '}\n'
    arm_c_code += 'void iat_fixup(void)\n{\n'
    for i, j, k, l in imports:
        if l in stubgen.external_non_funcs:
            arm_c_code += '    *(void* volatile*)0x%x = (void*)0x%x;\n'%(i, j)
    arm_c_code += '}\n'
    arm_c_code += 'void emu_tls_hook(void* handle, unsigned int reason, void* reserved)\n{\n'
    arm_c_code += '    if(reason == 1)\n'
    arm_c_code += '        iat_fixup();\n'
    for i in x86_tls_callbacks:
        arm_c_code += '    emu_do_callback((void*)'+hex(i)+', 0, handle, reason, reserved);\n'
    arm_c_code += '}\n'
    arm_c_code = process_winapi(arm_c_code, import_map)
    arm_code, arm_syms = cc.compile_arm(arm_c_code, arm_asm, v.sim_alloc())
    arm_addr, arm_buf = v.alloc(len(arm_code), 0x60000000, '.glue2')
    arm_buf[:len(arm_code)] = arm_code
    for i, j, k in indir_tbl:
        for l in range(i, j):
            if l not in indir_bl and 'x86_%x'%l in arm_syms:
                indir_buf[indir_buf_offset:indir_buf_offset+4] = (arm_addr + arm_syms['x86_%x'%l] | 1).to_bytes(4, 'little')
            indir_buf_offset += 4
    x.pe_header[4:6] = b'\xc4\x01'
    x.pe_header[40:44] = ((arm_addr + arm_syms['emu_entry'] | 1) - x.base_addr).to_bytes(4, 'little')
    v[arm_tls_hook:arm_tls_hook+4] = (arm_addr + arm_syms['emu_tls_hook'] | 1).to_bytes(4, 'little')
    castrate(x)
    with open(f2, 'wb') as file:
        file.write(x.to_bytes())

if __name__ == '__main__':
    import sys
    main(*sys.argv[1:])
