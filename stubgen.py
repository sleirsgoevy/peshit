import subprocess, pycparser.c_generator, recompiler, json

headers = '''\
#define _WIN32_WINNT 1000000000
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <synchapi.h>
#include <commctrl.h>

//abi-only declarations
int __getmainargs(int * _Argc, char *** _Argv, char *** _Env, int _DoWildCard, void * _StartInfo);
int __lconv_init(void);
char* __p__acmdln(void);
void __set_app_type(int);
void _initterm(void(**)(void), void(**)(void));
'''

custom_wrappers = {
    'atexit': '''\
void wrapper_atexit(struct { void* callback; int ret; }* opaque)
{
    void* arm_code = emu_malloc(0x10);
    unsigned short* thumb = arm_code;
    thumb[0] = 0x4901;
    thumb[1] = 0x4802;
    thumb[2] = 0x4708;
    thumb[3] = 0;
    unsigned int* consts = arm_code;
    consts[2] = 1 | (unsigned int)&emu_do_callback;
    consts[3] = (unsigned int)opaque->callback;
    emu_cacheflush(arm_code, 16);
    opaque->ret = ((int(*)(unsigned int))WINAPI::[atexit])(1|(unsigned int)arm_code);
}
''',
    '_onexit': '''\
void wrapper__onexit(struct { void* callback; void* ret; }* opaque)
{
    void* arm_code = emu_malloc(0x10);
    unsigned short* thumb = arm_code;
    thumb[0] = 0x4901;
    thumb[1] = 0x4802;
    thumb[2] = 0x4708;
    thumb[3] = 0;
    unsigned int* consts = arm_code;
    consts[2] = 1 | (unsigned int)&emu_do_callback;
    consts[3] = (unsigned int)opaque->callback;
    emu_cacheflush(arm_code, 16);
    opaque->ret = (((void*(*)(unsigned int))WINAPI::[_onexit])(1|(unsigned int)arm_code)) ? opaque->callback : (void*)0;
}
''',
    '_initterm': ('''\
void _initterm(void(** start)(void), void(** end)(void))
{
    while(start < end)
    { 
        if(*start)
            (**start)();
        start++;
    }
}
''', ''),
    'printf': ('''\
asm(".global _printf\\n_printf:\\npush %eax\\nmov %esp, %eax\\nsyscall\\npop %eax\\nret");
''', '''\
#define DO_PRINTF(SINGLE, DOUBLE, LF) do {\\
    int nll = -1;\\
    for(unsigned int i = 0; fmts[i]; i++)\\
    {\\
        if(nll < 0)\\
        {\\
            if(fmts[i] == '%')\\
                nll = 0;\\
            continue;\\
        }\\
        switch(fmts[i])\\
        {\\
        case 'l':\\
            nll++;\\
            break;\\
        case 'j':\\
        case 'L':\\
            nll = 2;\\
            break;\\
        case 'd':\\
        case 'i':\\
        case 'u':\\
        case 'o':\\
        case 'x':\\
        case 'X':\\
        case 'c':\\
            {\\
                if(nll == 2)\\
                    DOUBLE;\\
                else\\
                    SINGLE;\\
                nll = -1;\\
                break;\\
            }\\
        case 's':\\
        case 'S':\\
        case 'p':\\
        case 'n':\\
            nll = -1;\\
        case '*':\\
            SINGLE;\\
            break;\\
        case 'f':\\
        case 'F':\\
        case 'e':\\
        case 'E':\\
        case 'g':\\
        case 'G':\\
        case 'a':\\
        case 'A':\\
            DOUBLE;\\
            nll = -1;\\
            break;\\
        case '%':\\
            nll = -1;\\
            break;\\
        }\\
    }\\
} while(0)

void wrapper_printf(unsigned int* stack)
{
    char* fmts = (void*)stack[2];
    unsigned int nwords = 1;
    DO_PRINTF(nwords++, nwords += nwords % 2 + 2, );
    unsigned int* src = stack + 2;
    unsigned int tgt[nwords];
    tgt[0] = (unsigned int)fmts;
    unsigned int src_idx = 1, tgt_idx = 1;
    DO_PRINTF(tgt[tgt_idx++] = src[src_idx++], (tgt_idx += tgt_idx % 2, tgt[tgt_idx++] = src[src_idx++], tgt[tgt_idx++] = src[src_idx++]), src_idx++);
    stack[0] = (unsigned int)emu_call_native(tgt, nwords*4, WINAPI::[printf]);
}

#undef DO_PRINTF
'''),
'CreateThread': '''\
DWORD thread_callback(void* param)
{
    void** x = param;
    void* x86_function = x[0];
    void* x86_param = x[1];
    ((typeof(&SetEvent))WINAPI::[SetEvent])((HANDLE)x[2]);
    return emu_do_callback(x86_function, 0, x86_param);
}

void wrapper_CreateThread(struct
{
    LPSECURITY_ATTRIBUTES lpThreadAttributes;
    SIZE_T dwStackSize;
    LPTHREAD_START_ROUTINE lpStartAddress;
    LPVOID lpParameter;
    DWORD dwCreationFlags;
    LPDWORD lpThreadId;
    HANDLE ans;
}* param)
{
    HANDLE evt = ((typeof(&CreateEventA))WINAPI::[CreateEventA])(NULL, FALSE, FALSE, "thread creation");
    if(!evt)
    {
        param->ans = evt;
        return;
    }
    void* x[3] = {param->lpStartAddress, param->lpParameter, (void*)evt};
    HANDLE thr = ((typeof(&CreateThread))WINAPI::[CreateThread])(param->lpThreadAttributes, param->dwStackSize, thread_callback, x, param->dwCreationFlags, param->lpThreadId);
    ((typeof(&WaitForSingleObject))WINAPI::[WaitForSingleObject])(evt, INFINITE);
    ((typeof(&CloseHandle))WINAPI::[CloseHandle])(evt);
    param->ans = thr;
}
''',
'GetProcAddress': ('''\
struct emu_dlsymtab_entry
{
    char* name;
    void* func;
};

extern struct emu_dlsymtab_entry emu_dlsymtab_start[], emu_dlsymtab_end[];

struct opaque
{
    struct emu_dlsymtab_entry* begin;
    struct emu_dlsymtab_entry* end;
    HMODULE hModule;
    LPCSTR lpProcName;
    FARPROC ans;
};

__attribute__((stdcall)) FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    struct opaque opaq;
    opaq.begin = emu_dlsymtab_start;
    opaq.end = emu_dlsymtab_end;
    opaq.hModule = hModule;
    opaq.lpProcName = lpProcName;
    asm volatile("syscall"::"a"(&opaq):"memory");
    return opaq.ans;
}''', '''\
struct emu_dlsymtab_entry
{
    char* name;
    void* func;
};

struct opaque
{
    struct emu_dlsymtab_entry* begin;
    struct emu_dlsymtab_entry* end;
    HMODULE hModule;
    LPCSTR lpProcName;
    FARPROC ans;
};

void wrapper_GetProcAddress(struct opaque* opaq)
{
    HANDLE hModule = opaq->hModule;
    LPCSTR lpProcName = opaq->lpProcName;
    struct emu_dlsymtab_entry* left = opaq->begin;
    struct emu_dlsymtab_entry* right = opaq->end;
    int idx = 0;
    do
    {
        struct emu_dlsymtab_entry* sep = right;
        while(sep - left > 1)
        {
            struct emu_dlsymtab_entry* mid = left + (sep - left) / 2;
            if(mid->name[idx] >= lpProcName[idx])
                sep = mid;
            else
                left = mid;
        }
        if(left->name[idx] >= lpProcName[idx])
            sep = left;
        if(sep == right || sep->name[idx] != lpProcName[idx])
            goto return0;
        left = sep;
        while(right - sep > 1)
        {
            struct emu_dlsymtab_entry* mid = sep + (right - sep) / 2;
            if(mid->name[idx] > lpProcName[idx])
                right = mid;
            else
                sep = mid;
        }
        if(left == right || left->name[idx] != lpProcName[idx])
            goto return0;
    }
    while(lpProcName[idx++]);
    opaq->ans = left->func;
    return;
return0:
    dbg_puts("GetProcAddress: could not resolve ");
    dbg_puts(opaq->lpProcName);
    dbg_puts("\\n");
    opaq->ans = 0;
    return;
}
''')
}

wrapper_deps = {'CreateThread': [('kernel32.dll', 'CreateEventA'), ('kernel32.dll', 'SetEvent'), ('kernel32.dll', 'WaitForSingleObject'), ('kernel32.dll', 'CloseHandle')]}

def get_headers(arch):
    p = subprocess.Popen((arch+'-w64-mingw32-gcc', '-E', '-P', '-'), stdin=subprocess.PIPE, stdout=subprocess.PIPE, encoding='utf-8')
    out = p.communicate(headers)[0]
    assert not p.wait()
    return out

def preprocess_headers(arch):
    out = get_headers(arch)
    out = out.split('__attribute__((__stdcall__))')
    out = ''.join(i.rstrip()[:-1]+' volatile volatile const (' if i.rstrip()[-1:] == '(' else (i+' volatile volatile const' if not i[:-1].isalnum() and i[:-1] != '_' else '__attribute__((__stdcall__))') for i in out[:-1])+out[-1]
    stage2 = '''\
#define __builtin_va_list va_list
typedef int va_list;
#define __attribute__(...)
#define __inline
#define __inline__
#define __volatile__
#define __extension__
#define extern
#define __restrict__ restrict
'''+out
    p = subprocess.Popen((arch+'-w64-mingw32-gcc', '-E', '-P', '-'), stdin=subprocess.PIPE, stdout=subprocess.PIPE, encoding='utf-8')
    out = p.communicate(stage2)[0]
    assert not p.wait()
    stage3 = '''\
#define __asm__(...)
'''+out
    p = subprocess.Popen((arch+'-w64-mingw32-gcc', '-E', '-P', '-'), stdin=subprocess.PIPE, stdout=subprocess.PIPE, encoding='utf-8')
    out = p.communicate(stage3)[0]
    assert not p.wait()
    return '\n'.join(i for i in out.split('\n') if not i.startswith('#pragma '))

def parse_headers(arch):
    headers = preprocess_headers(arch)
    return pycparser.CParser().parse(headers)

def extract_decls(arch):
    headers = parse_headers(arch)
    return {i.name: i for i in headers.ext if isinstance(i, pycparser.c_ast.Decl) and isinstance(i.type, pycparser.c_ast.FuncDecl)}

def process(cgen, fn, upstream):
    if fn.name in custom_wrappers and isinstance(custom_wrappers[fn.name], tuple):
        return custom_wrappers[fn.name]
    try:
        if any(isinstance(j, pycparser.c_ast.EllipsisParam) for j in fn.type.args.params):
            print('Warning: '+fn.name+': varargs not supported')
            return (cgen.visit(fn).strip()+'{ *(void* volatile*)0; }\n', '')
        mx = '__' + max(['arg']+[i.name for i in fn.type.args.params if i.name != None], key=len)
        for i, j in enumerate(fn.type.args.params):
            if isinstance(j.type.type, pycparser.c_ast.IdentifierType) and j.type.type.names == ['void']:
                continue
            if j.name == None:
                j.name = j.type.declname = mx+str(i+1)
            if isinstance(j.type, pycparser.c_ast.ArrayDecl):
                j.type = pycparser.c_ast.PtrDecl(type=j.type.type, quals=[])
    except:
        raise Exception("error while processing "+fn.name)
    args = [i.name for i in fn.type.args.params if i.name != None]
    is_void_fn = isinstance(fn.type.type.type, pycparser.c_ast.IdentifierType) and fn.type.type.type.names == ['void']
    if fn.quals[-3:] == ['volatile', 'volatile', 'const']:
        fn.quals[-3:] = ('__attribute__((stdcall))',)
    if isinstance(fn.type.type, pycparser.c_ast.PtrDecl) and fn.type.type.quals[-3:] == ['volatile', 'volatile', 'const']:
        fn.type.type.quals[-3:] = ('__attribute__((stdcall))',)
    ans_name = mx+'0'
    opaque = mx+'o'
    decl = cgen.visit(fn).strip()
    decl_type = fn.type.type
    while not isinstance(decl_type, pycparser.c_ast.TypeDecl):
        decl_type = decl_type.type
    decl_type.declname = ans_name
    outer = decl+'\n'
    outer += '{\n    struct\n    {\n'
    for i in args:
        outer += '        typeof(%s) %s;\n'%(i, i)
    if not is_void_fn:
        outer += '        typeof(%s) %s;\n'%(fn.name+'('+', '.join(args)+')', ans_name)
    outer += '    } '+opaque+' = {\n'
    for i in args:
        outer += '        '+i+',\n'
    outer += '    };\n'
    outer += '    asm volatile("syscall"::"a"(&'+opaque+'):"memory");\n'
    if not is_void_fn:
        outer += '    return '+opaque+'.'+ans_name+';\n'
    outer += '}\n'
    inner = 'void wrapper_'+fn.name+'(struct\n{\n'
    for i in fn.type.args.params:
        if i.name != None:
            inner += '    '+cgen.visit(i)+';\n'
    if not is_void_fn:
        inner += '    '+cgen.visit(pycparser.c_ast.Decl(name=ans_name, type=fn.type.type, quals=[], storage=[], funcspec=[], init=None, bitsize=None))+';\n'
    inner += '}* '+opaque+')\n{\n'
    if recompiler.TRACE:
        inner += '    dbg_puts("calling %s\\n");\n'%fn.name
    inner += '    '
    if not is_void_fn:
        inner += opaque+'->'+ans_name+' = '
    inner += '((typeof(&'+fn.name+'))('+upstream+'))('+', '.join(opaque+'->'+i for i in args)+');\n'
    inner += '}\n'
    decl_type.declname = fn.name
    if fn.name in custom_wrappers: inner = custom_wrappers[fn.name]
    return (outer, inner)

external_non_funcs = {'__initenv'}

def gen_decls(arch, fns):
    decls = extract_decls(arch)
    cgen = pycparser.c_generator.CGenerator()
    x86_code = get_headers(arch)
    arm_code = headers
    wrapper_names = []
    for i, j in fns.items():
        if i == '__initenv': continue
        if i in decls:
            x, y = process(cgen, decls[i], j)
        else:
            print('Warning:', i, 'is a stub')
            x = 'void '+i+'(void)\n{\n    asm volatile("syscall");\n}\n'
            y = 'void wrapper_'+i+'(void)\n{\n    emu_unsupported_c("'+i+' is a stub!\\n");\n}\n'
        x86_code += x
        arm_code += y
        if y != '':
            wrapper_names.append(i)
    return (x86_code, arm_code, wrapper_names)

def gen_dlsymtab(symbols):
    names = sorted([j[1] for j in symbols])
    ans = '.align 4\n'
    ans += '_emu_dlsymtab_start:\n'
    for i in names:
        ans += '.long .L_'+i+'\n'
        ans += '.long _'+i+'\n'
    ans += '_emu_dlsymtab_end:\n'
    for i in names:
        ans += '.L_'+i+':\n'
        ans += '.asciz "'+i+'"\n'
    return 'asm(' + json.dumps(ans) + ');'
