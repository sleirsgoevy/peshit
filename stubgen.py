import subprocess, pycparser.c_generator

headers = '''\
#include <windows.h>
#include <stdio.h>

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
}''', '')
}

def get_headers(arch):
    p = subprocess.Popen((arch+'-w64-mingw32-gcc', '-E', '-P', '-'), stdin=subprocess.PIPE, stdout=subprocess.PIPE, encoding='utf-8')
    out = p.communicate(headers)[0]
    assert not p.wait()
    return out

def preprocess_headers(arch):
    out = get_headers(arch)
    out = out.split('__attribute__((__stdcall__))')
    out = ''.join(i[:-1]+' volatile volatile const (' if i[-1:] == '(' else (i+' volatile volatile const' if not i[:-1].isalnum() and i[:-1] != '_' else '__attribute__((__stdcall__))') for i in out[:-1])+out[-1]
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
    outer += '    asm volatile("syscall"::"a"(&'+opaque+'));\n'
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
            x86_code += x
            arm_code += y
            if y != '':
                wrapper_names.append(i)
        else:
            print('Warning:', i, 'is a stub')
            x86_code += 'void '+i+'(void){ *(void* volatile*)0; }\n'
    return (x86_code, arm_code, wrapper_names)
