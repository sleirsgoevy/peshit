import pefile, subprocess, tempfile, json, os

CC_X86 = 'i686-w64-mingw32-'
CC_ARM = 'llvm-mingw-20201020-ucrt-ubuntu-18.04/bin/armv7-w64-mingw32-'
CC_ARM_HOST = 'arm-linux-gnueabihf-'

def nm(cc_prefix, file, text_vma):
    p = subprocess.Popen((cc_prefix+'nm', file), stdout=subprocess.PIPE, encoding='utf-8')
    ans = p.communicate(None)[0]
    assert not p.wait()
    return {i[2].split('@', 1)[0]: int(i[0], 16) - text_vma for i in map(str.split, ans.split('\n')) if len(i) == 3}

def elf_extract_text(data):
    assert data[:4] == b'\x7fELF'
    shoff = int.from_bytes(data[32:36], 'little')
    shnum = int.from_bytes(data[48:50], 'little')
    for i in range(shnum):
        off = shoff + 40 * i
        entry = data[off:off+40]
        flags = int.from_bytes(entry[8:12], 'little')
        addr = int.from_bytes(entry[12:16], 'little')
        offset = int.from_bytes(entry[16:20], 'little')
        size = int.from_bytes(entry[20:24], 'little')
        if flags == 6: # ax
            return (addr, data[offset:offset+size])
    return None

def compile_x86(c_code, asm_code):
    with tempfile.TemporaryDirectory() as file:
        p = subprocess.Popen((CC_X86+'gcc', '-x', 'c', '-', '-nostdlib', '-static', '-o', file+'/out.dll'), stdin=subprocess.PIPE, encoding='utf-8')
        p.communicate('asm('+json.dumps(asm_code).replace('\\u00', '\\x')+');\n'+c_code)
        assert not p.wait()
        with open(file+'/out.dll', 'rb') as f:
            pe = pefile.PeFile(f.read())
        text_section = next(i for i in pe.sections if i[0] == '.text')
        text_vma = text_section[1]
        text_memsz = text_section[2]
        text = text_section[4]
        return (text[:text_memsz], nm(CC_X86, file+'/out.dll', text_vma))

# mingw arm clang does not allow `.code 32`, so this hack
def clang_sucks(asm_code):
    ans = []
    ii = iter(asm_code.split('\n'))
    for i in ii:
        if i.split()[:1] == ['.def']:
            while next(ii).strip() != '.endef': pass
        elif i.strip() == '.section\t.rdata,"dr"': pass
        else:
            ans.append(i)
    return '\n'.join(ans)

def compile_arm(c_code, asm_code, link_addr):
    with tempfile.TemporaryDirectory() as file:
        p = subprocess.Popen((CC_ARM+'gcc', '-fno-addrsig', '-fno-asynchronous-unwind-tables', '-x', 'c', '-', '-S', '-o', '-'), stdin=subprocess.PIPE, stdout=subprocess.PIPE, encoding='utf-8')
        asm_code = clang_sucks(p.communicate(c_code)[0] + asm_code + '\n.global _start\n_start:\n')
        assert not p.wait()
        p = subprocess.Popen((CC_ARM_HOST+'gcc', '-march=armv8-a', '-mfpu=neon', '-x', 'assembler', '-', '-nostdlib', '-static', '-Ttext='+hex(link_addr), '-o', file+'/out.elf'), stdin=subprocess.PIPE, stdout=subprocess.PIPE, encoding='utf-8')
        p.communicate(asm_code)
        assert not p.wait()
        with open(file+'/out.elf', 'rb') as f:
            text_vma, text = elf_extract_text(f.read())
        return (text, nm(CC_ARM_HOST, file+'/out.elf', text_vma))
