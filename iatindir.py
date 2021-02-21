import pefile, vmem, sys, collections

class CaseInsensitive(str):
    def __hash__(self): return hash(self.lower())
    def __eq__(self, other): return self.lower() == other.lower()

def read_string(x, v, addr):
    ans = []
    while True:
        c = v[addr]
        if not c: break
        ans.append(c)
        addr += 1
    return bytes(ans).decode('latin-1')

def parse_iat(x, v):
    it = x.offset_table[1][0]
    ans = collections.OrderedDict()
    while any(v[it:it+4]):
        p_lookup = x.base_addr + int.from_bytes(v[it:it+4], 'little')
        dllname = read_string(x, v, x.base_addr + int.from_bytes(v[it+12:it+16], 'little'))
        p_iat = x.base_addr + int.from_bytes(v[it+16:it+20], 'little')
        symbols = collections.OrderedDict()
        while any(v[p_lookup:p_lookup+4]):
            symbol_descr = x.base_addr + int.from_bytes(v[p_lookup:p_lookup+4], 'little')
            symbol_hint = int.from_bytes(v[symbol_descr:symbol_descr+2], 'little')
            symbol_name = read_string(x, v, symbol_descr + 2)
            symbols[symbol_name] = (symbol_hint, p_iat)
            p_lookup += 4
            p_iat += 4
        ans[CaseInsensitive(dllname)] = symbols
        it += 20
    return ans

def build_iat(x, v, iat):
    strings = [b'']
    string_idxs = {}
    def make_string(s):
        string_idxs[s] = len(strings[0])
        strings[0] += (s + '\0').encode('latin-1')
    dlls_size = 20
    symt_size = 0
    iat_size = 0
    for dllname, dll in iat.items():
        dlls_size += 20
        symt_size += 4
        make_string(dllname)
        for name, (hint, old_iat) in dll.items():
            if len(strings[0]) % 2: strings[0] += b'\0'
            make_string(hint.to_bytes(2, 'little').decode('latin-1') + name)
            symt_size += 4
            iat_size += 4
    strings = strings[0]
    strings += bytes((-len(strings)) % 4)
    addr, arr = v.alloc(dlls_size + symt_size + iat_size + len(strings), 0xc0000000, '.iat2')
    addr -= x.base_addr
    dlls_offset = 0
    symt_offset = dlls_offset + dlls_size
    iat_offset = symt_offset + symt_size
    strings_offset = addr + iat_offset + iat_size
    symbols = []
    for dllname, dll in iat.items():
        arr[dlls_offset:dlls_offset+4] = (addr + symt_offset).to_bytes(4, 'little')
        arr[dlls_offset+12:dlls_offset+16] = (strings_offset + string_idxs[dllname]).to_bytes(4, 'little')
        arr[dlls_offset+16:dlls_offset+20] = (addr + iat_offset).to_bytes(4, 'little')
        dlls_offset += 20
        for name, (hint, old_iat) in dll.items():
            symbols.append((old_iat, x.base_addr + addr + iat_offset, dllname, name))
            arr[symt_offset:symt_offset+4] = (strings_offset + string_idxs[hint.to_bytes(2, 'little').decode('latin-1')+name]).to_bytes(4, 'little')
            symt_offset += 4
            iat_offset += 4
        symt_offset += 4
    arr[strings_offset-addr:strings_offset-addr+len(strings)] = strings
    x.offset_table[1] = (addr + x.base_addr, len(strings) + strings_offset)
    return symbols

def iatindir(x, v, add_symbols=[], deps={}):
    iat = parse_iat(x, v)
    for dllname, name in add_symbols:
        dllname = CaseInsensitive(dllname)
        if dllname not in iat: iat[dllname] = collections.OrderedDict()
        if name not in iat[dllname]: iat[dllname][name] = (0, None)
    syms = [j for i in iat.values() for j in i]
    syms_s = set(syms)
    for i in syms:
        if i not in deps: continue
        for dllname, name in deps[i]:
            dllname = CaseInsensitive(dllname)
            if dllname not in iat: iat[dllname] = collections.OrderedDict()
            if name not in iat[dllname]: iat[dllname][name] = (0, None)
            if name not in syms_s:
                syms_s.add(name)
                syms.append(name)
    return build_iat(x, v, iat)

def main():
    with open(sys.argv[1], 'rb') as file: x = pefile.PeFile(file.read())
    v = vmem.VirtualMemory(x.sections, x.mem_align)
    symbols = iatindir(x, v)
    glue_len = 12 * len(symbols) + 5
    addr, arr = v.alloc(glue_len, 0x60000000, '.glue')
    glue = b''
    for i, j, k, l in symbols:
        glue += b'\xff\x35'+j.to_bytes(4, 'little')
        glue += b'\x8f\x05'+i.to_bytes(4, 'little')
    glue += b'\xe9'
    entry = int.from_bytes(x.pe_header[40:44], 'little') + x.base_addr
    glue += (entry - (addr + glue_len)).to_bytes(4, 'little', signed=True)
    assert len(glue) == glue_len
    arr[:glue_len] = glue
    x.pe_header[40:44] = (addr - x.base_addr).to_bytes(4, 'little')
    x.pe_header[22] |= 1
    with open(sys.argv[2], 'wb') as file: file.write(x.to_bytes())

if __name__ == '__main__':
    main()
