class PeFile:
    def __init__(self, data):
        assert data[:2] == b'MZ'
        pe_offset = int.from_bytes(data[60:64], 'little')
        assert data[pe_offset:pe_offset+2] == b'PE'
        self.dos_stub = bytearray(data[:pe_offset])
        self.pe_header = bytearray(data[pe_offset:pe_offset+120])
        noffsets = int.from_bytes(self.pe_header[116:120], 'little')
        nsections = int.from_bytes(self.pe_header[6:8], 'little')
        self.base_addr = base_addr = int.from_bytes(self.pe_header[52:56], 'little')
        self.mem_align = int.from_bytes(self.pe_header[56:60], 'little')
        self.offset_table = []
        for i in range(noffsets):
            t = data[pe_offset+120+i*8:pe_offset+128+i*8]
            rva = int.from_bytes(t[:4], 'little')
            l = int.from_bytes(t[4:], 'little')
            if l == 0:
                self.offset_table.append(None)
            elif i == 4:
                self.offset_table.append(data[rva:rva+l])
            else:
                self.offset_table.append((rva + base_addr, l))
        self.sections = []
        for i in range(nsections):
            t = data[pe_offset+120+noffsets*8+i*40:pe_offset+160+noffsets*8+i*40]
            name = t[:8].decode('latin-1')
            while name[-1:] == '\0': name = name[:-1]
            memsz = int.from_bytes(t[8:12], 'little')
            rva = int.from_bytes(t[12:16], 'little')
            filesz = int.from_bytes(t[16:20], 'little')
            offset = int.from_bytes(t[20:24], 'little')
            flags = int.from_bytes(t[36:40], 'little')
            self.sections.append((name, base_addr+rva, memsz, flags, bytearray(data[offset:offset+filesz])))
    @classmethod
    def from_bytes(self, data):
        return self(data)
    def to_bytes(self):
        self.dos_stub[60:64] = len(self.dos_stub).to_bytes(4, 'little')
        ans = bytearray(self.dos_stub)
        self.base_addr = base_addr = int.from_bytes(self.pe_header[52:56], 'little')
        self.mem_align = int.from_bytes(self.pe_header[56:60], 'little')
        file_align = int.from_bytes(self.pe_header[60:64], 'little')
        self.pe_header[88:92] = bytes(4) # checksum
        self.pe_header[6:8] = len(self.sections).to_bytes(2, 'little')
        self.pe_header[116:120] = len(self.offset_table).to_bytes(4, 'little')
        self.pe_header[80:84] = (max(i[1] + i[2] for i in self.sections) - base_addr).to_bytes(4, 'little')
        ans += self.pe_header
        o_o = []
        for i in self.offset_table:
            if i == None:
                ans += bytes(8)
            elif isinstance(i, bytes):
                o_o.append(len(ans))
                ans += bytes(4) + len(i).to_bytes(4, 'little')
            else:
                va, l = i
                ans += (va - base_addr).to_bytes(4, 'little') + l.to_bytes(4, 'little')
        sz = len(ans) + 40 * len(self.sections)
        for name, va, memsz, flags, data in self.sections:
            rva = va - base_addr
            filesz = len(data)
            sz += (-sz) % file_align
            sz += (-sz) % 4096
            offset = sz
            sz += filesz + (-filesz) % 4096
            ans += name.encode('latin-1') + bytes(8 - len(name))
            ans += memsz.to_bytes(4, 'little')
            ans += rva.to_bytes(4, 'little')
            ans += filesz.to_bytes(4, 'little')
            ans += offset.to_bytes(4, 'little')
            ans += bytes(12)
            ans += flags.to_bytes(4, 'little')
        for name, va, memsz, flags, data in self.sections:
            ans += bytes((-len(ans)) % file_align)
            ans += bytes((-len(ans)) % 4096)
            ans += data
            ans += bytes((-len(ans)) % 4096)
        o_o = iter(o_o)
        for i in self.offset_table:
            if isinstance(i, bytes):
                o = next(o_o)
                ans += bytes((-len(ans)) % 16)
                ans[o:o+4] = len(ans).to_bytes(4, 'little')
                ans += i
        return bytes(ans)
