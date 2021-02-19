class VirtualMemory:
    def __init__(self, sections, align):
        self.sections = sections
        self.align = align
        self.maxvma = 0
        for name, va, memsz, flags, data in self.sections:
            self.maxvma = max(self.maxvma, va+memsz)
    def _section_at(self, va):
        l = -1
        r = len(self.sections)
        while r - l > 1:
            m = (l+r)//2
            if self.sections[m][1] > va:
                r = m
            else:
                l = m
        return l
    def __getitem__(self, idx):
        if isinstance(idx, slice):
            return bytes(map(self.__getitem__, range(idx.start, idx.stop, idx.step if idx.step != None else 1)))
        s = self._section_at(idx)
        if s < 0 or idx >= self.sections[s][1]+self.sections[s][2]:
            raise IndexError("unmapped VM read at 0x%x"%idx)
        return self.sections[s][4][idx-self.sections[s][1]]
    def __setitem__(self, idx, data):
        if isinstance(idx, slice):
            r = range(idx.start, idx.stop, idx.step if idx.step != None else 1)
            if len(r) != len(data):
                raise ValueError("lvalue and rvalue have different structures")
            for i, x in zip(r, data):
                self[i] = x
            return
        s = self._section_at(idx)
        if s < 0 or idx >= self.sections[s][1]+self.sections[s][2]:
            raise IndexError("unmapped VM write at 0x%x"%idx)
        self.sections[s][4][idx-self.sections[s][1]] = data
    def alloc(self, size, flags, sect_name=''):
        va = self.maxvma
        va += (-va) % self.align
        data = bytearray(size)
        self.sections.append((sect_name, va, size, flags, data))
        self.maxvma = va + size
        return (va, data)
    def sim_alloc(self):
        return self.maxvma + (-self.maxvma) % self.align
