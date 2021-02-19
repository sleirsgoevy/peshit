import pefile, vmem

def gen_indir_tables(x, v):
    total_code_sz = 0
    for i in x.sections:
        if i[3] & 0x20000000:
            total_code_sz += i[2]
    table_sz = total_code_sz * 4
    table, table_buf = v.alloc(table_sz, 0x40000000, '.indirb')
    ans = []
    for i in x.sections:
        if i[3] & 0x20000000:
            start = i[1]
            end = i[1] + i[2]
            ans.append((start, end, table))
            table += 4*(end-start)
    return (ans, table_buf)
