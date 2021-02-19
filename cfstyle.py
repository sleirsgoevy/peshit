def propagate_cf_uses(cfg, cf_uses):
    cf_uses_0 = set(cf_uses)
    q = list(cf_uses)
    cf_uses = set()
    q2 = []
    while q:
        while q:
            i = q.pop()
            if i in cf_uses: continue
            cf_uses.add(i)
            if i not in cfg: continue
            q2.extend(cfg[i])
        q, q2 = q2, q
    assert cf_uses_0.issubset(cf_uses)
    return cf_uses

def calculate_cf_style(cfg, cf_uses, cf_styles):
    cf_uses = propagate_cf_uses(cfg, cf_uses)
    return {i: j if i in cf_uses else 'none' for i, j in cf_styles.items()}
