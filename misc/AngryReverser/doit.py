import angr

proj = angr.Project('./yolomolo')

init_state = proj.factory.entry_state()
path_group = proj.factory.path_group(init_state)

avoids = [
    0x605F78,
    0x4004E0,
    '_exit',
    '_puts'
]

finds = [
    0x405AD8
]


def step_func(pg):
    print
    for p in pg.active:
        # print p.__dict__
        print hex(p.addr)
    pg.drop(filter_func = lambda p: p.addr in avoids)
    pg.stash(
        filter_func = lambda p: p.addr in finds,
        from_stash='active',
        to_stash='found')
    return pg

"""
path_group.explore(
    find=0x405A6D,
    avoid=0x605F78
)
"""

path_group.step(
    step_func = step_func,
    until = lambda pg: len(pg.found) > 0)

print path_group.found[0].state.posix.dumps(0)
