# minimalist
> less is more
>
> Downloads
> [minimalist](https://drive.google.com/uc?export=download&id=1vMY6FRx_Eff2ypd9vaZCRr6HYNdPsneX)

## Solution
Yet again, I nicely asked angr to solve the challenge for me. Luckily, it agreed:
```py
import angr
import claripy

proj = angr.Project('./minimalist', load_options={'main_opts': {'base_addr':0x100000}})

flag_bytes = [claripy.BVS(f'flag_{i}', 8) for i in range(0x2f)]
flag = claripy.Concat(*flag_bytes)

st = proj.factory.full_init_state()

for b in flag_bytes:
	st.solver.add(b > ord(' '))
	st.solver.add(b <= ord('~'))

sm = proj.factory.simgr(st)

sm.explore(
	find  = 0x1012ee,
	avoid = 0x1012dd
)

print(sm.found[0].posix.dumps(0))
```

## Flag
`LITCTF{Wh0_n33ds_a11_th0sE_f4ncy_1nstructions?}`
