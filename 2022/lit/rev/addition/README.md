# addition
> Enter the flag, and it will be checked with addition!
>
> Downloads
> [addition](https://drive.google.com/uc?export=download&id=1hRfIzZrNdkjxLpUtnc_8uwyd2jYpOvhV)

## Solution
Honestly, I didn't really bother to reverse engineer the binary, I've just checked in the main function that the length of the flag is 0x18 and rigged up this basic Python script using angr to get the flag. It does the job ¯\\\_(ツ)\_\/¯:
```py
import angr
import claripy

proj = angr.Project('./addition', load_options={'main_opts': {'base_addr':0x100000}})

flag_bytes = [claripy.BVS(f'flag_{i}', 8) for i in range(24)]
flag = claripy.Concat(*flag_bytes)

st = proj.factory.full_init_state()

for b in flag_bytes:
	st.solver.add(b > ord(' '))
	st.solver.add(b <= ord('~'))

sm = proj.factory.simgr(st)

sm.explore(
	find  = 0x1010e4,
	avoid = 0x1010d0
)

print(sm.found[0].posix.dumps(0))
```

## Flag
`LITCTF{add1ti0n_is_h4rd}`
