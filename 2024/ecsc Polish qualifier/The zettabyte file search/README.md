# The zettabyte file search

> I accidentally force formatted my existing ZFS pool by placing another ZFS pool on top of it. Can you help me recover some very important pictures?
>
> [zettabyte.raw](https://hack.cert.pl/storage/zettabyte-088dfef4fc0aa071bc88909247568f8b22728358.raw)
>
> [zettabyte.raw (mirror)](https://f003.backblazeb2.com/b2api/v1/b2_download_file_by_id?fileId=4_ze4bd220f173c5545990d011e_f230410e810c6f3d0_d20240626_m110748_c003_v0312026_t0008_u01719400068954)
>
> **Hint (29.06.24 16:00)**: Sometimes having a monkey brain is the way forward.
>
> **Hint (30.06.24 00:00)**: Monke brain like simple solution. Monke brain no understand ZFS. Monke brain no have time for solving hard problem. Monke brain want find "flag" image file on disk. Return to monke and solve chall.

## Solution
Monke want find "flag" image file on disk. Monke run `$ strings zettabyte-088dfef4fc0aa071bc88909247568f8b22728358.raw | grep flag | less`. Monke find `flag.webp`. Monke write Python script to recover webp files:
```python
import mmap

fname = 'zettabyte-088dfef4fc0aa071bc88909247568f8b22728358.raw'

with open(fname, 'rb+') as f:
    with mmap.mmap(f.fileno(), 0) as mm:
        idx = 0
        while True:
            idx = mm.find(bytes([0x52, 0x49, 0x46, 0x46]), idx + 1)
            if idx == -1:
                break
            mm.seek(idx)
            with open(f'outputs/{idx}.webp', 'wb') as f:
                f.write(mm.read(1024 * 1024 * 5))
```
Monke see cool raccoon pictures, e.g.:

![./media/3989942272.webp](./media/3989942272.webp)

![./media/4002111488.webp](./media/4002111488.webp)

![./media/9763164160.webp](./media/9763164160.webp)


Monke also find an image with the flag at offset 9752784896:

![./media/9752784896.webp](./media/9752784896.webp)

Monke happy.

## Flag
`ecsc24{1_h0p3_u_w111_23m3m832_70_41w4y5_m4k3_84ckup5}`
