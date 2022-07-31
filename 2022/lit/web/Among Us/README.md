# Among Us
> Hello! I am Polopopy, and my friends like to call me Ryan. I have an unhealthy ~fetich~obsession with Among Us, so I made [this website](http://litctf.live:31779/) to demonstrate my unyielding enthusiasm!

## Solution
After reading through the wall of text on the website all we know is that "yellow do be looking super sussy". However neither analysing the page's source nor the `sussy-yellow-amogus` file yields any results. The only other thing we can check is inspect the responses returned by server (e.g. using browser devtools). Upon looking at response headers returned by the server when the file `syssy-yellow-amogus` is requested, we can see a "sus" header:
```
sussyflag: LITCTF{mr_r4y_h4n_m4y_b3_su55y_bu7_4t_l3ast_h3s_OTZOTZOTZ}
```

## Flag
`LITCTF{mr_r4y_h4n_m4y_b3_su55y_bu7_4t_l3ast_h3s_OTZOTZOTZ}`
