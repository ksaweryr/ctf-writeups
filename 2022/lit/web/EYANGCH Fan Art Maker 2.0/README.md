# EYANGCH Fan Art Maker 2.0
> Unfortunately the last Fan Art maker had an unintended extremely easy solution. Frankly I am disappointed by people's willingness to take the easy route when it comes to ORZing Eyang. To make up for it, here is more [EYANG OTZ OTZ OTZ](http://litctf.live:45392/)
>
> Downloads
> [EyangchFanArt2.zip](https://drive.google.com/uc?export=download&id=1Uc8QfAj9HnOZ9y4IdZpZrshZN4CQp6Qc)

## Unintended solution (yet again)
This time the `flag` component is password-protected and we can't simply use it. We can however overwrite `EYANGOTZ` component to make it empty and therefore reveal the covered flag:
```xml
<component name="EYANGOTZ"></component>
```

## Flag
`LITCTF{3y4ngCH_15_l1k3_ju5t_s0_g3n10sit4}`
