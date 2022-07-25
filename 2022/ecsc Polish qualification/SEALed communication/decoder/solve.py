for _ in range(2):
    polynomial = input().replace('^', '**').replace('1x', 'x')
    exec(f'x = 2; print(({polynomial}) / 1000000.0)')