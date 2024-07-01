# 1FA

> ~~My old man~~ Our `admin` is a fishing Formula 1 fanatic... But he has recently been phished (and infected by an infostealer). Here is his password: `RobertR@c!ng#24` and the stolen file:
>
> [1fa.py](https://hack.cert.pl/files/1fa-88f3f1d5e2ef6aa2ccce3faf847b304d5956a682.py)
>
> [https://1fa.ecsc24.hack.cert.pl/](https://1fa.ecsc24.hack.cert.pl/)

## Vulnerability
Take a look at the `/mfa` route:

```py
@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if current_user.is_authenticated:
        return redirect(url_for('root'))

    if request.method == 'GET':
        mfa_login = session.get('mfa_login', None)
        if mfa_login is None:
            return redirect(url_for('login'))

        session['mfa_user'] = User.query.filter_by(login=mfa_login).first()
        if session['mfa_user'] is None:
            return redirect(url_for('login'))

        return render_template('mfa.html')

    mfa_user = session.get('mfa_user', None)
    totp = pyotp.TOTP(mfa_user.mfa_secret)
    if totp.verify(request.form.get('mfa_code')):
        login_user(session.get('user', None))
        return redirect(url_for('root'))

    return render_template('mfa.html', message='MFA verification failed!', type='warning')
```

`mfa_user` in the session is only set if the route is accessed with a GET request. That means that if you log in as user , log out, log in as user2 and then perform a POST request to `/mfa` (without first making a GET request to that route), you will be able to authorize user2 using user1's OTP.

## Solution
1. Register
2. Set up MFA for your user
2. Log out
3. Log back in as your user (to set `mfa_user` in your session)
4. (optional) pass the MFA check for your user
5. Log out again
6. Log in as admin with the provided credentials (using curl, not a browser, because you want to avoid making a GET request to `/mfa` when `/login` returns a redirect)
7. Make a post request to `/mfa` with your user's OTP
8. Profit

## Flag
`ecsc24{sl0w_4nd_5t3ady_w1ns_th3_r4ce}`
 