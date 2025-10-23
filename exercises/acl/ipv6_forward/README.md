We make changes to the github code [pullself/ipv6_forward_p4](https://github.com/pullself/ipv6_forward_p4) and let it fit for the P4 tutorial images on Ubuntu 20.04 so that it can run on BMv2 target **simple_switch_grpc**.

The file folder **utils** is copied from the tutorials/utils.**We modify the file Makefile to change the path of it. And we also modify the utils/p4runtime_lib/convert.py file to add the function to convert IPv6 address from the rules.**

1.In your shell, run:
```
$ make
```

This will:
*compile ipv6_forward.p4, and
*start a Mininet instance with three switches 's1' configured in a triangle, each connected to one host 'h1', 'h2'.

2.You should now see a Mininet command prompt. Open two terminals for 'h1' and 'h2', respectively:

```
mininet> xterm h1 h2
```

3.Each host includes a small Python-based messaging client and server. **In h2's xterm**, start the server:
```
$ python3 receive.py
```

4.**In 'h1''s xterm**, send a message from the client:
```
$ python3 send.py fe80::1234 fe80::5678 "Hello P4!"
```
The message will be received in h2's windows.

5.Type 'exit' to leave each xterm and the Mininet command line.
```
mininet>exit
$ make clean
```

