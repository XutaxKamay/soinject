## Introduction
I knew there was a lot of methods of injections around the web but they seemed more complicated than it needed to be or crashed, so I did mine.
The first method to load your custom shared library is to use LD_PRELOAD. (there is a plenty of tutorials online)
Second method is actually making your own debugger to call dlopen with your dynamic library path.
There might be other methods, but this one worked just fine as a small tool.

Sadly it needs to have two seperate programs for 32 & 64 bits due on how ptrace works.. (Getting registers, writing memory and so on)

## Requirements
- make
- gcc

## How to build
Type ```make``` inside the root directory of the repository. (soinject)

## How to run
Let's imagine you want to inject a library inside a game.
If 32 bits:

`sudo ./inject32.dbg $(pgrep your_game_name) ~/hacks/game_hax.so`

If 64 bits:

`sudo ./inject64.dbg $(pgrep your_game_name) ~/hacks/game_hax.so`

You should see something like the above:
```
Found dlopen address 0xf7c64260 on pid 26391
Attached to 26391
Got regs (ip: 0x566422da) on pid 26391
Reserving some memory on stack for filename on pid 26391
Writing data 0xfff170d0 + 28 -> 0x006F732E
Writing data 0xfff170d0 + 24 -> 0x32336C61
Writing data 0xfff170d0 + 20 -> 0x6D696E69
Writing data 0xfff170d0 + 16 -> 0x6D2F6F73
Writing data 0xfff170d0 + 12 -> 0x2F2B2B63
Writing data 0xfff170d0 + 8 -> 0x2F79616D
Writing data 0xfff170d0 + 4 -> 0x616B2F65
Writing data 0xfff170d0 + 0 -> 0x6D6F682F
Wrote filename 0xfff170d0 on pid 26391
Writing data 0xfff170c8 + 4 -> 0x00000001
Writing data 0xfff170c8 + 0 -> 0xFFF170D0
Reading current on instructions on ip address on pid 26391
Reading data 0xff8c0510 + 4 -> 0x8BC9DE02
Reading data 0xff8c0510 + 0 -> 0xDD08558B
Writing instructions for dlopen call on pid 26391
Writing data 0x566422da + 4 -> 0x90909090
Writing data 0x566422da + 0 -> 0x90CCD0FF
Executing shellcode on pid 26391
    IP: 0x566422da
Waiting for pid 26391
Done on pid 26391 with signal Trace/breakpoint trap
    IP: 0x566422dd
Writing data 0x566422da + 4 -> 0x8BC9DE02
Writing data 0x566422da + 0 -> 0xDD08558B
Injected /home/kamay/c++/so/minimal32.so on pid 26391 at address 0x56ae2ba0
```

If you see injected then your dynamic library should be loaded.

Have fun~


## TODO
- Make another program to call dlclose in order to close shared libraries.
- Maybe making a GUI & in order to unload/load would be better
