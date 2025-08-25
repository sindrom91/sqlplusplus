# sqlplusplus - Better SQL\*Plus REPL for Windows

The goal was to add readline-like features to `sqlplus`. It supports basic features like history, navigation and basic completion.

Note that this is only a wrapper around `sqlplus`, so it is necessary to have original installed.

## Build

Tested with zig 0.15.1.

```
zig build
```

## Run

```
.\zig-out\bin\sqlplusplus.exe
```
