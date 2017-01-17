# linux-utils
Some linux utils I've coded and decided to share.

## Toys included
This repo is to-be populated.
At the moment there is:

- `lindump` - simple process memory dumping utility based on ptrace

```
:: lindump v0.1
Simple Linux process memory dumping utility based on ptrace
Mariusz B., '16

Usage: lindump [options] <pid> [start [stop|Llen]]

Arguments:
	<pid>	Process ID
	start	Dumping start address, may be 0x for hex, or not for dec.
	stop	Upper address to reach while dumping.
		When preceded with letter 'L' stands for length
	Llen	Specifies number of bytes to dump. Also may be preceded with 0x (e.g. L0x10)

Options:
	-o	Memory dumps output directory (stdout hexdump otherwise, '-' for stdout)
	-f	Force dumping of unreadable or inaccessible regions (still not a brute force)
	-v	Verbose output.
	-h	This cruft
```

- `dlresolve` - dynamic symbol resolve utility useful while in need of obtainin symbol's address and it's offset relative to the libc's base (handy while crafting ASLR exploits)

```
./dlresolve system
[+] libc comes from:		/lib/x86_64-linux-gnu/libc-2.19.so
[+] libc loaded at:		0x7f44e2b24000
[+] system located at:		0x7f44e2b65490
[+] Offset from libc base:	0x00041490
```
