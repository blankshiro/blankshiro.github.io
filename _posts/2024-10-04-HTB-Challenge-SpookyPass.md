---
layout: post
title: HackTheBox Challenge SpookyPass (Rev)
date: 2024-10-04
tags: [HackTheBox, Challenge, Rev]
---

# Challenge Synopsis

All the coolest ghosts in town are going to a Haunted Houseparty - can you prove you deserve to get in? ([Source](https://app.hackthebox.com/challenges/SpookyPass))

# Enumeration

```bash
❯ file pass
pass: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3008217772cc2426c643d69b80a96c715490dd91, for GNU/Linux 4.4.0, not stripped

❯ ./pass
Welcome to the SPOOKIEST party of the year.
Before we let you in, you'll need to give us the password: password
You're not a real ghost; clear off!
```

# Exploitation

Lets use `strings` to find hidden data in the file.

```bash
❯ strings pass
/lib64/ld-linux-x86-64.so.2
fgets
stdin
puts
__stack_chk_fail
__libc_start_main
__cxa_finalize
strchr
printf
strcmp
libc.so.6
GLIBC_2.4
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u3UH
Welcome to the 
[1;3mSPOOKIEST
[0m party of the year.
Before we let you in, you'll need to give us the password: 
s3cr3t_p455_f0r_gh05t5_4nd_gh0ul5
Welcome inside!
You're not a real ghost; clear off!
;*3$"
GCC: (GNU) 14.2.1 20240805
GCC: (GNU) 14.2.1 20240910
main.c
_DYNAMIC
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_start_main@GLIBC_2.34
_ITM_deregisterTMCloneTable
puts@GLIBC_2.2.5
stdin@GLIBC_2.2.5
_edata
_fini
__stack_chk_fail@GLIBC_2.4
strchr@GLIBC_2.2.5
printf@GLIBC_2.2.5
parts
fgets@GLIBC_2.2.5
__data_start
strcmp@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
_end
__bss_start
main
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@GLIBC_2.2.5
_init
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got
.got.plt
.data
.bss
.comment
```

Notice the interesting output `s3cr3t_p455_f0r_gh05t5_4nd_gh0ul5`? This is most likely the password for the binary. 

```bash
❯ ./pass
Welcome to the SPOOKIEST party of the year.
Before we let you in, you'll need to give us the password: s3cr3t_p455_f0r_gh05t5_4nd_gh0ul5
Welcome inside!
HTB{un0bfu5c4t3d_5tr1ng5}
```

**Flag:** `HTB{un0bfu5c4t3d_5tr1ng5}`
