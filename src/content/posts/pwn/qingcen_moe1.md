---
title: 1 find it
published: 2026-06-01
image: ""
tags: [fd]
category: pwn
draft: false
series: 青岑moectf2025
---

# 题目描述

这题主要是让我们了解`fd`的作用和分配

# 解题流程

用`ida`打开，看伪代码

![image-20260603223052851](https://img.leeshang.top/typora/2026/06/d4f0b069ae201bed992aa101f42eb284.png)

又知道默认的fd分配为

> 0 -> stdin
> 1 -> stdout
> 2 -> stderr

`dup(1)` 会复制当前的 stdout 文件描述符。由于程序启动时 0、1、2 分别被 stdin、stdout、stderr 占用，所以 dup(1) 会返回当前最小可用的 fd，也就是 3

随后程序 close(1)，关闭了原本的 stdout，**但 fd 3 仍然指向同一个终端输出**。因此当程序询问我们隐藏的 stdout fd时，就该输入 3。成功的话就会由write有屏幕输出“You are right.What would you like to see?”

```terminal
I've hidden the fd of stdout. Can you find it?
3
You are right.What would you like to see?
```

再然后就是让我们输入字符串并存入file，并在后续打开该文件，显然我们该输入诸如flag的字符串

```terminal
flag
What is its fd?
```

之后程序调用 open(file, 0) 打开我们输入的文件。**虽然伪代码中没有保存 open 的返回值，但文件确实已经被打开，并且内核会为它分配当前最小可用的 fd，由于前面 fd 1 已经被 close 掉，所以此时 open("flag", 0) 会返回 fd 1**

"What is its fd?" 输入的 1 被对应存入 fd2 后，read 和 write 便会将读到的 0x50 大小的字符串放至 buf 地址处并打印到屏幕，flag 就出来了

```terminal
1
flag{8ed628b6-792a-4a36-9592-298a29eacb66}
```

# 总结

+ 了解了fd的作用和分配规则
+ 对更偏系统和底层的函数(如write、open)的作用和参数规则有了更好的理解
