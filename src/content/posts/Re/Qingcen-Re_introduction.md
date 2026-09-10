---
title: RE 入门
published: 2026-06-04
image: ""
tags: [re]
category: re
draft: false
series: 青岑RE入门
---

# REVERSE_0

用ida打开附件，F5查看伪代码

![image-20260604200527242](https://img.leeshang.top/typora/2026/06/dc2c5f12c55cd96cc0d7f9a7c2252716.png)

很简单的逻辑，flag也告诉你了

# REVERSE_1

用ida打开附件，F5查看伪代码

![image-20260604203537409](https://img.leeshang.top/typora/2026/06/141e7807657e0a5f412004fe08727884.png)

看来主函数内部别有洞天，点开main_0

![image-20260604203719669](https://img.leeshang.top/typora/2026/06/3d84301bb114b5f4a6f8500210423497.png)

前面的**未初始化栈内存填充循环**不用管，看第二个循环以及后面的内容

经过分析，不难发现，这是在先把Str2内的小写o都换成数字0，再把我们输入的字符串`Str1`和字符串`Str2`的前`v5`个字符(也就是`Str2的长度`)进行比较，如果相同，则就是我们要找的flag

那么点击Str2查看数据

![image-20260604204705203](https://img.leeshang.top/typora/2026/06/1c11efab92a2733989ea475e27f22906.png)

把它进行替换，也就是{hell0_w0rld}，就是我们要找的flag了

# REVERSE_2

用ida打开附件，F5查看伪代码

![image-20260604215549861](https://img.leeshang.top/typora/2026/06/3b148829a8fcff6f6cb89c87f1a7d922.png)

前面的是栈保护，不用管

后面调用了`fork()`函数，程序至此被分为了`父子进程`，两者此处定义的 pid(并不等价于进程本身 PID)的值由 fork() 函数返回且不同，**父进程里是子进程的进程号，通常是一个正数；而子进程里则等于0**

所以父进程会进入 if 分支(pid > 0)，执行`waitpid(pid, &stat_loc, 0)`函数等待子进程结束后再继续；而子进程进入 else 分支(pid = 0)，根据ASCII码值来看，会把 flag 字符串的 i 和 r 都换成数字 1。后面依旧是跟输入的字符串比较。

此时再点击flag查看数据

![image-20260604221145333](https://img.leeshang.top/typora/2026/06/72957ede3923daac02368be4ffad884d.png)

父进程没有进行替换，则是原样的`{hacking_for_fun}`；子进程替换后就变成了`{hack1ng_fo1_fun}`

而这题明显是在考察子进程对flag的修改，故预期解为后者

# REVERSE_3

