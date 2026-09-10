---
title: 从自定义base64到小端序常量比较--B4se_64复盘
published: 2026-09-10
image: ""
tags: [re]
category: re
draft: false
series: zypc2026
---

## 前言

这道题的题面已经给出了很强的提示：普通的在线 Base64 解码工具无法得到正确结果，程序中可能存在一张被替换过的自定义字符表。因此，本题的核心不是“会不会调用 Base64 解码函数”，而是能否从程序中找到编码表、确认编码逻辑，再还原主函数的验证条件。

分析过程中，我还遇到了几个比最终脚本更值得记录的问题：

- 为什么 Base64 会把三个字节变成四个字符？
- `& 0x3F` 为什么不会导致信息丢失？
- 为什么字符串在程序里会表现为“反着写”的 64 位常量？
- 为什么编码结果前半段被 IDA 命名为 `v8`，后半段却变成了 `v9`？

## 1. 从静态字符串发现自定义表

将程序载入 IDA，按 `Shift+F12` 打开 Strings 窗口，可以发现一串十分可疑的字符：

```text
qwertyuiopasdfghjklzxcvbnm1234567890QWERTYUIOPASDFGHJKLZXCVBNM@#
```

它不仅看起来像按照键盘顺序排列，而且恰好包含 64 个字符。这与标准 Base64 字符表的长度完全一致：

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```

由此可以提出猜想：程序保留了 Base64 的位拆分规则，只是将标准字符表替换成了这张自定义表。

不过，“长得像”只能形成猜想，仍然需要通过交叉引用确认。选中字符串并按 `X` 查看引用，可以定位到函数 `custom_base64_encode`。

## 2. 识别自定义 Base64 编码函数

函数签名如下：

```c
void __fastcall custom_base64_encode(__int64 a1, int a2, char *a3);
```

结合函数中的读写方式，可以先为三个参数赋予更有意义的名称：

```c
a1 -> input
a2 -> input_len
a3 -> output
```

理由是：程序不断从 `a1 + 偏移` 处读取字节，用 `a2` 判断剩余长度，并将结果依次写入 `a3` 指向的区域。

### 2.1 三个字节如何拼成 24 位

对于连续的三个输入字节 `b0`、`b1`、`b2`，程序进行的核心操作可以整理为：

```c
uint32_t n = ((uint32_t)b0 << 16)
           | ((uint32_t)b1 << 8)
           | b2;
```

例如：

```text
b0 = 0x12
b1 = 0x34
b2 = 0x56
```

经过移位后：

```text
b0 << 16 = 0x120000
b1 << 8  = 0x003400
b2       = 0x000056
```

再通过按位或 `|` 合并：

```text
0x120000 | 0x003400 | 0x000056 = 0x123456
```

三个字节因此被依次放入同一个 24 位整数中。

### 2.2 将 24 位拆成四组 6 位

Base64 将 24 位数据从高到低划分为四组，每组 6 位：

```text
[23……18] [17……12] [11……6] [5……0]
```

对应下标的计算方式是：

```c
i0 = n >> 18;
i1 = (n >> 12) & 0x3F;
i2 = (n >> 6)  & 0x3F;
i3 = n         & 0x3F;
```

其中：

```text
0x3F = 00111111₂ = 63
```

与 `0x3F` 进行按位与，可以只保留最低 6 位，使结果落在 `0～63` 之间，正好作为 64 字符表的下标。

第一组 `n >> 18` 不需要再与 `0x3F`，因为 24 位整数右移 18 位后天然只剩 6 位，最大值已经是 63。

这里的掩码不会造成整个输入的信息丢失。Base64 不是只保存某一组低 6 位，而是将四组 6 位分别转换为四个字符；某一步被掩掉的位属于其他分组，会在其他下标中得到保留。

最后，程序通过下标查询自定义表：

```c
output[0] = table[i0];
output[1] = table[i1];
output[2] = table[i2];
output[3] = table[i3];
```

### 2.3 非完整三字节与特殊补位

当剩余输入不足三个字节时，程序将缺失的位按 0 处理，并使用字符 `q` 进行补位：

```c
v5[2] = 113;
v5[3] = 113;
```

十进制 `113` 对应 ASCII 字符 `q`。标准 Base64 通常使用 `=` 补位，而本题用 `q` 替代，这也是普通在线解码工具无法直接正确处理密文的原因之一。

## 3. 分析主函数的验证逻辑

主函数首先读取输入并去除行末换行符：

```c
fgets(Buffer, 256, stdin);
len = strlen(Buffer);

if (len && Buffer[len - 1] == '\n') {
    Buffer[len - 1] = '\0';
    --len;
}
```

随后调用自定义编码函数：

```c
custom_base64_encode(Buffer, len, (char *)v8);
```

编码结果不会直接通过一个清晰的字符串常量进行比较，而是被按 8 字节读取，与若干 64 位常量进行异或。

### 3.1 QWORD 与 IDA 的类型推断

常见的数据宽度如下：

| 名称 | 大小 | 位数 |
| --- | ---: | ---: |
| BYTE | 1 字节 | 8 bit |
| WORD | 2 字节 | 16 bit |
| DWORD | 4 字节 | 32 bit |
| QWORD | 8 字节 | 64 bit |

IDA 将部分输出区域推断为：

```c
_QWORD v8[3];
_QWORD v9[62];
```

但编码函数将 `v8` 强制转换为 `char *`，并从这个地址开始逐字节写入。根据栈偏移：

```text
v8 起点：rsp + 0x120
v8 大小：3 × 8 = 0x18
v9 起点：rsp + 0x138
```

而：

```text
0x120 + 0x18 = 0x138
```

所以 `v8` 和 `v9` 在内存中紧密相邻。逻辑上的编码输出从 `v8` 地址开始连续写入，前 24 字节被 IDA 称为 `v8`，后续部分则落入 IDA 称为 `v9` 的区域。

编译后的机器码通常不会保留原始局部变量名称和完整类型。IDA 只能根据访问方式进行推断，因此反编译变量不一定对应原源码中真正独立的变量。

### 3.2 小端序还原字符串常量

以第一段比较为例：

```c
v8[0] ^ 0x79505A6A6A575776LL
```

x86-64 使用小端序：多字节整数的最低有效字节存放在最低地址。将常量按字节拆分并反转：

```text
整数书写顺序：79 50 5A 6A 6A 57 57 76
内存地址顺序：76 57 57 6A 6A 5A 50 79
ASCII 字符：  v  W  W  j  j  Z  P  y
```

因此，这个 64 位常量实际对应编码字符串的前八个字符：

```text
vWWjjZPy
```

字符串本身在内存中没有反转。只是将同样的八个字节解释并书写为一个 64 位整数时，十六进制数字通常从最高位写到最低位，而小端内存从最低有效字节开始存储。

### 3.3 异或与或运算实现判等

异或具有以下性质：

```c
x ^ x == 0
```

因此：

```c
encoded_chunk ^ target_chunk
```

在两段数据完全相等时结果为 0，存在任何不同位时结果非 0。

程序再用按位或 `|` 和逻辑或 `||` 合并多段比较结果。只有所有异或结果都为 0，最终条件才为假，从而进入 `else` 成功分支；只要任意一段不同，就会进入失败分支。

可以将复杂条件整体理解为：

```c
if (encoded_input != target_encoded_string)
    puts("Oh no! Alarm was rung!!!");
else
    printf("I got it!!! Correct Flag: %s\n", Buffer);
```

## 4. 还原完整目标密文

依次将各个 64 位常量按照小端序还原，并根据它们读取的内存位置排序：

| 输出位置 | 比较位置 | 还原结果 |
| ---: | --- | --- |
| 0～7 | `v8[0]` | `vWWjjZPy` |
| 8～15 | `v8[1]` | `3rcJdHyA` |
| 16～23 | `v8[2]` | `bLjHbKwp` |
| 24～31 | `v9[0]` | `zWMCdic6` |
| 29～36 | `(char *)v9 + 5` | `ic6mHwJo` |
| 37～44 | `(char *)&v9[1] + 5` | `lt8obJq\0` |

其中第五段与第四段重叠了三个字符：

```text
z W M C d i c 6
          i c 6 m H w J o
```

重叠部分 `ic6` 完全一致，也从侧面验证了字节顺序和内存位置判断。

最后一段中的 `\0` 是 C 字符串结束符，不属于密文本身。因此完整目标密文为：

```text
vWWjjZPy3rcJdHyAbLjHbKwpzWMCdic6mHwJolt8obJq
```

## 5. 编写还原脚本

编码时，程序按照相同索引将标准 Base64 字符替换为自定义表字符。解码时需要执行相反的映射：

```text
自定义表字符 → 标准 Base64 表字符
```

Python 中，`str.maketrans(from, to)` 的第一个参数代表当前字符串中的原字符，第二个参数代表转换后的目标字符。因此这里必须写成：

```python
str.maketrans(custom_table, standard_table)
```

完整脚本如下：

```python
import base64

standard_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
custom_table = "qwertyuiopasdfghjklzxcvbnm1234567890QWERTYUIOPASDFGHJKLZXCVBNM@#"

ciphertext = "vWWjjZPy3rcJdHyAbLjHbKwpzWMCdic6mHwJolt8obJq"

custom_to_standard = str.maketrans(custom_table, standard_table)

# 根据编码函数可知，本题密文末尾的 q 是补位字符。
standard_ciphertext = ciphertext[:-1].translate(custom_to_standard) + "="

plaintext = base64.b64decode(standard_ciphertext).decode()

print("标准 Base64：", standard_ciphertext)
print("解码结果：", plaintext)
```

运行结果：

```text
标准 Base64：WllQQ3tFcDV0MzFuX2QzX1BJTl95MHVfZzB0ISEhIX0=
解码结果：ZYPC{Ep5t31n_d3_PIN_y0u_g0t!!!!}
```

最终 flag：

```text
ZYPC{Ep5t31n_d3_PIN_y0u_g0t!!!!}
```

## 6. 总结

本题的解题链条可以概括为：

```text
静态字符串发现 64 字符表
→ 通过交叉引用定位编码函数
→ 根据移位、掩码和查表确认自定义 Base64
→ 分析主函数中的 QWORD 异或比较
→ 按小端序还原目标密文
→ 将自定义字符映射回标准 Base64
→ 恢复补位并解码得到 flag
```

这道题本身并不依赖复杂算法，但把多个 RE 基础知识连接到了一起：位运算、指针与数组、数据宽度、大小端、栈内存布局，以及反编译器类型推断。相比只记住“看到 64 字符表就是换表 Base64”，真正重要的是能够从代码中验证猜想，并解释程序为什么会接受某个输入。

## 7. 本次知识盲点与后续计划

本次分析暴露出的主要薄弱点是：

- 对 `<<`、`|`、`&` 等 C 位运算不够熟悉；
- 忘记了 BYTE、DWORD、QWORD 等数据宽度；
- 容易混淆字符串顺序、内存地址顺序和整数高低位顺序；
- 容易把 IDA 推断出的变量名称和类型当成原始源码；
- 对指针强制转换、数组下标与地址偏移还不够敏感。

后续不必脱离题目一次性死记这些知识，而应在新的逆向题中反复识别、计算和验证，逐渐形成稳定的内存与数据流思维。

