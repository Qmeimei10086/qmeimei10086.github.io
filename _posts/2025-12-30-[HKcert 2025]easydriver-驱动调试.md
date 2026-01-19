---
layout: post
title: "[HKcert 2025]easydriver-驱动调试与手撕汇编"
date:       2025-12-30
author: "Qmeimei10086"
header-style: text
tags:
  - CTF
  - 逆向
  - 驱动逆向
  - 汇编
---


# 前言
好难的题啊，唉即使已经被各路大佬提示了好几次还是写不出来，我好菜我好菜我好菜...(此处省略100字)  
前面的部分可以看liv师傅的视频，我主要补充下剩下来的汇编分析  
https://www.bilibili.com/video/BV17hBQBqEda/?spm_id_from=333.1391.0.0&vd_source=97e6e1f7527112411786b01f30007712  
# 分析
## 花指令分析
我们可以看到这里都是一堆
- sse/avx指令
- push reg ;pop reg ;call 某个地址
- 无意义的浮点数操作
这些我们都不要看，很有可能你单步执行跳来跳去半天才到真实的指令，所以要有耐心

## 获取输入的正确字符串长度
- 接下来的步骤建立在你已经看过视频，使驱动正常跑起来  
我们在strlen下断点
```cmd
bp nt!strlen
```
然后随便输入点字符串，便会断下，我们先用db rcx命令可以看到rcx的值也就是我们输入的值  
点击step out,r rax命令可以看到我们strlen的返回值  
小知识,x64调用约定  
rcx,rdx,r8,r9分别是前四个参数，rax是返回值  

下面使一堆奇奇怪怪的运算，最后eax cmp了一个奇奇怪怪的值，遇到这种混淆的，我们要抓住主干，比如这里使rax  
```asm
mov     rdi,rax ;这一步把我们的结果给了rdi

mov     eax,r8d ;把r8d给了rax,那r8d呢？

;往上找找
mov     r8d,dword ptr [easyDriver!malloc+0x18050 (fffff805`45fa9050)]
;也就是说rax被赋值了一个固定的值, 我调出来是:0x22222212

xor     eax,edi 
cmp     eax,22222222h
```
最后得到我们的到输入rax应该是48才行
## 分析加密
我们在之后db rcx时，把字符串记录下来，下个硬件断点
```cmd
ba r8 字符串地址
```
会先遇到
```asm
mov     r8,  7EFEFEFEFEFEFEFFh
mov     r11, 8101010101010100h
mov     rdx, qword ptr [rax]
mov     r9,  r8
add     rax, 8
add     r9,  rdx
not     rdx
xor     rdx, r9
and     rdx, r11
je      ... (回到 mov rdx,[rax] 那里)"
```
这是0字符扫瞄，我们继续运行,遇到
```asm
hit
mov     eax, dword ptr [rdx]    rdx=字符串地址
;eax 作为为前8位，我们计为left

mov     r9d,dword ptr [rdx+4]   rdx=字符串地址
;r9d 作为为前8-16位，我们计为right
```
接着看到
```asm
mov     r10d,11111111h
xor     r10d,dword ptr [easyDriver!malloc+0x18018 (fffff805`45fa9018)]
;然后就可以看到r10d变为000000009E3779B9这明显是tea的delta
```
继续
```asm
mov     esi,r9d
mov     edi,r9d

shl     esi,4
shr     edi,5
xor     edi,esi

add     edi,r9d
;整理一下就是temp = edi = (right<<4) ^ (right>>5) + right
```
继续
```asm
mov     esi,r11d
;这里r11d位sum
and esi 3
mov     esi,dword ptr [r8+rsi*4]
;这里r8就是key的地址，所以这里是key[sum & 3]
```
db r8可以看到key的值
```cmd
kd> dd r8
ffffd20d`14cd6ad0  3c4ed885 12af3e87 d6e1b31f 25c10aa0
```
```asm
add esi,r11d     
;所以是temp2 = esi = Key[Sum & 3] + Sum;
```

```asm
xor     esi,edi                        ;esi = temp3 =  temp1 ^ temp2
add     eax,esi                        ;left += temp3
add     r11d,r10d                      ;sum += delta
mov     esi,eax                        ;esi = left
```
接下来类似
```asm
shl     esi,4                            ;esi << 4
mov     edi,eax                          ;edi = left
shr     edi,5                            ;edi >> 5
xor     edi,esi                          ;temp = (left<<4) xor ( left >> 5)
add     edi,eax                          ;temp2 = temp + left
```
```asm
mov     esi,r11d                      ;esi = sum
shr     esi,9                         ;esi = sum >> 9
and     esi,0Ch                       ;esi = esi & 0xc
mov     esi,dword ptr [r8+rsi]        ;esi = key[(sum & 0xc)/4]
```
```asm
add     esi,r11d                        ;esi += sum
xor     esi,edi                         ;esi = edi ^ temp2
add     r9d,esi                         ;left += esi
```
这边已经完成了对左右值的第一次变换然后看到一个dec     ecx,  相当与轮数，可以看到ecx的值是0xff  

差不多可以还原为
```cpp
void encrypt(DWORD *data)
{
    DWORD Key[]{0x3c4ed885, 0x12af3e87, 0xd6e1b31f, 0x25c10aa0};

    DWORD Delta = 0x9e3779b9;

    DWORD d1{}, d2{};

    d1 = data[0];
    d2 = data[1];

    DWORD Sum{};

    for (int i = 0; i < 0xff; i++)
    {
        DWORD tmp1{}, tmp2{}, tmp3{};

        tmp1 = ((d2 << 4) ^ (d2 >> 5)) + d2;
        tmp2 = Key[Sum & 3] + Sum;
        tmp3 = tmp1 ^ tmp2;
        d1 += tmp3;

        Sum += Delta;

        tmp1 = ((d1 << 4) ^ (d1 >> 5)) + d1;
        tmp2 = Key[((Sum >> 9) & 0xC) / 4] + Sum;
        tmp3 = tmp1 ^ tmp2;
        d2 += tmp3;
    }

    data[0] = d1;
    data[1] = d2;
}
```
我们直接继续，会断在
```asm
mov     dword ptr [rdx], eax
mov     dword ptr [rdx+4], ecx
```
这就是把值还回去了,继续运行可以看到
```asm
fffff805`45fa7ab3 483b0411        cmp     rax,qword ptr [rcx+rdx]
```
这里可以看到对比的值，密文在rcx+rdx，我们看看
```
fffff805`45fa9090  2a90bfd5 aa53b7ef fc23b031 dd985d10
fffff805`45fa90a0  ff5ceea4 0ade98c1 c5bb1dd3 60a3d0cc
fffff805`45fa90b0  c02fcca9 dd9f252b 9750cd50 808a76e5
```

一点关于memcmp的细节:  
memcmp 常见的三段式结构：  
先按 32 字节块比 → 再按 8 字节块比 → 最后按 1~7 字节比（你没贴出来的是最后那段）  
  
最后解题脚本  
```c
#include <iostream>
#include <windows.h>

void decrypt(DWORD *data)
{
    DWORD Key[]{0x3c4ed885, 0x12af3e87, 0xd6e1b31f, 0x25c10aa0};

    DWORD Delta = 0x9e3779b9;

    DWORD d1{}, d2{};

    d1 = data[0];
    d2 = data[1];

    DWORD Sum = Delta * 0x257;

    for (int i = 0; i < 0x257; i++)
    {
        DWORD tmp1{}, tmp2{}, tmp3{};

        tmp1 = ((d1 << 4) ^ (d1 >> 5)) + d1;
        tmp2 = Key[((Sum >> 9) & 0xC) / 4] + Sum;
        tmp3 = tmp1 ^ tmp2;
        d2 -= tmp3;

        Sum -= Delta;

        tmp1 = ((d2 << 4) ^ (d2 >> 5)) + d2;
        tmp2 = Key[Sum & 3] + Sum;
        tmp3 = tmp1 ^ tmp2;
        d1 -= tmp3;
    }

    data[0] = d1;
    data[1] = d2;
}

int main()
{
    DWORD Enc[]{0x2a90bfd5, 0xaa53b7ef, 0xfc23b031, 0xdd985d10, 0xff5ceea4, 0x0ade98c1, 0xc5bb1dd3, 0x60a3d0cc, 0xc02fcca9, 0xdd9f252b, 0x9750cd50, 0x808a76e5};
    for (int i = 0; i < 8; i++)
    {
        decrypt((DWORD *)((BYTE *)Enc + i * 8));
    }
    {% raw %}printf("flag{%.48s}\n", Enc);{% endraw %}
    // flag{C3A1F8E0B9D24765A9C0E1B4F3D687029514A3E8B6D7C2F0}
    return 0;
}
```


