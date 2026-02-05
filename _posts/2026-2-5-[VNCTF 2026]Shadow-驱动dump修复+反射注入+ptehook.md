---
layout: post
title: "[VNCTF 2026]Shadow-驱动dump修复+反射注入+ptehook"
date:       2026-2-5
author: "Qmeimei10086"
header-style: text
tags:
  - CTF
  - 逆向
  - 驱动
  - dump修复
  - ptehook
---

# 前言
赛后对着liv师傅的博客瞪半天还是复现出来了，主要是当时不会修dump，系统函数都识别出来还算好说，毕竟有万能的ai大人  
不过这次意外发现了一个非常好的修dump的方法，只要dump下来的内存中有int的内存残影，甚至比unicorn模拟执行的方法还好用  
# 粗略分析
R3的maze.exe没什么好分析的，真就是一个迷宫，R0的Shadow.sys就比较有意思了，是一个经典的反射注入，这里偷一下liv师傅的图  
![ida1](https://github.com/Qmeimei10086/qmeimei10086.github.io/blob/main/img/2026-2-5-blog-ida1.png?raw=true "ida")  
大概就是经过一轮解密，然后把解密出来的驱动加载进内存里    
不过我不想熬解密的部分，就选择的dump 
我们在修复重定位的地方下断点   
```cmd
kd> sxe ld Shadow.sys
kd> g
kd> bp Shadow+0xC1B7
kd> g
```
这里的rcx就是载入驱动的首地址  
```cmd
Breakpoint 0 hit
Shadow+0xc1b7:
fffff805`45fac1b7 e8885effff      call    Shadow+0x2044 (fffff805`45fa2044)
2: kd> r rcx
rcx=ffffc10ff2f1c000
2: kd> db rcx L10
ffffc10f`f2f1c000  4d 5a 90 00 03 00 00 00-04 00 00 00 ff ff 00 00  MZ..............
2: kd> !dh rcx

File Type: EXECUTABLE IMAGE
FILE HEADER VALUES
    8664 machine (X64)
       6 number of sections
695CE348 time date stamp Tue Jan  6 18:26:16 2026

       0 file pointer to symbol table
       0 number of symbols
      F0 size of optional header
      22 characteristics
            Executable
            App can handle >2gb addresses

OPTIONAL HEADER VALUES
     20B magic #
   14.29 linker version
    4200 size of code
    1800 size of initialized data
       0 size of uninitialized data
    8000 address of entry point
    1000 base of code
         ----- new -----
0000000140000000 image base
    1000 section alignment
     200 file alignment
       1 subsystem (Native)
   10.00 operating system version
   10.00 image version
   10.00 subsystem version
    A000 size of image
     400 size of headers
    EA2F checksum
0000000000100000 size of stack reserve
0000000000001000 size of stack commit
0000000000100000 size of heap reserve
0000000000001000 size of heap commit
    4160  DLL characteristics
            High entropy VA supported
            Dynamic base
            NX compatible
            Guard
       0 [       0] address [size] of Export Directory
    805C [      28] address [size] of Import Directory
       0 [       0] address [size] of Resource Directory
    7000 [     1D4] address [size] of Exception Directory
       0 [       0] address [size] of Security Directory
    9000 [      14] address [size] of Base Relocation Directory
    5224 [      38] address [size] of Debug Directory
       0 [       0] address [size] of Description Directory
       0 [       0] address [size] of Special Directory
       0 [       0] address [size] of Thread Storage Directory
    5260 [     118] address [size] of Load Configuration Directory
       0 [       0] address [size] of Bound Import Directory
    5000 [     138] address [size] of Import Address Table Directory
       0 [       0] address [size] of Delay Import Directory
       0 [       0] address [size] of COR20 Header Directory
       0 [       0] address [size] of Reserved Directory


SECTION HEADER #1
   .text name
    3B85 virtual size
    1000 virtual address
    3C00 size of raw data
     400 file pointer to raw data
       0 file pointer to relocation table
       0 file pointer to line numbers
       0 number of relocations
       0 number of line numbers
68000020 flags
         Code
         Not Paged
         (no align specified)
         Execute Read

SECTION HEADER #2
  .rdata name
     6B0 virtual size
    5000 virtual address
     800 size of raw data
    4000 file pointer to raw data
       0 file pointer to relocation table
       0 file pointer to line numbers
       0 number of relocations
       0 number of line numbers
48000040 flags
         Initialized Data
         Not Paged
         (no align specified)
         Read Only


Debug Directories(2)
	Type       Size     Address  Pointer
	cv           4f        5378     4378	Format: RSDS, guid, 1, D:\åºé¢\VNCTF2026\src\DLoader\x64\Debug\LoadTest.pdb
	(   13)     148        53c8     43c8

SECTION HEADER #3
   .data name
     BB8 virtual size
    6000 virtual address
     C00 size of raw data
    4800 file pointer to raw data
       0 file pointer to relocation table
       0 file pointer to line numbers
       0 number of relocations
       0 number of line numbers
C8000040 flags
         Initialized Data
         Not Paged
         (no align specified)
         Read Write

SECTION HEADER #4
  .pdata name
     1D4 virtual size
    7000 virtual address
     200 size of raw data
    5400 file pointer to raw data
       0 file pointer to relocation table
       0 file pointer to line numbers
       0 number of relocations
       0 number of line numbers
48000040 flags
         Initialized Data
         Not Paged
         (no align specified)
         Read Only

SECTION HEADER #5
    INIT name
     534 virtual size
    8000 virtual address
     600 size of raw data
    5600 file pointer to raw data
       0 file pointer to relocation table
       0 file pointer to line numbers
       0 number of relocations
       0 number of line numbers
62000020 flags
         Code
         Discardable
         (no align specified)
         Execute Read

SECTION HEADER #6
  .reloc name
      14 virtual size
    9000 virtual address
     200 size of raw data
    5C00 file pointer to raw data
       0 file pointer to relocation table
       0 file pointer to line numbers
       0 number of relocations
       0 number of line numbers
42000040 flags
         Initialized Data
         Discardable
         (no align specified)
         Read Only
```
size of image A000，这是加载后的大小  
dump就行  
```cmd
.writemem D:\dumped.sys ffffc10ff2f1c000 L?0xA000
```
# dump修复
不错的教程：https://bbs.kanxue.com/thread-274505-1.htm  
里面的pe_unmapper挺好用的，https://github.com/hasherezade/libpeconv/tree/master/pe_unmapper  
![pe1](https://github.com/Qmeimei10086/qmeimei10086.github.io/blob/main/img/2026-2-5-blog-pe1.png?raw=true "pe1")  
可以看到，pe文件再加载后会像展开一样  
这里就有两种方法  
```cmd
pe_unmapper.exe /in D:\dumped.sys 00400000 /out fix.dump
```
这种就像是pe加载的逆过程，让他缩回去  
当是这里要讲的是第二种方法，realign模式  
现在的dump我们脱ida里，是不能把所有函数都识别出来的，而且int也是有问题的  
但是我们现在用010 editor打开，让SizeOfRawData等与PhysicalAddress，PointerToRawData等于VirtualAddress  
再用ida打开，奇迹的发现函数都识别了，int也是好的  
这是为什么？    
计算公式  
```cmd
FOA=PointerToRawData+(RVA−VirtualAddress)
```
为什么ida会找不到相关系统函数，以为ida加载一个pe时，会首先假装把这个文件加载，显示的地址都是按后算的加载算的  
第一个问题时，我们的dump是已经加载好的，但是ida又按照原本pe头里的数据去拉伸，相当与二次拉伸，导致数据错位，这是为什么有的函数没有识别  
第二个问题是，ida在假装加载好后，是怎么识别系统函数的呢，我们先来看一个例子  
```asm
FF 15 35 6F FF FF                 call    cs:ExAllocatePool
```
FF 15是通过偏移来找的，也就是当前指令往下偏移35 6F FF FF就是我们的系统函数地址  
但是我们的ida把程序再次拉伸，倒是落得的地方不是iat的区域，所以就无法是被去查int表  
其三就是，由于错位，ida也无法正确识别int在哪  
但是我们PointerToRawData=VirtualAddress，所以foa等于rva，所以现在在文件里的偏移和真实内存中是一样的！  
也就是ida把他加载完还是和原本一样  
这样子所有的数据都是对的上的  
实测部分vmp驱动也能这样恢复函数名字，不用去模拟执行   
# 驱动分析
驱动逻辑可以去看liv师傅的博客，大概概括一下    
1. 解密一个字符串KeDelayExecutionThread  
2. 通过查名字表查到函数地址  
3. 寻找到maze.exe的pid  
4. 构造一个pte hook,只hook maze.exe的KeDelayExecutionThread,功能如下  
- 接受传入的参数作为密钥派生参数  
- 派生密钥  
- 解密一段shellcode，这是加密函数  
- 对一段数据A用加密函数和密钥加密，最后对比    
5. 将驱动附加到键盘上， 并且监控输入:  
- 按下f12，输出on input  
- 然后把你输入的存入数据A
- 按下f12, 输出input end  
你可能会好奇KeDelayExecutionThread什么时候被调用，这是关键启动校验输入的核心  
在maze.exe的迷宫走到尽头的时候，会调用sleep，这里底层就会调用KeDelayExecutionThread，还会传入时间作为参数，在密钥派生时用到  
# 复现
  
```c
__int64 __fastcall my_DelayExecutionThread(unsigned __int8 a1, unsigned __int8 a2, _QWORD *arg3)
{
  char *P_1; // [rsp+20h] [rbp-B8h]
  char *dst; // [rsp+20h] [rbp-B8h]
  char *dst_1; // [rsp+20h] [rbp-B8h]
  char *dst_2; // [rsp+20h] [rbp-B8h]
  void *dst_3; // [rsp+20h] [rbp-B8h]
  int n0x1AD; // [rsp+28h] [rbp-B0h]
  int n0x1AD_1; // [rsp+2Ch] [rbp-ACh]
  int n0x1AD_2; // [rsp+30h] [rbp-A8h]
  int n0x1AD_3; // [rsp+34h] [rbp-A4h]
  int n430_1; // [rsp+38h] [rbp-A0h]
  int i; // [rsp+3Ch] [rbp-9Ch]
  int i_3; // [rsp+40h] [rbp-98h]
  int n57; // [rsp+44h] [rbp-94h]
  int i_2; // [rsp+48h] [rbp-90h]
  __int64 key; // [rsp+70h] [rbp-68h] BYREF
  unsigned __int64 n430; // [rsp+78h] [rbp-60h]
  __int64 i_1; // [rsp+80h] [rbp-58h]
  PVOID P; // [rsp+88h] [rbp-50h]
  SIZE_T NumberOfBytes; // [rsp+90h] [rbp-48h]
  _BYTE *Source2; // [rsp+98h] [rbp-40h]
  char *p_to_decrpted_fun; // [rsp+A0h] [rbp-38h]
  char *p_to_decrpted_fun_1; // [rsp+A8h] [rbp-30h]
  __int64 v26; // [rsp+B0h] [rbp-28h]

  key = 0x17658990C729C992LL;
  for ( n57 = 0; n57 < 57; ++n57 )
    key = *arg3 ^ (65539 * key);          //密钥派生
  n430 = 430;
  NumberOfBytes = 2146;
  P = ExAllocatePoolWithTag(NonPagedPool, 0x862u, 'ENCM');
  P_1 = P;
  qmemcpy(P, &src_, 0x1ADu);
  sub_140001B60(P, 429);
  for ( n0x1AD = 0; n0x1AD < 0x1AD; ++n0x1AD )
    P_1[n0x1AD] ^= unk_140006870;
  dst = P_1 + 429;
  qmemcpy(dst, &src__0, 0x1ADu);
  sub_140001B60(dst, 429);
  for ( n0x1AD_1 = 0; n0x1AD_1 < 0x1AD; ++n0x1AD_1 )
    dst[n0x1AD_1] ^= unk_140006871;
  dst_1 = dst + 429;
  qmemcpy(dst_1, &src__1, 0x1ADu);
  sub_140001B60(dst_1, 429);
  for ( n0x1AD_2 = 0; n0x1AD_2 < 0x1AD; ++n0x1AD_2 )
    dst_1[n0x1AD_2] ^= unk_140006872;
  dst_2 = dst_1 + 429;
  qmemcpy(dst_2, &src__2, 0x1ADu);
  sub_140001B60(dst_2, 429);
  for ( n0x1AD_3 = 0; n0x1AD_3 < 0x1AD; ++n0x1AD_3 )
    dst_2[n0x1AD_3] ^= unk_140006873;
  dst_3 = dst_2 + 429;
  qmemcpy(dst_3, &src__3, n430);
  sub_140001B60(dst_3, n430);
  for ( n430_1 = 0; n430_1 < n430; ++n430_1 )
    *(dst_3 + n430_1) ^= unk_140006874;
  p_to_decrpted_fun = P + 1909;
  Source2 = input;      //解密shellcode
  i_1 = -1;
  do
    ++i_1;
  while ( Source2[i_1] );
  i_3 = i_1;
  if ( i_1 )
  {
    i_2 = i_1 % 8;
    for ( i = i_1; i < i_2; ++i )
      input[i] = 1;
    p_to_decrpted_fun_1 = p_to_decrpted_fun;
    (p_to_decrpted_fun)(input, i_2 + i_3, &key);    
    if ( RtlCompareMemory(&Source1_, input, 0x28u) == 40 )
      KeBugCheck(0x11111111u); //蓝屏
  }
  ExFreePoolWithTag(P, 0x454E434Du);
  v26 = qword_140006BB0;
  return (qword_140006BB0)(a1, a2, arg3);
}
```
  
我们的目标有三  
1. 拿到加密函数  
2. 拿到密文  
3. 拿到最终传入派生过的的密钥  
  
```cmd
0: kd> sxe ld Shadow.sys
0: kd> g                          //然后我们去加载驱动
nt!DebugService2+0x5:  
fffff805`41611d95 cc              int     3
```
根据我们前面的分析，在shadow+c258的地方是调用Driverentry  
```asm
INIT:000000014000C258 FF 15 FA 6D FF FF                 call    cs:__guard_dispatch_icall_fptr
```
我们在Driverentry下断点
```cmd
1: kd> bp Shadow+c258
1: kd> g
Breakpoint 0 hit
Shadow+0xc258:
fffff805`45fac258 ff15fa6dffff    call    qword ptr [Shadow+0x3058 (fffff805`45fa3058)]
3: kd> dq fffff805`45fa3058
fffff805`45fa3058  fffff805`45fa2600 00002530`00001c70
fffff805`45fa3068  0000c370`00002540 02000000`01000000
fffff805`45fa3078  08000000`04000000 20000000`10000000
fffff805`45fa3088  80000000`40000000 36000000`1b000000
fffff805`45fa3098  695ce463`00000000 0000000d`00000000
fffff805`45fa30a8  000031d8`0000014c 00000000`000021d8
fffff805`45fa30b8  00000000`00000000 00000000`00000118
fffff805`45fa30c8  00000000`00000000 00000000`00000000
3: kd> u fffff805`45fa2600
Shadow+0x2600:
fffff805`45fa2600 ffe0            jmp     rax
fffff805`45fa2602 cc              int     3
fffff805`45fa2603 cc              int     3
fffff805`45fa2604 cc              int     3
fffff805`45fa2605 cc              int     3
fffff805`45fa2606 cc              int     3
fffff805`45fa2607 cc              int     3
fffff805`45fa2608 cc              int     3
3: kd> r rax
rax=ffffc10ff2f24000
3: kd> bp ffffc10ff2f24000
3: kd> g
Breakpoint 2 hit
ffffc10f`f2f24000 48895c2408      mov     qword ptr [rsp+8],rbx
```
便来到Driverentry，我们首先要获取加密的函数，在这里分配了他的空间，P就是首地址，长度862
```c
P = ExAllocatePoolWithTag(NonPagedPool, 0x862u, 'ENCM')
//对应汇编
.text:000000014000138F FF 15 93 3C 00 00                 call    cs:ExAllocatePoolWithTag
```
由于是放射注入，系统里并没有相关符号，我们只能这么下断点  
比如就在ExAllocatePoolWithTag这里  
ffffc10ff2f24000是driverentry，在ida里是  
```asm
INIT:0000000140008000 48 89 5C 24 08                    mov     [rsp+arg_0], rbx
```
所以断点下为  ffffc10f`f2f24000+(138F-8000)  = FFFFC10FF2F1D38F
```cmd
3: kd> u FFFFC10FF2F1D38F
ffffc10f`f2f1d38f ff15933c0000    call    qword ptr [ffffc10f`f2f21028]
ffffc10f`f2f1d395 4889842488000000 mov     qword ptr [rsp+88h],rax
ffffc10f`f2f1d39d 488b842488000000 mov     rax,qword ptr [rsp+88h]
ffffc10f`f2f1d3a5 4889442420      mov     qword ptr [rsp+20h],rax
ffffc10f`f2f1d3aa 488d054f4c0000  lea     rax,[ffffc10f`f2f22000]
ffffc10f`f2f1d3b1 488b7c2420      mov     rdi,qword ptr [rsp+20h]
ffffc10f`f2f1d3b6 488bf0          mov     rsi,rax
ffffc10f`f2f1d3b9 488b4c2450      mov     rcx,qword ptr [rsp+50h]
3: kd> bp ffffc10f`f2f1d38f
3: kd> g
```
此时什么也不会发生，以为我们没加入这个hook的地方    
接下来我按f12开始输入，输入完再按f12，完成迷宫，就会触发  
```cmd
[LDriver] on input.
Breakpoint 3 hit
ffffc10f`f2f1d38f ff15933c0000    call    qword ptr [ffffc10f`f2f21028]
```
我们步过，此时rax就我们解密数据的首地址，不过此时还未解密  
```cmd
3: kd> p
ffffc10f`f2f1d395 4889842488000000 mov     qword ptr [rsp+88h],rax
3: kd> r rax
rax=ffffc10ff2f03010
```
接下来要在调用这个函数前下断点，此时已经解密  
```asm
.text:0000000140001727 4C 8D 44 24 70                    lea     r8, [rsp+0D8h+key]
.text:000000014000172C 48 8B D0                          mov     rdx, rax
.text:000000014000172F 48 8D 0D 0A 54 00                 lea     rcx, input
.text:000000014000172F 00
.text:0000000140001736 48 8B 84 24 A8 00                 mov     rax, [rsp+0D8h+var_30]
.text:0000000140001736 00 00
.text:000000014000173E FF 15 FC 39 00 00                 call    cs:__guard_dispatch_icall_fptr
```
按照前面的计算方法也就是    
```cmd
3: kd> bp FFFFC10FF2F1D73E
3: kd> g
Breakpoint 4 hit
ffffc10f`f2f1d73e ff15fc390000    call    qword ptr [ffffc10f`f2f21140]
```
我们dump下来  
```cmd
3: kd> .writemem D:\final.dump FFFFC10FF2F03010 L0x862
Writing 862 bytes.
```
我们还可以看看数据
```cmd
3: kd> db rcx
ffffc10f`f2f22b40  64 64 73 73 73 73 73 73-64 73 73 64 64 64 77 64  ddssssssdssdddwd
ffffc10f`f2f22b50  64 64 64 64 73 73 64 00-00 00 00 00 00 00 00 00  ddddssd.........
ffffc10f`f2f22b60  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
ffffc10f`f2f22b70  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
ffffc10f`f2f22b80  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
ffffc10f`f2f22b90  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
ffffc10f`f2f22ba0  00 00 00 00 01 00 00 00-17 00 00 00 00 00 00 00  ................
ffffc10f`f2f22bb0  30 2b f0 f2 0f c1 ff ff-00 00 00 00 00 00 00 00  0+..............
3: kd> r rdx
rdx=000000000000001e
3: kd> dq r8
ffffd20d`17647420  e7d1cc85`d2172c16 00000000`000001ae
ffffd20d`17647430  00000000`00000017 ffffc10f`f2f03010
ffffd20d`17647440  00000000`00000862 ffffc10f`f2f22b40
ffffd20d`17647450  ffffc10f`f2f03785 ffffc10f`f2f03785
ffffd20d`17647460  00000000`00000000 ffffc10f`fade1080
ffffd20d`17647470  ffffc283`dc21b51b 00000000`00000000
ffffd20d`17647480  00000000`00000000 fffff805`418b756f
ffffd20d`17647490  00000000`00000001 00000000`00000000
```
根据前面的汇编和调用约定得到rdx是输入长度，rcx是输入的，r8就是派生后的密钥，也就是e7d1cc85d2172c16  
接下来在对比前下断点，拿到我们要的密文  
```asm
.text:0000000140001744 41 B8 28 00 00 00                 mov     r8d, 28h ; '('  ; Length
.text:000000014000174A 48 8D 15 EF 53 00                 lea     rdx, input      ; Source2
.text:000000014000174A 00
.text:0000000140001751 48 8D 0D 68 53 00                 lea     rcx, Source1_   ; Source1
.text:0000000140001751 00
.text:0000000140001758 FF 15 C2 38 00 00                 call    cs:RtlCompareMemory
```
```cmd
3: kd> bp ffffc10f`f2f1d758
breakpoint 5 redefined
3: kd> g
Breakpoint 5 hit
ffffc10f`f2f1d758 ff15c2380000    call    qword ptr [ffffc10f`f2f21020]
3: kd> r r8d
r8d=28
3: kd> db rdx
ffffc10f`f2f22b40  87 66 db 0f 7e 87 06 44-a3 1f 47 55 d9 12 2e 82  .f..~..D..GU....
ffffc10f`f2f22b50  89 b8 0b 19 81 6e 88 cb-00 00 00 00 00 00 00 00  .....n..........
ffffc10f`f2f22b60  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
ffffc10f`f2f22b70  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
ffffc10f`f2f22b80  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
ffffc10f`f2f22b90  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
ffffc10f`f2f22ba0  00 00 00 00 01 00 00 00-17 00 00 00 00 00 00 00  ................
ffffc10f`f2f22bb0  30 2b f0 f2 0f c1 ff ff-00 00 00 00 00 00 00 00  0+..............
3: kd> db rcx
ffffc10f`f2f22ac0  51 da b8 52 73 b9 17 00-e0 02 f4 b2 2c 5f 22 62  Q..Rs.......,_"b
ffffc10f`f2f22ad0  33 0c 01 44 bb 70 9d 92-8a 06 f9 2c 1d 8f 0a a9  3..D.p.....,....
ffffc10f`f2f22ae0  22 7b 84 30 71 13 d0 f9-bc 5f 58 36 d6 7d 8a 66  "{.0q...._X6.}.f
ffffc10f`f2f22af0  4f 6e 03 3b 5d 2e 01 eb-5b 3a fb 9d 74 93 24 ca  On.;]...[:..t.$.
ffffc10f`f2f22b00  82 04 12 e5 9d 07 03 c7-a6 82 57 d5 10 ee 42 13  ..........W...B.
ffffc10f`f2f22b10  3c a2 df 2d 99 2b 00 00-c3 5d 20 d2 66 d4 ff ff  <..-.+...] .f...
ffffc10f`f2f22b20  50 2a f0 f2 0f c1 ff ff-50 2a f0 f2 0f c1 ff ff  P*......P*......
ffffc10f`f2f22b30  80 60 7e fb 0f c1 ff ff-00 87 c4 f3 0f c1 ff ff  .`~.............
```
rcx的数据就是我们要的密文，r8d是长度    
接下来东西起了，就可以丢ai了  
# 解密
ai对话
```text
算法核心逻辑分析：
S-Box 生成 (sub_55):
使用 Key 初始化种子，利用 Xorshift 类 PRNG 进行 Fisher-Yates 洗牌生成 256 字节的 S-Box。
轮密钥生成 (sub_225):
基于 Key 和黄金分割常数（Delta 0x9E3779B9 / 0xB7E15163）生成 32 个 Round Keys (RK[0]...RK[31])。
Tweak 生成 (sub_392):
每一块加密前，根据块索引（Block Index）生成一个 Tweak 值，混入初始状态。
加密循环 (sub_476):
32 轮迭代。
每轮包含复杂的位移（ROL/ROR）、异或和 32位 S-Box 变换（sub_1AD）。
包含条件交换（Conditional Swap），取决于累加器 v29 的奇偶性。
```
解密脚本
```python
import struct

def rol(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def ror(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def inv_rol(x, n):
    return ror(x, n)

def inv_ror(x, n):
    return rol(x, n)

def sbox32(val, sbox):
    b0 = val & 0xFF
    b1 = (val >> 8) & 0xFF
    b2 = (val >> 16) & 0xFF
    b3 = (val >> 24) & 0xFF
    return ((sbox[b3] << 24) | (sbox[b2] << 16) | (sbox[b1] << 8) | sbox[b0]) & 0xFFFFFFFF

def inv_sbox32(val, inv_sbox):
    return sbox32(val, inv_sbox) # Same logic, just different table

# PRNG sub_0
def sub_0_prng(seed_ref):
    seed = seed_ref[0]
    # v5 = (((seed << 13) ^ seed) >> 17) ^ (seed << 13) ^ seed
    # All 32-bit ops
    term1 = ((seed << 13) & 0xFFFFFFFF) ^ seed
    v5 = (term1 >> 17) ^ term1
    
    # v6 = (32 * v5) ^ v5  -> (v5 << 5) ^ v5
    v6 = ((v5 << 5) & 0xFFFFFFFF) ^ v5
    
    seed_ref[0] = v6
    return v6

# SBox Gen sub_55
def gen_sbox(key):
    sbox = list(range(256))
    
    # Initialize seed
    # v7 = (a4[1] >> 21) | (a4[1] << 11) -> ROR(k1, 21)
    k0 = key[0]
    k1 = key[1]
    
    v7 = ror(k1, 21)
    seed_val = v7 ^ k0 ^ 0x1244F4C6
    seed_ref = [seed_val] # Pass by ref
    
    # Shuffle
    for n255 in range(255, 0, -1):
        rand_val = sub_0_prng(seed_ref)
        v15 = rand_val % (n255 + 1)
        
        # Swap
        sbox[n255], sbox[v15] = sbox[v15], sbox[n255]
        
    return sbox

# Round Key Gen sub_225
def gen_round_keys(key):
    k0 = key[0]
    k1 = key[1]
    
    rk = [0] * 32
    v7 = k0 ^ 0xB7E15163
    v6 = (k1 - 1640531527) & 0xFFFFFFFF
    
    for i in range(32):
        # v8 = ((Delta * i) ^ 0xB7E15163) + (ROL(v6, v7 & 0x1F) ^ v7)
        delta_i = ((-1640531527 & 0xFFFFFFFF) * i) & 0xFFFFFFFF
        term1 = delta_i ^ 0xB7E15163
        term2 = rol(v6, v7 & 0x1F) ^ v7
        v8 = (term1 + term2) & 0xFFFFFFFF
        
        # rk[i] = ROR(v6 + v7, v6 & 0x1F) ^ v8
        rk[i] = ror((v6 + v7) & 0xFFFFFFFF, v6 & 0x1F) ^ v8
        
        # v7 = rk[i] ^ v6
        v7 = rk[i] ^ v6
        # v6 = ROL(rk[i], v8 & 0x1F) + v8
        v6 = (rol(rk[i], v8 & 0x1F) + v8) & 0xFFFFFFFF
        
    return rk

# Tweak Gen sub_392
def gen_tweak(key, idx):
    k0 = key[0]
    k1 = key[1]
    
    # v5 = (k1 ^ 0xDEADBEEF) + (ROL(k0, idx & 0x1F) ^ (73244475 * (idx + 1)))
    term1 = k1 ^ 0xDEADBEEF
    term2 = rol(k0, idx & 0x1F) ^ ((73244475 * (idx + 1)) & 0xFFFFFFFF)
    v5 = (term1 + term2) & 0xFFFFFFFF
    
    # v6 calculation
    hi_v5 = (v5 >> 16) & 0xFFFF
    
    # C code: v6 = -2073254261 * (((2146121005 * (HIWORD(v5) ^ v5)) >> 15) ^ (2146121005 * (HIWORD(v5) ^ v5)));
    # (HIWORD(v5) ^ v5)
    xor_val = hi_v5 ^ v5
    mult_val = (2146121005 * xor_val) & 0xFFFFFFFF
    
    inner = (mult_val >> 15) ^ mult_val
    v6 = ((-2073254261 & 0xFFFFFFFF) * inner) & 0xFFFFFFFF
    
    # result = HIWORD(v6) ^ v6
    result = ((v6 >> 16) & 0xFFFF) ^ v6
    return result

def decrypt_block(block, key, round_keys, sbox, block_idx):
    # Prepare inverse S-box
    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i
        
    v30 = gen_tweak(key, block_idx)
    
    # Final Output Mapping Reverse
    # data[1] = v27 = v30 ^ Key[0] ^ v26
    # data[0] = (((v30 >> 21) | (v30 << 11)) + Key[1]) ^ v22
    
    d0_out = block[0]
    d1_out = block[1]
    
    k0 = key[0]
    k1 = key[1]
    
    # Recover v26 (final)
    v26 = d1_out ^ v30 ^ k0
    
    # Recover v22 (final)
    term = ror(v30, 21) + k1
    v22 = d0_out ^ (term & 0xFFFFFFFF)
    
    # Pre-calculate v29 sequence (accumulator)
    v29_seq = [0] * 33
    curr_v29 = 0
    for i in range(32):
        v29_seq[i] = curr_v29
        # v29 += *(a5 + 4LL * i) ^ 0xB7E15163;
        curr_v29 = (curr_v29 + (round_keys[i] ^ 0xB7E15163)) & 0xFFFFFFFF
    
    # Reverse Loop (i from 31 down to 0)
    for i in range(31, -1, -1):
        rk = round_keys[i]
        
        # Current v29 at START of this round (for swap check)
        # But wait. In code: use v29 accumulator.
        # v29 is updated at start of loop body.
        # So inside the loop body, v29 represents sum(0..i).
        # v29_seq[i+1] is the value used inside round i.
        
        v29 = (v29_seq[i] + (rk ^ 0xB7E15163)) & 0xFFFFFFFF
        
        # 1. Undo Swap
        if (v29 & 1) != 0:
            v22, v26 = v26, v22
            
        # 2. Recover v24
        # v22 = ROL(v24, shift)
        # shift = ((rk >> 1) + (v29 ^ v26)) & 0x1F
        # Note: v26 here is v26_out (current value)
        shift1 = ((rk >> 1) + (v29 ^ v26)) & 0x1F
        v24 = ror(v22, shift1)
        
        # 3. Recover v26_old
        # v26 = (rk ^ v24) + ROR(v15, shift2)
        # shift2 = SBox[v24 & 0xFF] & 0x1F
        # v15 = SBox32(v26_old)
        
        byte_idx = v24 & 0xFF
        shift2 = sbox[byte_idx] & 0x1F
        
        # ROR(v15, shift2) = v26 - (rk ^ v24)
        target = (v26 - (rk ^ v24)) & 0xFFFFFFFF
        v15 = rol(target, shift2)
        
        v26_old = inv_sbox32(v15, inv_sbox)
        v26 = v26_old
        
        # 4. Recover v22_old
        # v24 = ROL(rk, v15 & 0x1F) ^ term1 ^ term2
        # term1 = ((v29 << 29) | (v29 >> 3)) + v15  -> ROL(v29, 29) + v15
        # term2 = ((rk ^ v29) + v23)
        # v23 = SBox32(v22_old)
        
        term1 = (rol(v29, 29) + v15) & 0xFFFFFFFF
        rol_rk = rol(rk, v15 & 0x1F)
        
        # term2 = v24 ^ rol_rk ^ term1
        term2 = v24 ^ rol_rk ^ term1
        
        # term2 = (rk ^ v29) + v23
        # v23 = term2 - (rk ^ v29)
        v23 = (term2 - (rk ^ v29)) & 0xFFFFFFFF
        
        v22_old = inv_sbox32(v23, inv_sbox)
        v22 = v22_old
        
    # Initial Read Logic Reverse
    # v22 = (v30 + Key[0]) ^ data[0]
    # v26 = (ROL(v30, 25) | ROR(v30, 7)) ^ Key[1] ^ data[1]
    
    # data[0] = v22 ^ (v30 + Key[0])
    d0_in = v22 ^ ((v30 + k0) & 0xFFFFFFFF)
    
    # term = ROL(v30, 25)
    d1_in = v26 ^ k1 ^ rol(v30, 25)
    
    return [d0_in, d1_in]

def solve():
    # Encrypted data
    # 51 da b8 52 -> 0x52B8DA51
    # 73 b9 17 00 -> 0x0017B973
    # ...
    enc_bytes = bytes([
        0x51, 0xda, 0xb8, 0x52, 0x73, 0xb9, 0x17, 0x00, 0xe0, 0x02, 0xf4, 0xb2, 0x2c, 0x5f, 0x22, 0x62,
        0x33, 0x0c, 0x01, 0x44, 0xbb, 0x70, 0x9d, 0x92, 0x8a, 0x06, 0xf9, 0x2c, 0x1d, 0x8f, 0x0a, 0xa9,
        0x22, 0x7b, 0x84, 0x30, 0x71, 0x13, 0xd0, 0xf9
    ])
    
    # Format to uint32 arrays
    blocks = []
    for i in range(0, len(enc_bytes), 8):
        chunk = enc_bytes[i:i+8]
        if len(chunk) < 8: break # Check alignment
        val0 = struct.unpack("<I", chunk[0:4])[0]
        val1 = struct.unpack("<I", chunk[4:8])[0]
        blocks.append([val0, val1])
        
    # Key
    # e7d1cc85`d2172c16 => Low: d2172c16, High: e7d1cc85
    key = [0xD2172C16, 0xE7D1CC85]
    
    print("Generating tables...")
    sbox = gen_sbox(key)
    round_keys = gen_round_keys(key)
    
    print("Decrypting...")
    decrypted_bytes = bytearray()
    
    for i, block in enumerate(blocks):
        print(f"Block {i}: {hex(block[0])} {hex(block[1])}")
        dec = decrypt_block(block, key, round_keys, sbox, i)
        print(f"  -> Dec: {hex(dec[0])} {hex(dec[1])}")
        decrypted_bytes.extend(struct.pack("<I", dec[0]))
        decrypted_bytes.extend(struct.pack("<I", dec[1]))
        
    print("\nDecrypted Hex:")
    print(decrypted_bytes.hex())
    print("\nDecrypted String:")
    try:
        print(decrypted_bytes.decode('utf-8')) # or ascii
    except:
        print(decrypted_bytes)

if __name__ == "__main__":
    solve()
# flag: ebbc8827-c040-4a7d-8bc7-0aeccb1ce094
```

# 后继
看liv师傅的博客说还有一个trick，通过越界访问偷偷改了密文的值？管他呢，反正我的习惯都是动态去获取密文和密钥嘻嘻   
这次因为没有恢复系统函数名字，根本做不了，或许恢复了还可以靠ai蒸一下  
这里的加密先丢ai，欠着以后在学，已经被多个师傅拷打说密码学水平不行了呜呜呜呜  
唉，还留了好多技术债没补，之后再专门出一篇加密相关的博客吧，把之前欠的算法都补了  




