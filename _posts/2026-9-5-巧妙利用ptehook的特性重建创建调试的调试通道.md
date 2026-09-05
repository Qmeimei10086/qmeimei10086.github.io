---
layout:     post
title:      巧妙利用ptehook的特性重建创建调试的调试通道
date:       2026-9-5
author:     Qmeimei10086
header-style: text
tags:
    - pte hook
    - windows调试体系
---

# 前情提要
前几天不是发了一个利用npt hook重建调试通道的文章：https://bbs.kanxue.com/thread-292825.htm    
虽然是老掉牙的技术，但是反响意外的还不错   
但是这几天在研究创建调试时，发现npt hook一个不可避免的事情，效率太差了，尤其是在虚拟机里。。。   
创建调试需要hook两个及其高频的函数：   
NtCreatUserProcess，DbgkCreateThread  
前者还好，是ssdt里的函数，我们可以用etw hook，效率还行  
DbgkCreateThread就糟糕了，他不是ssdt里的函数，而且创建线程这种这种事情几乎是无时无刻不在发生，一hook就卡的系统不能用，我只能另寻其他hook  
因为有pg，能够hook这些未导出的内核函数的hook太少了，可以的话我还是不希望搞打pg这么麻烦的事  
有没有一种只能针对一个进程的内核函数hook呢？这样子还能避免高频调用导致的系统卡顿  
于是我想到ptehook  
# PTE hook
参考：https://xz.aliyun.com/news/18999  
值针对一个进程，不会pg。。。ptehook就是一种挺完美的办法。。吗？  
让我们回忆创建调试，调试器调用完NtCreatUserProces，把创建的进程的第一次线程放入等待队列，然后就跑路了，此时是等待cpu去第一次调度  
但是对于被调试进程，我们至少要hook DbgkpQueueMessage DbgkForwardException KiDispatchException，难道说我们要抢先cpu第一次调度之前去hook？这显然不可能  
但是我突然想起之前调试ptehook时发现的奇怪现象： 
我们hook explorer进程的NtCreateFile给hook了，如果检查到参数是tips.txt，就会返回无权限  
也就是我们无法打开tips.txt了  
我们隔离了exploere.exe，用他打开tips.txt。。。打不开，超级正常  
但是我们在**桌面**双击启动我安装好的notpad++，然后把tips.exe打开。。。打不开？？？？  
我们在windbg里切换到notpad++的上下文，使用命令u NtCreateFile，竟然第一条时jmp！这不是明显给hook过了  
但是假如你在hook前提前启动一个cmd，然后装载驱动，然后用cmd启动notpad++，欸嘿，正常打开  
后来拷打ai发现其原因是：  
**pml4t具有继承关系，注意我们“在桌面”启动，这时候其实就是explorer启动了notpad++，操作系统为了速度，直接复制了启动者高位的pml4e给他，导致他的也继承了hook了**  
这太好了，这样子我们的调试器调用NtCreatUserProces创建进程时，也会继承我们的hook  
于是我拷打ai，烹饪出来成品：  
# pte-dbg
效果:   
![img2](https://github.com/Qmeimei10086/pte-dbg/blob/main/img/QQ20260905-005523.png?raw=true "img2")
甚至不需要虚拟化，或者说不能开虚拟化  
因为如果开了虚拟化，会给cr4.cet置位，此时我们就不能开启内核强写了，ptehook也就无法完成  
同时我也支持了附加调试，感觉调试一些反作弊比较弱的游戏还是没问题的  
项目地址：https://github.com/Qmeimei10086/pte-dbg，点个star谢谢喵    




