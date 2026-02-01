---
layout: post
title: "[UniCTF 2026] ezobf-基于rdtsc指令反调试+控制流平坦化+变异aes"
date:       2026-1-29
author: "Qmeimei10086"
header-style: text
tags:
  - CTF
  - 逆向
  - 花指令
  - 平坦化
  - 反调试
  - 混淆
---
# 前言
这题写了快10个小时了，也是挺难的，或许是我太菜了  
# 定位主函数  
通过定位字符串找到主函数，长这样，有点哈人   
![CFG1](https://github.com/Qmeimei10086/qmeimei10086.github.io/blob/main/img/2026-1-29-blog-cfg1.png?raw=true "CFG1")
# 去花
在ida里只看到  
```asm
.text:0000000140008778                 lea     rax, Buffer     ; "wrong"
.text:000000014000877F                 mov     rcx, rax        ; Buffer
.text:0000000140008782                 call    puts
.text:0000000140008787                 mov     [rbp+8F0h+var_944], 0
.text:000000014000878E                 mov     rax, [rbp+8F0h+var_950]
.text:0000000140008792                 xor     al, 0FFh
.text:0000000140008794                 mov     [rbp+8F0h+var_60], rax
.text:000000014000879B                 jmp     loc_140008983   ; jumptable 00000001400019BC case 255
```
字符串列表理由right，但是却没看到？  
往下滑一点发现  
![Flower](https://github.com/Qmeimei10086/qmeimei10086.github.io/blob/main/img/2026-1-29-blog-flower.png?raw=true "Flower")  
由于上面有关retn，而且没有交叉应用关系，ida把他识别为数据了  
按c重建可以看到代码块，但是没有交叉引用挺诡异的，估计是经过一个跳转表过来的  
全部重建后（差不多130个，耐心点）  
![CFG2](https://github.com/Qmeimei10086/qmeimei10086.github.io/blob/main/img/2026-1-29-blog-cfg2.png?raw=true "CFG2")  
明显发现上面那一大串就是真实块，这是一道明显的控制流平坦化问题  
可以先看我之前写的：https://qmeimei10086.github.io/2026/01/19/angr%E7%AC%A6%E5%8F%B7%E6%89%A7%E8%A1%8C%E5%AF%B9%E6%8A%97ollvm/  
# 反调试
在序言下个断点，运行一下发现直接跑飞了？说明是有反调试的  
找了半天没找到beingdebug之类的函数，最后发现了一段大量存在的代码  
```asm
rdtsc
shl     rdx, 20h
or      rax, rdx
nop
mov     [rbp+8F0h+var_68], rax
mov     rax, [rbp+8F0h+var_950]
xor     rax, 0Dh
mov     [rbp+8F0h+var_60], rax
```
上网搜一下发现rdtsc是获取当前时间戳，那就很明显了，大概率是获取当前时间戳然后与开始的相减，通过时间判断是否被调试  
我发现3处是校验时间的  
第一处
```asm
.text:0000000140008983 loc_140008983:          ; jumptable 00000001400019BC case 255
.text:0000000140008983 mov     rax, [rbp+8F0h+var_950]
.text:0000000140008987 xor     rax, [rbp+8F0h+var_60]
.text:000000014000898E cmp     rax, 0FFh
.text:0000000140008994 setnz   al
.text:0000000140008997 test    al, al
.text:0000000140008999 jnz     loc_1400017AE
```
这里发现如果不跳转到loc_1400017AE就会跑到retn的地方，所以这里patch为jmp loc_1400017AE  
第二处  
```asm
.text:00000001400017AE
.text:00000001400017AE loc_1400017AE:
.text:00000001400017AE rdtsc
.text:00000001400017B0 shl     rdx, 20h
.text:00000001400017B4 or      rax, rdx
.text:00000001400017B7 nop
.text:00000001400017B8 sub     rax, [rbp+8F0h+var_70]
.text:00000001400017BF mov     rdx, 1DCD65000h
.text:00000001400017C9 cmp     rdx, rax
.text:00000001400017CC setb    al
.text:00000001400017CF test    al, al
.text:00000001400017D1 jz      short loc_1400017DF
```
这里发现必须要跳转到loc_1400017DF，否则会跑飞，所以也patch为jmp  
第三处  
```asm
.text:00000001400017DF
.text:00000001400017DF loc_1400017DF:
.text:00000001400017DF mov     rax, [rbp+8F0h+var_950]
.text:00000001400017E3 xor     rax, [rbp+8F0h+var_60]
.text:00000001400017EA mov     edx, 0FEEDF00Dh
.text:00000001400017EF cmp     rax, rdx
.text:00000001400017F2 jz      loc_140008960
```
这里发现跳转到loc_140008960会跑飞，所以也patch为nop  
然后生成一个新文件，就可以正常调试了  
# 寻找真实块  
请先阅读我的上一篇博客（  
![CFG3](https://github.com/Qmeimei10086/qmeimei10086.github.io/blob/main/img/2026-1-29-blog-cfg3.png?raw=true "CFG3")   
发现所有的真实块都有一个共同后继0x140008983，所以我们只要找到0x140008983的所有前驱即可  
主要有三种真实块  
![CFG4](https://github.com/Qmeimei10086/qmeimei10086.github.io/blob/main/img/2026-1-29-blog-cfg4.png?raw=true "CFG4")   
第一种我们正常  
![CFG5](https://github.com/Qmeimei10086/qmeimei10086.github.io/blob/main/img/2026-1-29-blog-cfg5.png?raw=true "CFG5") 
第二种我们要找上面那块当真实块地址
![CFG6](https://github.com/Qmeimei10086/qmeimei10086.github.io/blob/main/img/2026-1-29-blog-cfg6.png?raw=true "CFG6") 
第三种要找上面数第二个块  
ida脚本  
```python
import idaapi
import idc


def get_basic_block(ea):
    func = idaapi.get_func(ea)
    if not func:
        return None
    f = idaapi.FlowChart(func) # 获取函数的控制流图
    for block in f:
        if block.start_ea <= ea < block.end_ea:
            return block
    return None
def get_block_size(block):
    return block.end_ea - block.start_ea


def find_all_real_blocks(fun_ea):

    real_blocks_has_branch = []
    real_blocks_has_no_branch = []
    real_blocks_has_no_branch_but_has_pred = []
    blocks = idaapi.FlowChart(idaapi.get_func(fun_ea))
    loop_head_addr= 0x000000140008983
    loop_head_block = get_basic_block(loop_head_addr)
    blocks =  list(loop_head_block.preds())
    for block in blocks:
        size = get_block_size(block)
        if size != 25 and size != 20:
            start_ea = block.start_ea
            if start_ea != 5368715678:
                preds = list(block.preds())
                if len(preds) == 0:
                    real_blocks_has_no_branch.append(start_ea)
                if len(preds) == 1:
                    pred = preds[0]
                    real_blocks_has_branch.append(pred.start_ea)
                if len(preds) == 2:
                    for pred in preds:
                        preds_1 = list(pred.preds())
                        pred_1 = preds_1[0]
                        real_blocks_has_no_branch.append(pred_1.start_ea)
                        real_blocks_has_no_branch_but_has_pred.append(pred_1.start_ea)

    real_blocks_has_branch = list(set(real_blocks_has_branch))
    real_blocks_has_no_branch = list(set(real_blocks_has_no_branch))
    real_blocks_has_no_branch_but_has_pred = list(set(real_blocks_has_no_branch_but_has_pred))
    real_blocks = real_blocks_has_branch + real_blocks_has_no_branch
    
    print("所有有跳转真实块地址真实块地址:", [hex(x) for x in real_blocks_has_branch])
    print("所有无跳转真实块地址真实块地址:", [hex(x) for x in real_blocks_has_no_branch])
    print("所有真实块地址真实块地址:", [hex(x) for x in real_blocks])
    print("所有无跳转但有前驱真实块地址真实块地址:", [hex(x) for x in real_blocks_has_no_branch_but_has_pred])
    print('-----------------------------------------------------------------------------------------')
    print("所有有跳转真实块地址真实块地址:",real_blocks_has_branch)
    print("所有无跳转真实块地址真实块地址:", real_blocks_has_no_branch)
    print("所有真实块地址真实块地址:", real_blocks)
    print("所有无跳转但有前驱真实块地址真实块地址:", real_blocks_has_no_branch_but_has_pred)
    
    
find_all_real_blocks(0x1400016D0)

jmp_table = {
    0x1400065df:0x14000661F,
    0x140006d53:0x140006D93,
    0x140006ad7:0x140006B17,
    0x14000685b:0x14000689B,
}


'''
所有有跳转真实块地址真实块地址: [5368731680, 5368721346, 5368720899, 5368733699, 5368731240, 5368743560, 5368716810, 5368730347, 5368733259, 5368718318, 5368719375, 5368729678, 5368716082, 5368743991, 5368742232, 5368744189, 5368716574]
所有无跳转真实块地址真实块地址: [5368736265, 5368739855, 5368725012, 5368715284, 5368742939, 5368724001, 5368730146, 5368737327, 5368740917, 5368734780, 5368723006, 5368721991, 5368742471, 5368738377, 5368727626, 5368716363, 5368717907, 5368728661, 5368735835, 5368726621, 5368739423, 5368715878, 5368732782, 5368720496, 5368725619, 5368724611, 5368718980, 5368736901, 5368740491, 5368723598, 5368742031, 5368734354, 5368722595, 5368737957, 5368727214, 5368721583, 5368720050, 5368741554, 5368717496, 5368735419, 5368728252, 5368732352, 5368729281, 5368739009, 5368726214, 5368714960, 5368736471, 5368725209, 5368730841, 5368740059, 5368718558, 5368743137, 5368721136, 5368733938, 5368724213, 5368719610, 5368741115, 5368737537, 5368717059, 5368723208, 5368722187, 5368731919, 5368734993, 5368738587, 5368728860, 5368727843, 5368726821, 5368718119, 5368725813, 5368736055, 5368733498, 5368744250, 5368739645, 5368720703, 5368729922, 5368719176, 5368724810, 5368737107, 5368742741, 5368731479, 5368740695, 5368723802, 5368733027, 5368734567, 5368722794, 5368727413, 5368738167, 5368743799, 5368721787, 5368717701, 5368729477, 5368732550, 5368726411, 5368728459, 5368735629, 5368720273, 5368739219, 5368731039, 5368741799, 5368725419, 5368718770, 5368736691, 5368740281, 5368724415, 5368734144, 5368743362, 5368723397, 5368741322, 5368719827, 5368737747, 5368722394, 5368717275, 5368730586, 5368735199, 5368715231, 5368732129, 5368727015, 5368738791, 5368729068, 5368728045, 5368726012]
所有真实块地址真实块地址: [5368731680, 5368721346, 5368720899, 5368733699, 5368731240, 5368743560, 5368716810, 5368730347, 5368733259, 5368718318, 5368719375, 5368729678, 5368716082, 5368743991, 5368742232, 5368744189, 5368716574, 5368736265, 5368739855, 5368725012, 5368715284, 5368742939, 5368724001, 5368730146, 5368737327, 5368740917, 5368734780, 5368723006, 5368721991, 5368742471, 5368738377, 5368727626, 5368716363, 5368717907, 5368728661, 5368735835, 5368726621, 5368739423, 5368715878, 5368732782, 5368720496, 5368725619, 5368724611, 5368718980, 5368736901, 5368740491, 5368723598, 5368742031, 5368734354, 5368722595, 5368737957, 5368727214, 5368721583, 5368720050, 5368741554, 5368717496, 5368735419, 5368728252, 5368732352, 5368729281, 5368739009, 5368726214, 5368714960, 5368736471, 5368725209, 5368730841, 5368740059, 5368718558, 5368743137, 5368721136, 5368733938, 5368724213, 5368719610, 5368741115, 5368737537, 5368717059, 5368723208, 5368722187, 5368731919, 5368734993, 5368738587, 5368728860, 5368727843, 5368726821, 5368718119, 5368725813, 5368736055, 5368733498, 5368744250, 5368739645, 5368720703, 5368729922, 5368719176, 5368724810, 5368737107, 5368742741, 5368731479, 5368740695, 5368723802, 5368733027, 5368734567, 5368722794, 5368727413, 5368738167, 5368743799, 5368721787, 5368717701, 5368729477, 5368732550, 5368726411, 5368728459, 5368735629, 5368720273, 5368739219, 5368731039, 5368741799, 5368725419, 5368718770, 5368736691, 5368740281, 5368724415, 5368734144, 5368743362, 5368723397, 5368741322, 5368719827, 5368737747, 5368722394, 5368717275, 5368730586, 5368735199, 5368715231, 5368732129, 5368727015, 5368738791, 5368729068, 5368728045, 5368726012]
所有无跳转但有前驱真实块地址真实块地址: [5368735199, 5368737107, 5368715284, 5368736471, 5368735835, 5368715231]
'''
```
有两个不在idacfg里不在上面的，但是脚本会输出，我们把他剔除掉（但是我忘了哪一个OwO），这些是分发器，不过也不影响后面  
# 重建控制流  
我们先做过小实验,在ida里试一下执行到个块是否是不依赖除了前驱块的快执行结果的    
```python
import idaapi
import ida_dbg
import ida_bytes
import idc
import ida_ua


i = 0
real_blocks: list[int] =[5368720899, 5368733699, 5368736265, 5368716810, 5368719375, 5368739855, 5368725012, 5368742939, 5368731680, 5368724001, 5368730146, 5368737327, 5368740917, 5368743991, 5368734780, 5368723006, 5368721991, 5368742471, 5368738377, 5368727626, 5368716363, 5368733259, 5368729678, 5368717907, 5368728661, 5368735835, 5368726621, 5368739423, 5368715878, 5368731240, 5368732782, 5368720496, 5368725619, 5368724611, 5368718980, 5368736901, 5368743560, 5368740491, 5368723598, 5368742031, 5368734354, 5368722595, 5368737957, 5368727214, 5368721583, 5368720050, 5368741554, 5368717496, 5368735419, 5368728252, 5368732352, 5368729281, 5368739009, 5368726214, 5368714960, 5368736471, 5368725209, 5368730841, 5368740059, 5368718558, 5368743137, 5368730347, 5368721136, 5368733938, 5368724213, 5368719610, 5368741115, 5368744189, 5368737537, 5368717059, 5368723208, 5368722187, 5368731919, 5368734993, 5368738587, 5368728860, 5368716574, 5368727843, 5368726821, 5368718119, 5368716082, 5368725813, 5368736055, 5368733498, 5368744250, 5368739645, 5368720703, 5368729922, 5368719176, 5368724810, 5368737107, 5368742741, 5368731479, 5368740695, 5368742232, 5368723802, 5368733027, 5368734567, 5368722794, 5368727413, 5368738167, 5368743799, 5368721787, 5368717701, 5368729477, 5368732550, 5368726411, 5368728459, 5368735629, 5368720273, 5368739219, 5368731039, 5368741799, 5368725419, 5368718770, 5368736691, 5368740281, 5368724415, 5368734144, 5368721346, 5368743362, 5368723397, 5368741322, 5368719827, 5368737747, 5368722394, 5368717275, 5368730586, 5368735199, 5368732129, 5368727015, 5368738791, 5368729068, 5368728045, 5368718318, 5368726012]

addr_list = []

def add_breakpoint():
    # Anti-debug bypass breakpoints
    # ida_dbg.add_bpt(0x1400017D1)
    # ida_dbg.add_bpt(0x1400017F2)
    # ida_dbg.add_bpt(0x140008999)
    print("Anti-debug breakpoints set at 0x1400017D1, 0x1400017F2")

    for addr in real_blocks:
        insn = ida_ua.insn_t()
        next_ea = idc.next_head(addr)
        ida_dbg.add_bpt(next_ea)
        addr_list.append(next_ea)
        print(f"Breakpoint set at {hex(next_ea)}")


import ida_ua
import ida_idp
import ida_allins

# 日志文件路径
LOG_FILE = r"d:\reverse\MCP\ida_trace_log.txt"

# 清空/初始化日志
with open(LOG_FILE, "w") as f:
    f.write("IDA Trace Log Started\n")

def log_current_block(start_ea):
    """
    反汇编当前块直到遇到控制流改变指令
    """
    with open(LOG_FILE, "a") as f:
        f.write(f"\n------------------------------------------------\n")
        f.write(f"Block Execution: {hex(start_ea)}\n")
        
        curr = start_ea
        # 防止无限循环，设置最大指令数
        for _ in range(200):
            # 获取反汇编文本
            disasm = idc.generate_disasm_line(curr, 0)
            f.write(f"{hex(curr)}: {disasm}\n")
            
            # 解码指令判断是否结束
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, curr) == 0:
                break
                
            # 常见的块结束指令类型
            # 注意: call 一般不算块结束，但在某些流图中算。OLLVM平坦化里通常遇到 jmp/jcc 就结束了
            if ida_idp.is_ret_insn(insn) or \
               ida_idp.is_indirect_jump_insn(insn) or \
               (insn.itype == ida_allins.NN_jmp) or \
               (insn.itype >= ida_allins.NN_ja and insn.itype <= ida_allins.NN_jz):
                break
                
            curr = idc.next_head(curr)

class hook_all_opecode(ida_dbg.DBG_Hooks):

    def dbg_bpt(self, tid, ea):
        # if ea == 0x1400017D1:
        #     print(f"Hit 0x1400017D1, Force ZF=1")
        #     ida_dbg.set_reg_val("ZF", 1)
        #     ida_dbg.request_continue_process()
        #     return 0
        # if ea == 0x1400017F2:
        #     print(f"Hit 0x1400017F2, Force ZF=0")
        #     ida_dbg.set_reg_val("ZF", 0)
        #     ida_dbg.request_continue_process()
        #     return 0
        # if ea == 0x140008999:
        #     print(f"Hit 0x140008999, Force ZF=0")
        #     ida_dbg.set_reg_val("ZF", 0)
        #     ida_dbg.request_continue_process()
        #     return 0

        
        for addr in addr_list:
            if ea == addr:
                global i
                print(f"Hit breakpoint at {hex(ea)} - Real block #{i}")
                
                # 记录块汇编到文件
                log_current_block(ea)
                
                i+=1
        
        
        
        return 0
def install_hook():
    # 清理旧的 hook (如果存在于全局变量中)
    global my_hook
    try:
        if 'my_hook' in globals():
            my_hook.unhook()
            print("Removed old hook")
    except:
        pass

    # 安装新的 hook
    my_hook = hook_all_opecode()
    my_hook.hook()
    print("Hook installed. Please set the breakpoint manually.")


install_hook()
add_breakpoint()

```
在序言尾下个断点，运行，然后强制rip设置为一个块的的首地址，然后按f9，而且发现每次到哪个块是相同的  
而且我们发现输出please input flag的下一个块有fget函数，这很符合逻辑  
这里提一嘴，rdtsc指令好像断不下来，所以我都是设置他的下一个指令  
对应第二种块，我们发现我们修改jz/jnz指令时的zf寄存器，到达的块时不同的，所以这是条件跳转相关的，待会模拟执行时候要分裂处理  
对应第三种，我们发现怎么改jz/jnz，虽然会到不同的代码，但是到的下一个块都是一样的所以和第一种一样  
# 模拟执行
我拷打ai写了两个unicorn模拟执行的脚本，思路参考angr那一篇，主要都是为了找后继  
遇到会分裂的，手动分裂两种情况去执行  
```python
import unicorn
from unicorn import *
from unicorn.x86_const import *
import pefile
import sys
import struct

# Configuration
EXE_PATH = "D:\\reverse\\MCP\\ezobf1.exe"
STACK_BASE = 0x00100000
STACK_SIZE = 0x00200000

# Constants from analysis
PROLOGUE_START = 0x1400016D0
PROLOGUE_END = 0x1400017A9

# Lists from hook_rebuild_by_ida.py
real_blocks_has_branch = [5368731680, 5368721346, 5368720899, 5368733699, 5368731240, 5368743560, 5368716810, 5368730347, 5368733259, 5368718318, 5368719375, 5368729678, 5368716082, 5368743991, 5368742232, 5368744189, 5368716574]
real_blocks_has_no_branch = [5368736265, 5368739855, 5368725012, 5368742939, 5368724001, 5368730146, 5368737327, 5368740917, 5368734780, 5368723006, 5368721991, 5368742471, 5368738377, 5368727626, 5368716363, 5368717907, 5368728661, 5368735835, 5368726621, 5368739423, 5368715878, 5368732782, 5368720496, 5368725619, 5368724611, 5368718980, 5368736901, 5368740491, 5368723598, 5368742031, 5368734354, 5368722595, 5368737957, 5368727214, 5368721583, 5368720050, 5368741554, 5368717496, 5368735419, 5368728252, 5368732352, 5368729281, 5368739009, 5368726214, 5368714960, 5368736471, 5368725209, 5368730841, 5368740059, 5368718558, 5368743137, 5368721136, 5368733938, 5368724213, 5368719610, 5368741115, 5368737537, 5368717059, 5368723208, 5368722187, 5368731919, 5368734993, 5368738587, 5368728860, 5368727843, 5368726821, 5368718119, 5368725813, 5368736055, 5368733498, 5368744250, 5368739645, 5368720703, 5368729922, 5368719176, 5368724810, 5368737107, 5368742741, 5368731479, 5368740695, 5368723802, 5368733027, 5368734567, 5368722794, 5368727413, 5368738167, 5368743799, 5368721787, 5368717701, 5368729477, 5368732550, 5368726411, 5368728459, 5368735629, 5368720273, 5368739219, 5368731039, 5368741799, 5368725419, 5368718770, 5368736691, 5368740281, 5368724415, 5368734144, 5368743362, 5368723397, 5368741322, 5368719827, 5368737747, 5368722394, 5368717275, 5368730586, 5368735199, 5368732129, 5368727015, 5368738791, 5368729068, 5368728045, 5368726012]

all_real_block = real_blocks_has_branch + real_blocks_has_no_branch

# Helpers
all_real_block_set = set(all_real_block)
found_successor = {}

def load_pe(uc):
    try:
        pe = pefile.PE(EXE_PATH)
    except Exception as e:
        print(f"Error loading PE: {e}")
        sys.exit(1)

    image_base = pe.OPTIONAL_HEADER.ImageBase
    # Align size up to 4KB
    header_size = (pe.OPTIONAL_HEADER.SizeOfHeaders + 0xFFF) & ~0xFFF
    uc.mem_map(image_base, header_size)
    uc.mem_write(image_base, pe.header)
    
    max_addr = image_base + header_size
    
    for section in pe.sections:
        va = section.VirtualAddress
        vsize = section.Misc_VirtualSize
        data = section.get_data()
        
        map_addr = image_base + va
        map_start = map_addr & ~0xFFF
        map_end = (map_addr + vsize + 0xFFF) & ~0xFFF
        
        if map_end > max_addr:
             addr_to_map = max(map_start, max_addr)
             size_to_map = map_end - addr_to_map
             if size_to_map > 0:
                 uc.mem_map(addr_to_map, size_to_map)
                 max_addr = map_end
        
        uc.mem_write(image_base + va, data)

try:
    from capstone import *
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    def disassemble(code, address):
        for i in cs.disasm(code, address):
            return f"{i.mnemonic}\t{i.op_str}"
        return ""
except ImportError:
    def disassemble(code, address):
        return code.hex()

def hook_code_verbose(uc, address, size):
    try:
        code = uc.mem_read(address, size)
        asm = disassemble(code, address)
        print(f"0x{address:x}: {asm}")
    except:
        print(f"0x{address:x}: ???")

def hook_code(uc, address, size, user_data):
    # hook_code_verbose(uc, address, size)
    try:
        code = uc.mem_read(address, 2)
        if code[0] == 0xE8: # call relative
            # Calculate target address
            offset = struct.unpack("<i", uc.mem_read(address + 1, 4))[0]
            target = address + 5 + offset
            
            # Check if target matches sub_140008A67 or sub_14000A090
            # 0x140008A67: Initialization check
            # 0x14000A090: printf/vfprintf
            if target == 0x140008A67 or target == 0x14000A090:
                 # print(f"Skipping CALL to {hex(target)} at {hex(address)}")
                 uc.reg_write(UC_X86_REG_RAX, 1) # Return success/1
                 uc.reg_write(UC_X86_REG_RIP, address + 5)
            
        elif code[0] == 0xFF and code[1] == 0x15: # call qword ptr [rip+disp] (imports)
            # print(f"Skipping CALL FF 15 at {hex(address)}")
            uc.reg_write(UC_X86_REG_RAX, 1)
            uc.reg_write(UC_X86_REG_RIP, address + 6)
        # RET handling removed to allow execution to continue via stack manipulation jumps

    except Exception:
        pass

def hook_mem_invalid(uc, access, address, size, value, user_data):
    # Simply map memory to allow execution to continue
    # print(f"Invalid access at {hex(address)}")
    page_start = address & ~0xFFF
    try:
        uc.mem_map(page_start, 0x1000)
        return True
    except Exception as e:
        # print(f"Map fail: {e}")
        return False

def hook_block(uc, address, size, user_data):
        found = None
        if address in all_real_block_set:
            found = address
        elif (address - 1) in all_real_block_set:
            found = address - 1
            
        if found:
            if found != user_data['current_start']:
                print(f"Successor found: {hex(user_data['current_start'])} -> {hex(found)}")
                found_successor[user_data['current_start']] = found
                uc.emu_stop()

def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    
    # 1. Load PE
    load_pe(uc)
    
    # 2. Setup Stack
    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.reg_write(UC_X86_REG_RSP, STACK_BASE + STACK_SIZE - 0x1000)

    # Hook Invalid Memory
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_invalid)
    
    # 3. Save Initial State at Prologue Head
    # Run from entry? No, just manually set RIP to PROLOGUE_START and save context
    # Assuming PE is loaded correctly, registers are 0/defaults. 
    # Important: RSP is set.
    uc.reg_write(UC_X86_REG_RIP, PROLOGUE_START)
    
    # We might need to map a fake input flag if the code accesses it?
    # Based on solve_unicorn.py, there is FAKE_INPUT but it seems used later.
    # The prologue usually just does register saving.
    
    initial_context = uc.context_save()
    
    print("Starting search...")
    
    for block_addr in real_blocks_has_no_branch:
        # print(f"Checking {hex(block_addr)}")
        # a. Restore context
        uc.context_restore(initial_context)
        
        # Special handling for Prologue Start as per request
        if block_addr == PROLOGUE_START:
            # Just run it. It will hit end and go somewhere.
            # We hook blocks to see where it lands.
            user_data = {'current_start': block_addr}
            h = uc.hook_add(UC_HOOK_BLOCK, hook_block, user_data)
            h_code = uc.hook_add(UC_HOOK_CODE, hook_code, user_data)
            try:
                # We expect it to leave prologue and hit a real block
                uc.emu_start(PROLOGUE_START, -1, 0, 500) 
            except UcError:
                pass
            uc.hook_del(h)
            uc.hook_del(h_code)
            
            if block_addr not in found_successor:
                print(f"[-] No successor found for block {hex(block_addr)}")
            continue
            
        # b. Execute to prologue tail
        # We run from Start to End.
        try:
            h_code = uc.hook_add(UC_HOOK_CODE, hook_code, None)
            uc.emu_start(PROLOGUE_START, PROLOGUE_END)
            uc.hook_del(h_code)
            # print(f"RBP after prologue: {hex(uc.reg_read(UC_X86_REG_RBP))}")
        except UcError as e:
            print(f"Error running prologue: {e}")
            try:
                uc.hook_del(h_code)
            except:
                pass
            continue
            
        # c. Force Jump to current block
        uc.reg_write(UC_X86_REG_RIP, block_addr)
        
        # d. Simulate
        user_data = {'current_start': block_addr}
        h = uc.hook_add(UC_HOOK_BLOCK, hook_block, user_data)
        h_code = uc.hook_add(UC_HOOK_CODE, hook_code, user_data)
        
        try:
            # Run for a limited number of instructions to find next block
            # timeout=0 (infinite), count=50000 to prevent infinite loops
            uc.emu_start(block_addr, -1, 0, 50000)
        except UcError as e:
            # print(f"Error emulating block {hex(block_addr)}: {e}")
            pass
            
        uc.hook_del(h)
        uc.hook_del(h_code)

        if block_addr not in found_successor:
            print(f"[-] No successor found for block {hex(block_addr)}")

    print("Done.")

if __name__ == "__main__":
    main()

```
这是寻找直接跳转的，下一个时寻找条件跳转的  
```python
import sys
import struct
import re
from unicorn import *
from unicorn.x86_const import *
from capstone import *

# Ensure we can import from current directory
sys.path.append('d:\\reverse\\MCP')

try:
    from find_succeed import load_pe, all_real_block, real_blocks_has_no_branch, hook_mem_invalid, hook_code as hook_code_base, PROLOGUE_START, PROLOGUE_END, STACK_BASE, STACK_SIZE
except ImportError as e:
    print(f"Error importing from find_succeed.py: {e}")
    sys.exit(1)

# Derive branch blocks: All Real Blocks - No-Branch Blocks
# We must use set operations
# real_blocks_has_branch = sorted(list(set(all_real_block) - set(real_blocks_has_no_branch)))
real_blocks_has_branch =  [5368731680, 5368721346, 5368720899, 5368733699, 5368731240, 5368743560, 5368716810, 5368730347, 5368733259, 5368718318, 5368719375, 5368729678, 5368716082, 5368743991, 5368742232, 5368744189, 5368716574]
real_blocks_has_branch = sorted(real_blocks_has_branch)

all_real_block_set = set(all_real_block)

def get_mnemonic(uc, address):
    try:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        code = uc.mem_read(address, 15)
        for i in md.disasm(code, address):
            return i.mnemonic
    except:
        return ""

# Wrapper to reuse hook_code logic or just duplicat it to be safe
def hook_code_skip(uc, address, size, user_data):
    # Reuse the logic from find_succeed but avoiding dependency on its globals if any
    try:
        code = uc.mem_read(address, 2)
        if code[0] == 0xE8: # call relative
             offset = struct.unpack("<i", uc.mem_read(address + 1, 4))[0]
             target = address + 5 + offset
             if target == 0x140008A67 or target == 0x14000A090:
                 uc.reg_write(UC_X86_REG_RAX, 1) # Return success/1
                 uc.reg_write(UC_X86_REG_RIP, address + 5)
        elif code[0] == 0xFF and code[1] == 0x15: # call qword ptr [rip+disp] (imports)
            uc.reg_write(UC_X86_REG_RAX, 1)
            uc.reg_write(UC_X86_REG_RIP, address + 6)
    except:
        pass

def hook_find_jcc(uc, address, size, user_data):
    # 1. Skip calls logic first
    hook_code_skip(uc, address, size, user_data)
    
    # Check if we already skipped (RIP changed) - but UC hooks run before execution. Use memory check?
    # Usually hook code runs, then instruction executes. If hook modifies RIP, execution continues at new RIP?
    # Unicorn documentation says hook runs BEFORE instruction.
    # If we change RIP, we effectively skip ONLY IF we stop or if Unicorn handles it immediately.
    # With uc.reg_write(RIP, new), the current instruction is NOT skipped unless we stop or return?
    # Actually, changing RIP in hook causes execution to resume at new RIP *after* the hook returns? 
    # Whatever find_succeed.py did worked. It modified RIP.
    
    # We should detect if it's a call before disassembly JCC.
    # The code looks fine.

    # 2. Check JCC
    mnemonic = get_mnemonic(uc, address)
    if mnemonic.startswith('j') and mnemonic != 'jmp':
        user_data['jcc_addr'] = address
        user_data['mnemonic'] = mnemonic
        uc.emu_stop()

def hook_block_succ(uc, address, size, user_data):
    # Fuzzy match buffer
    found = None
    if address in all_real_block_set:
        found = address
    elif (address - 1) in all_real_block_set:
        found = address - 1
        
    if found:
        user_data['succ'] = found
        uc.emu_stop()

def find_jcc_by_disasm(uc, block_addr, max_ins=80, max_bytes=0x300):
    try:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        code = uc.mem_read(block_addr, max_bytes)
        count = 0
        for insn in md.disasm(code, block_addr):
            if insn.address != block_addr and insn.address in all_real_block_set:
                break
            if insn.mnemonic.startswith('j') and insn.mnemonic != 'jmp':
                return insn.address
            count += 1
            if count >= max_ins:
                break
    except:
        return None
    return None

def set_flags_for_cond(existing_flags, mnemonic, take_true):
    ZF = 1 << 6
    SF = 1 << 7
    OF = 1 << 11
    flags = existing_flags & ~(ZF | SF | OF)

    if mnemonic in ("jz", "je"):
        if take_true:
            flags |= ZF
    elif mnemonic in ("jnz", "jne"):
        if not take_true:
            flags |= ZF
    elif mnemonic in ("jg", "jnle"):
        if take_true:
            # ZF=0 and SF==OF -> choose SF=0, OF=0
            pass
        else:
            flags |= ZF
    elif mnemonic in ("jge", "jnl"):
        if take_true:
            # SF==OF -> choose SF=0, OF=0
            pass
        else:
            # SF!=OF
            flags |= SF
    elif mnemonic in ("jl", "jnge"):
        if take_true:
            # SF!=OF
            flags |= SF
        else:
            # SF==OF -> choose SF=0, OF=0
            pass
    elif mnemonic in ("jle", "jng"):
        if take_true:
            # ZF=1 satisfies condition
            flags |= ZF
        else:
            # ZF=0 and SF==OF -> choose SF=0, OF=0
            pass
    else:
        # Fallback to ZF-only split
        if take_true:
            flags |= ZF

    return flags

def main():
    print(f"Checking {len(real_blocks_has_branch)} blocks with branches...")
    
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    # Load PE
    load_pe(uc)
    # Setup Stack
    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.reg_write(UC_X86_REG_RSP, STACK_BASE + STACK_SIZE - 0x1000)
    # Handle unmapped
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_invalid)

    # 1. Run Prologue to get initial state
    print("Running prologue...")
    uc.reg_write(UC_X86_REG_RIP, PROLOGUE_START)
    try:
        # We use a code hook to skip calls in prologue too
        h_skip = uc.hook_add(UC_HOOK_CODE, hook_code_skip)
        uc.emu_start(PROLOGUE_START, PROLOGUE_END, 0, 50000)
        uc.hook_del(h_skip)
    except UcError as e:
        print(f"Error running prologue: {e}")
    
    # Save the 'ready' context
    ctx_ready = uc.context_save()
    
    simple_successors = {} # Unconditional
    cond_successors = {}   # Conditional
    cond_mnemonic = {}     # Conditional mnemonic

    # 0. Load trace
    try:
        with open(r"d:\reverse\MCP\trace_final.txt", "r", encoding="utf-16") as f:
            for line in f:
                m = re.search(r"Successor found: (0x[0-9a-fA-F]+) -> (0x[0-9a-fA-F]+)", line)
                if m:
                    simple_successors[int(m.group(1), 16)] = int(m.group(2), 16)
    except Exception as e:
        print(f"Warning load trace: {e}")

    print("Starting branch simulation...")
    
    for block_addr in real_blocks_has_branch:
        # 2. Restore state and run to find JCC
        uc.context_restore(ctx_ready)
        uc.reg_write(UC_X86_REG_RIP, block_addr)

        user_data = {'jcc_addr': None, 'mnemonic': ''}
        h_jcc = uc.hook_add(UC_HOOK_CODE, hook_find_jcc, user_data)

        try:
            # Run enough instructions to find the jump in the block
            uc.emu_start(block_addr, -1, 0, 5000)
        except UcError:
            pass
        uc.hook_del(h_jcc)

        jcc_addr = user_data['jcc_addr']
        jcc_mnemonic = user_data['mnemonic']
        if jcc_addr is None:
            # Fallback: try linear disassembly to locate JCC
            jcc_addr = find_jcc_by_disasm(uc, block_addr)
            if jcc_addr is not None:
                jcc_mnemonic = get_mnemonic(uc, jcc_addr)
        if jcc_addr is None:
            print(f"Warning: No JCC found in block {hex(block_addr)}")
            # Might be a RET block that ended up in the list, or implicit fallthrough?
            if block_addr == 0x140008837:
                cond_successors[block_addr] = (0x14000893A, 0x140008777)
                cond_mnemonic[block_addr] = "jnz"
            else:
                cond_successors[block_addr] = (None, None)
            continue

        # Ensure RIP is at JCC for a consistent split
        uc.reg_write(UC_X86_REG_RIP, jcc_addr)
        ctx_at_jcc = uc.context_save()
        existing_flags = uc.reg_read(UC_X86_REG_EFLAGS)
        
        # 3. Path TRUE (Left)
        uc.context_restore(ctx_at_jcc)
        uc.reg_write(UC_X86_REG_EFLAGS, set_flags_for_cond(existing_flags, jcc_mnemonic, True))
        
        ud_left = {'succ': None}
        h_succ = uc.hook_add(UC_HOOK_BLOCK, hook_block_succ, ud_left)
        h_skip = uc.hook_add(UC_HOOK_CODE, hook_code_skip)
        try:
            # Execute step (jump triggers) + run
            uc.emu_start(jcc_addr, -1, 0, 50000)
        except: pass
        uc.hook_del(h_succ)
        uc.hook_del(h_skip)
        
        # 4. Path FALSE (Right)
        uc.context_restore(ctx_at_jcc)
        uc.reg_write(UC_X86_REG_EFLAGS, set_flags_for_cond(existing_flags, jcc_mnemonic, False))
        
        ud_right = {'succ': None}
        h_succ = uc.hook_add(UC_HOOK_BLOCK, hook_block_succ, ud_right)
        h_skip = uc.hook_add(UC_HOOK_CODE, hook_code_skip)
        try:
            uc.emu_start(jcc_addr, -1, 0, 50000)
        except: pass
        uc.hook_del(h_succ)
        uc.hook_del(h_skip)
        
        left_val = ud_left['succ']
        right_val = ud_right['succ']

        if block_addr == 0x140008837 and left_val is None and right_val is None:
            left_val = 0x14000893A
            right_val = 0x140008777
        
        if left_val is None and right_val is None:
            cond_successors[block_addr] = (None, None)
            cond_mnemonic[block_addr] = jcc_mnemonic
            continue
            
        l_str = left_val if left_val else 0
        r_str = right_val if right_val else 0
        cond_successors[block_addr] = (l_str, r_str)
        cond_mnemonic[block_addr] = jcc_mnemonic

    # OUTPUT
    print("flow_patch = {")
    for k in sorted(simple_successors.keys()):
        v = simple_successors[k]
        print(f"    {hex(k)}: {hex(v)},")
    print("}")
    
    print("\nbranch_patch = {")
    for k in sorted(cond_successors.keys()):
        v = cond_successors[k]
        if v[0] is None and v[1] is None:
            print(f"    {hex(k)}: None,")
            continue
        l_str = hex(v[0]) if v[0] else "None"
        r_str = hex(v[1]) if v[1] else "None"
        print(f"    {hex(k)}: ({l_str}, {r_str}), # (Left:Cond=True, Right:Cond=False)")
    print("}")

    missing_successors = {k: None for k, v in cond_successors.items() if v[0] is None or v[1] is None}
    print("\nmissing_successors = {")
    for k in sorted(missing_successors.keys()):
        print(f"    {hex(k)}: None,")
    print("}")

    mnem_jz = ("jz", "je")
    mnem_jnz = ("jnz", "jne")
    mnem_jle = ("jle", "jng", "jl", "jnge")
    mnem_jg = ("jg", "jnle", "jge", "jnl")
    
    patch_jz = {k: cond_successors[k] for k, m in cond_mnemonic.items() if m in mnem_jz}
    patch_jnz = {k: cond_successors[k] for k, m in cond_mnemonic.items() if m in mnem_jnz}
    patch_jle = {k: cond_successors[k] for k, m in cond_mnemonic.items() if m in mnem_jle}
    patch_jg = {k: cond_successors[k] for k, m in cond_mnemonic.items() if m in mnem_jg}

    def print_patch_dict(name, d):
        print(f"\n{name} = " + "{")
        for k in sorted(d.keys()):
            v = d[k]
            l_str = hex(v[0]) if v[0] else "None"
            r_str = hex(v[1]) if v[1] else "None"
            print(f"    {hex(k)}: ({l_str}, {r_str}),")
        print("}")

    print_patch_dict("patch_jz", patch_jz)
    print_patch_dict("patch_jnz", patch_jnz)
    print_patch_dict("patch_jle", patch_jle)
    print_patch_dict("patch_jg", patch_jg)

if __name__ == "__main__":
    main()
```
运行下面那个就行，结果  
```python
Checking 17 blocks with branches...
Running prologue...
Starting branch simulation...
flow_patch = {
    0x1400016d0: 0x140001a66,
    0x140001a66: 0x140001b32,
    0x140001f03: 0x140001fdb,
    0x1400020b8: 0x140002185,
    0x140002185: 0x140002253,
    0x140002253: 0x140002327,
    0x140002327: 0x1400023ee,
    0x1400024de: 0x1400025b2,
    0x1400025b2: 0x140002684,
    0x140002684: 0x1400023ee,
    0x140002748: 0x14000280f,
    0x1400028fa: 0x1400029d3,
    0x1400029d3: 0x140002ab2,
    0x140002ab2: 0x140002b91,
    0x140002b91: 0x140002c70,
    0x140002c70: 0x140002d3f,
    0x140002d3f: 0x14000280f,
    0x140002ef0: 0x140002fc2,
    0x1400030af: 0x14000317b,
    0x14000317b: 0x140003247,
    0x140003247: 0x14000330b,
    0x14000330b: 0x1400033da,
    0x1400033da: 0x1400034a3,
    0x1400034a3: 0x14000356a,
    0x14000356a: 0x14000363e,
    0x14000363e: 0x140003708,
    0x140003708: 0x1400037c5,
    0x1400037c5: 0x14000388e,
    0x14000388e: 0x14000395a,
    0x14000395a: 0x140003a21,
    0x140003a21: 0x140003af5,
    0x140003af5: 0x140003bbf,
    0x140003bbf: 0x140003c83,
    0x140003c83: 0x140003d4a,
    0x140003d4a: 0x140003e14,
    0x140003e14: 0x140003ed9,
    0x140003ed9: 0x140003fab,
    0x140003fab: 0x140004073,
    0x140004073: 0x140004135,
    0x140004135: 0x1400041fc,
    0x1400041fc: 0x1400042c6,
    0x1400042c6: 0x14000438b,
    0x14000438b: 0x14000445d,
    0x14000445d: 0x140004525,
    0x140004525: 0x1400045e7,
    0x1400045e7: 0x1400046ae,
    0x1400046ae: 0x140004775,
    0x140004775: 0x14000484a,
    0x14000484a: 0x140004923,
    0x140004923: 0x1400049ed,
    0x1400049ed: 0x140004abc,
    0x140004abc: 0x140004b8b,
    0x140004b8b: 0x140004c55,
    0x140004c55: 0x140004d1c,
    0x140004d1c: 0x140004dec,
    0x140004dec: 0x140004ec1,
    0x140004ec1: 0x140002e03,
    0x140004f85: 0x14000504e,
    0x140005142: 0x140005222,
    0x140005222: 0x1400052eb,
    0x1400053da: 0x1400054d9,
    0x1400054d9: 0x1400052eb,
    0x14000559f: 0x140005668,
    0x140005757: 0x140005820,
    0x14000590f: 0x1400059e1,
    0x1400059e1: 0x140005ac0,
    0x140005ac0: 0x140005820,
    0x140005b86: 0x140005c6e,
    0x140005c6e: 0x140005d63,
    0x140005d63: 0x140005e4b,
    0x140005f3a: 0x140006003,
    0x1400060f2: 0x1400061c0,
    0x1400061c0: 0x140006292,
    0x140006292: 0x140006367,
    0x140006367: 0x14000643c,
    0x14000643c: 0x140006511,
    0x140006511: 0x1400065df,
    0x1400065df: 0x1400066bb,
    0x1400066bb: 0x14000678d,
    0x14000678d: 0x14000685b,
    0x14000685b: 0x140006937,
    0x140006937: 0x140006a09,
    0x140006a09: 0x140006ad7,
    0x140006ad7: 0x140006bb3,
    0x140006bb3: 0x140006c85,
    0x140006c85: 0x140006d53,
    0x140006d53: 0x140006e2f,
    0x140006e2f: 0x140006f01,
    0x140006f01: 0x140006fd3,
    0x140006fd3: 0x1400070a5,
    0x1400070a5: 0x140007177,
    0x140007177: 0x140007249,
    0x140007249: 0x14000731b,
    0x14000731b: 0x1400073e7,
    0x1400073e7: 0x1400074c1,
    0x1400074c1: 0x140007593,
    0x140007593: 0x14000765f,
    0x14000765f: 0x14000773d,
    0x14000773d: 0x14000780f,
    0x14000780f: 0x1400078db,
    0x1400078db: 0x1400079b9,
    0x1400079b9: 0x140007a8b,
    0x140007a8b: 0x140007b57,
    0x140007b57: 0x140007c35,
    0x140007c35: 0x140006003,
    0x140007cfb: 0x140007dca,
    0x140007dca: 0x140007eb2,
    0x140007eb2: 0x140007fa7,
    0x140007fa7: 0x14000808f,
    0x14000808f: 0x140008158,
    0x140008247: 0x140008355,
    0x140008355: 0x140008158,
    0x14000841b: 0x140005668,
    0x1400084e1: 0x1400085c2,
    0x1400085c2: 0x14000504e,
}

branch_patch = {
    0x140001b32: (0x140001c4b, None), # (Left:Cond=True, Right:Cond=False)
    0x140001d1e: (0x140001fdb, 0x140001e0a), # (Left:Cond=True, Right:Cond=False)
    0x140001e0a: (0x140001fdb, 0x140001f03), # (Left:Cond=True, Right:Cond=False)
    0x1400023ee: (0x140002748, 0x1400024de), # (Left:Cond=True, Right:Cond=False)
    0x14000280f: (0x140002e03, 0x1400028fa), # (Left:Cond=True, Right:Cond=False)
    0x140002e03: (0x140004f85, 0x140002ef0), # (Left:Cond=True, Right:Cond=False)
    0x140002fc2: (0x140004d1c, 0x1400030af), # (Left:Cond=True, Right:Cond=False)
    0x14000504e: (0x140008688, 0x140005142), # (Left:Cond=True, Right:Cond=False)
    0x1400052eb: (0x14000559f, 0x1400053da), # (Left:Cond=True, Right:Cond=False)
    0x140005668: (0x1400084e1, 0x140005757), # (Left:Cond=True, Right:Cond=False)
    0x140005820: (0x140005b86, 0x14000590f), # (Left:Cond=True, Right:Cond=False)
    0x140005e4b: (0x140007dca, 0x140005f3a), # (Left:Cond=True, Right:Cond=False)
    0x140006003: (0x140007cfb, 0x1400060f2), # (Left:Cond=True, Right:Cond=False)
    0x140008158: (0x14000841b, 0x140008247), # (Left:Cond=True, Right:Cond=False)
    0x140008688: (0x140008837, 0x140008777), # (Left:Cond=True, Right:Cond=False)
    0x140008837: (0x140008777, 0x14000893a), # (Left:Cond=True, Right:Cond=False)
    0x1400088fd: (0x14000893a, None), # (Left:Cond=True, Right:Cond=False)
}

missing_successors = {
}

patch_jz = {
    0x140001b32: (0x140001c4b, None),
    0x140001d1e: (0x140001fdb, 0x140001e0a),
    0x140008688: (0x140008837, 0x140008777),
    0x1400088fd: (0x14000893a, None),
}

patch_jnz = {
    0x140001e0a: (0x140001fdb, 0x140001f03),
    0x140002fc2: (0x140004d1c, 0x1400030af),
    0x140008837: (0x140008777, 0x14000893a),
}

patch_jle = {
}

patch_jg = {
    0x1400023ee: (0x140002748, 0x1400024de),
    0x14000280f: (0x140002e03, 0x1400028fa),
    0x140002e03: (0x140004f85, 0x140002ef0),
    0x14000504e: (0x140008688, 0x140005142),
    0x1400052eb: (0x14000559f, 0x1400053da),
    0x140005668: (0x1400084e1, 0x140005757),
    0x140005820: (0x140005b86, 0x14000590f),
    0x140005e4b: (0x140007dca, 0x140005f3a),
    0x140006003: (0x140007cfb, 0x1400060f2),
    0x140008158: (0x14000841b, 0x140008247),
}
```
对应jz/jnz/jg/jle这种，我把条件成立的放左边，条件不成立的放右边  
然后我拷打ai，叫他根据dfs画一个图  
![CFG7](https://github.com/Qmeimei10086/qmeimei10086.github.io/blob/main/img/2026-1-29-blog-cfg7.png?raw=true "CFG7")
挺好看的哈，不过没什么用说是  
# 重建控制流
和angr那篇差不多，单后继patch为jmp。双后继为jz/jnz/jg/jle xxx ;jmp xxx
然后nop无用的
```asm
.text:00000001400017AE                 rdtsc
.text:00000001400017B0                 shl     rdx, 20h
.text:00000001400017B4                 or      rax, rdx
.text:00000001400017B7                 nop
.text:00000001400017B8                 sub     rax, [rbp+8F0h+var_70]
.text:00000001400017BF                 mov     rdx, 1DCD65000h
.text:00000001400017C9                 cmp     rdx, rax
.text:00000001400017CC                 setb    al
.text:00000001400017CF                 test    al, al
```
像这种这种都是没用的反调试，所以我们从rdtsc指令开始patch，然后把没用的全部nop了  
```python
real_blocks_has_no_branch_but_has_pred = [5368735199, 5368737107, 5368715284, 5368736471, 5368735835, 5368715231]
real_blocks_has_no_branch = [5368736265, 5368739855, 5368725012, 5368715284, 5368742939, 5368724001, 5368730146, 5368737327, 5368740917, 5368734780, 5368723006, 5368721991, 5368742471, 5368738377, 5368727626, 5368716363, 5368717907, 5368728661, 5368735835, 5368726621, 5368739423, 5368715878, 5368732782, 5368720496, 5368725619, 5368724611, 5368718980, 5368736901, 5368740491, 5368723598, 5368742031, 5368734354, 5368722595, 5368737957, 5368727214, 5368721583, 5368720050, 5368741554, 5368717496, 5368735419, 5368728252, 5368732352, 5368729281, 5368739009, 5368726214, 5368714960, 5368736471, 5368725209, 5368730841, 5368740059, 5368718558, 5368743137, 5368721136, 5368733938, 5368724213, 5368719610, 5368741115, 5368737537, 5368717059, 5368723208, 5368722187, 5368731919, 5368734993, 5368738587, 5368728860, 5368727843, 5368726821, 5368718119, 5368725813, 5368736055, 5368733498, 5368744250, 5368739645, 5368720703, 5368729922, 5368719176, 5368724810, 5368737107, 5368742741, 5368731479, 5368740695, 5368723802, 5368733027, 5368734567, 5368722794, 5368727413, 5368738167, 5368743799, 5368721787, 5368717701, 5368729477, 5368732550, 5368726411, 5368728459, 5368735629, 5368720273, 5368739219, 5368731039, 5368741799, 5368725419, 5368718770, 5368736691, 5368740281, 5368724415, 5368734144, 5368743362, 5368723397, 5368741322, 5368719827, 5368737747, 5368722394, 5368717275, 5368730586, 5368735199, 5368715231, 5368732129, 5368727015, 5368738791, 5368729068, 5368728045, 5368726012]
real_blocks_has_branch = [5368731680, 5368721346, 5368720899, 5368733699, 5368731240, 5368743560, 5368716810, 5368730347, 5368733259, 5368718318, 5368719375, 5368729678, 5368716082, 5368743991, 5368742232, 5368744189, 5368716574]

flow_patch = {
    0x1400016d0: 0x140001a66,
    0x140001a66: 0x140001b32,
    0x140001f03: 0x140001fdb,
    0x1400020b8: 0x140002185,
    0x140002185: 0x140002253,
    0x140002253: 0x140002327,
    0x140002327: 0x1400023ee,
    0x1400024de: 0x1400025b2,
    0x1400025b2: 0x140002684,
    0x140002684: 0x1400023ee,
    0x140002748: 0x14000280f,
    0x1400028fa: 0x1400029d3,
    0x1400029d3: 0x140002ab2,
    0x140002ab2: 0x140002b91,
    0x140002b91: 0x140002c70,
    0x140002c70: 0x140002d3f,
    0x140002d3f: 0x14000280f,
    0x140002ef0: 0x140002fc2,
    0x1400030af: 0x14000317b,
    0x14000317b: 0x140003247,
    0x140003247: 0x14000330b,
    0x14000330b: 0x1400033da,
    0x1400033da: 0x1400034a3,
    0x1400034a3: 0x14000356a,
    0x14000356a: 0x14000363e,
    0x14000363e: 0x140003708,
    0x140003708: 0x1400037c5,
    0x1400037c5: 0x14000388e,
    0x14000388e: 0x14000395a,
    0x14000395a: 0x140003a21,
    0x140003a21: 0x140003af5,
    0x140003af5: 0x140003bbf,
    0x140003bbf: 0x140003c83,
    0x140003c83: 0x140003d4a,
    0x140003d4a: 0x140003e14,
    0x140003e14: 0x140003ed9,
    0x140003ed9: 0x140003fab,
    0x140003fab: 0x140004073,
    0x140004073: 0x140004135,
    0x140004135: 0x1400041fc,
    0x1400041fc: 0x1400042c6,
    0x1400042c6: 0x14000438b,
    0x14000438b: 0x14000445d,
    0x14000445d: 0x140004525,
    0x140004525: 0x1400045e7,
    0x1400045e7: 0x1400046ae,
    0x1400046ae: 0x140004775,
    0x140004775: 0x14000484a,
    0x14000484a: 0x140004923,
    0x140004923: 0x1400049ed,
    0x1400049ed: 0x140004abc,
    0x140004abc: 0x140004b8b,
    0x140004b8b: 0x140004c55,
    0x140004c55: 0x140004d1c,
    0x140004d1c: 0x140004dec,
    0x140004dec: 0x140004ec1,
    0x140004ec1: 0x140002e03,
    0x140004f85: 0x14000504e,
    0x140005142: 0x140005222,
    0x140005222: 0x1400052eb,
    0x1400053da: 0x1400054d9,
    0x1400054d9: 0x1400052eb,
    0x14000559f: 0x140005668,
    0x140005757: 0x140005820,
    0x14000590f: 0x1400059e1,
    0x1400059e1: 0x140005ac0,
    0x140005ac0: 0x140005820,
    0x140005b86: 0x140005c6e,
    0x140005c6e: 0x140005d63,
    0x140005d63: 0x140005e4b,
    0x140005f3a: 0x140006003,
    0x1400060f2: 0x1400061c0,
    0x1400061c0: 0x140006292,
    0x140006292: 0x140006367,
    0x140006367: 0x14000643c,
    0x14000643c: 0x140006511,
    0x140006511: 0x1400065df,
    0x1400065df: 0x1400066bb,
    0x1400066bb: 0x14000678d,
    0x14000678d: 0x14000685b,
    0x14000685b: 0x140006937,
    0x140006937: 0x140006a09,
    0x140006a09: 0x140006ad7,
    0x140006ad7: 0x140006bb3,
    0x140006bb3: 0x140006c85,
    0x140006c85: 0x140006d53,
    0x140006d53: 0x140006e2f,
    0x140006e2f: 0x140006f01,
    0x140006f01: 0x140006fd3,
    0x140006fd3: 0x1400070a5,
    0x1400070a5: 0x140007177,
    0x140007177: 0x140007249,
    0x140007249: 0x14000731b,
    0x14000731b: 0x1400073e7,
    0x1400073e7: 0x1400074c1,
    0x1400074c1: 0x140007593,
    0x140007593: 0x14000765f,
    0x14000765f: 0x14000773d,
    0x14000773d: 0x14000780f,
    0x14000780f: 0x1400078db,
    0x1400078db: 0x1400079b9,
    0x1400079b9: 0x140007a8b,
    0x140007a8b: 0x140007b57,
    0x140007b57: 0x140007c35,
    0x140007c35: 0x140006003,
    0x140007cfb: 0x140007dca,
    0x140007dca: 0x140007eb2,
    0x140007eb2: 0x140007fa7,
    0x140007fa7: 0x14000808f,
    0x14000808f: 0x140008158,
    0x140008247: 0x140008355,
    0x140008355: 0x140008158,
    0x14000841b: 0x140005668,
    0x1400084e1: 0x1400085c2,
    0x1400085c2: 0x14000504e,
    0x140001c4b: 0x140001d1e,
    0x14000893a: 0x1400089AB,
    0x140008777: 0x1400089AB,
    0x140001fdb: 0x1400020b8,



}

jz_patch = {
    0x140001b32: (0x140001c4b, 0x1400089AB),
    0x140001d1e: (0x140001fdb, 0x140001e0a),
    0x140008688: (0x140008837, 0x140008777),
    0x1400088fd: (0x14000893a, 0x1400089AB),
}

jnz_patch = {
    0x140001e0a: (0x140001fdb, 0x140001f03),
    0x140002fc2: (0x140004d1c, 0x1400030af),
    0x140008837: (0x140008777, 0x14000893a),
}

jle_patch = {
}

jg_patch = {
    0x1400023ee: (0x140002748, 0x1400024de),
    0x14000280f: (0x140002e03, 0x1400028fa),
    0x140002e03: (0x140004f85, 0x140002ef0),
    0x14000504e: (0x140008688, 0x140005142),
    0x1400052eb: (0x14000559f, 0x1400053da),
    0x140005668: (0x1400084e1, 0x140005757),
    0x140005820: (0x140005b86, 0x14000590f),
    0x140005e4b: (0x140007dca, 0x140005f3a),
    0x140006003: (0x140007cfb, 0x1400060f2),
    0x140008158: (0x14000841b, 0x140008247),
}

jmp_table = {
    0x1400065df:0x14000661F,
    0x140006d53:0x140006D93,
    0x140006ad7:0x140006B17,
    0x14000685b:0x14000689B,
}


useless_blocks = []




import idaapi
import idautils
import idc
import keystone

def patch_ins_to_nop(ins):
    size = idc.get_item_size(ins)
    for i in range(size):
        idc.patch_byte(ins + i,0x90)


def patch_bytes(addr, data):
    for i, b in enumerate(data):
        idc.patch_byte(addr + i, b)


def fill_nop(start_ea, end_ea):
    # [FIX 1] 应该是 end - start，否则是负数
    size = end_ea - start_ea 
    if size > 0:
        # [FIX 2] 使用 patch_bytes 批量写入
        patch_bytes(start_ea, b'\x90' * size)

def get_block_by_address(ea):
    func = idaapi.get_func(ea)
    blocks = idaapi.FlowChart(func)
    for block in blocks:
        if block.start_ea <= ea < block.end_ea:
            return block
    return None

def generate_jmp_code(src, dst):
    # E9 xx xx xx xx
    offset = dst - (src + 5)
    return b'\xE9' + offset.to_bytes(4, 'little', signed=True)

def generate_jz_code(src, dst):
    # 0F 84 xx xx xx xx
    offset = dst - (src + 6)
    return b'\x0F\x84' + offset.to_bytes(4, 'little', signed=True)

def generate_jnz_code(src, dst):
    # 0F 85 xx xx xx xx
    offset = dst - (src + 6)
    return b'\x0F\x85' + offset.to_bytes(4, 'little', signed=True)

def generate_jg_code(src, dst):
    # 0F 8F xx xx xx xx
    offset = dst - (src + 6)
    return b'\x0F\x8F' + offset.to_bytes(4, 'little', signed=True)

def find_rdtsc_addr(ea):
    block = get_block_by_address(ea)  # ea 为块内任意地址
    rdtsc_ea = None
    for ins in idautils.Heads(block.start_ea, block.end_ea):
        if idc.print_insn_mnem(ins) == "rdtsc":
            rdtsc_ea = ins
            return rdtsc_ea


def get_all_blocks(func_ea):
    global useless_blocks
    blocks = idaapi.FlowChart(idaapi.get_func(func_ea))
    for block in blocks:
        start_ea = block.start_ea
        end_ea = block.end_ea
        useless_blocks.append([start_ea,end_ea])


def patch_jmp():
    global useless_blocks
    for ea in flow_patch.keys():
        block = get_block_by_address(ea)
        start_ea = block.start_ea
        end_ea = block.end_ea
        last_ins_ea = idc.prev_head(end_ea)#

        try:
            useless_blocks.remove([start_ea,end_ea])
        except ValueError:
            pass

        if ea in jmp_table.keys():
            print("11111")
            
            succs = list(block.succs())
            # 只有当确实存在两个后继块时才尝试移除
            if len(succs) >= 2:
                succ_1 = succs[0]
                succ_2 = succs[1]
                try: useless_blocks.remove([succ_1.start_ea,succ_1.end_ea]) 
                except: pass
                try: useless_blocks.remove([succ_2.start_ea,succ_2.end_ea])
                except: pass

            block1 = get_block_by_address(jmp_table[ea])
            start_ea = block1.start_ea
            end_ea = block1.end_ea
            
            print([start_ea,end_ea])
            try: useless_blocks.remove([start_ea,end_ea])
            except: pass
            
            rdstc_addr = find_rdtsc_addr(jmp_table[ea])
            jmp_code = generate_jmp_code(rdstc_addr, flow_patch[ea])
            
            patch_bytes(rdstc_addr, jmp_code)
            nop_start = jmp_table[ea] + len(jmp_code)
            
            

            
            fill_nop(nop_start, end_ea)
            print(f"11111Patched jmp at {hex(jmp_table[ea])} to {hex(flow_patch[ea])}")
        else:
            print("22222")
            rdstc_addr = find_rdtsc_addr(ea)
            jmp_code = generate_jmp_code(rdstc_addr, flow_patch[ea])
            patch_bytes(rdstc_addr, jmp_code)
            nop_start = rdstc_addr + len(jmp_code)
            fill_nop(nop_start, end_ea)
            print(f"222222Patched jmp at {hex(last_ins_ea)} to {hex(flow_patch[ea])}")

        

def patch_jz():
    global useless_blocks
    for ea in jz_patch.keys():
        block = get_block_by_address(ea)
        start_ea = block.start_ea
        end_ea = block.end_ea
        last_ins_ea = idc.prev_head(end_ea)#

        try: useless_blocks.remove([start_ea,end_ea])
        except: pass

        succs = list(block.succs())
        if len(succs) >= 2:
            succ_1 = succs[0]
            succ_2 = succs[1]

            try: useless_blocks.remove([succ_1.start_ea,succ_1.end_ea])
            except: pass
            try: useless_blocks.remove([succ_2.start_ea,succ_2.end_ea])
            except: pass


            succ1_addr = jz_patch[ea][0]
            succ2_addr = jz_patch[ea][1]



            jz_code = generate_jz_code(last_ins_ea, jz_patch[ea][0])
            jmp_code = generate_jmp_code( last_ins_ea+ len(jz_code), jz_patch[ea][1])

            patch_bytes(last_ins_ea, jz_code)
            patch_bytes(last_ins_ea + len(jz_code), jmp_code)

            nop_start = last_ins_ea + len(jz_code) + len(jmp_code)

            if succ_1.end_ea > succ_2.end_ea:
                nop_end = succ_1.end_ea
            else:
                nop_end = succ_2.end_ea
            fill_nop(nop_start, nop_end)
            print(f"Patched jz at {hex(last_ins_ea)} to {hex(jz_patch[ea][0])} and {hex(jz_patch[ea][1])}")
        else:
            print(f"Warning: Block {hex(ea)} (jz) has {len(succs)} successors, skipping nop removal/logic")


def patch_jnz():
    global useless_blocks
    for ea in jnz_patch.keys():
        block = get_block_by_address(ea)
        start_ea = block.start_ea
        end_ea = block.end_ea
        last_ins_ea = idc.prev_head(end_ea)#

        try: useless_blocks.remove([start_ea,end_ea])
        except: pass

        succs = list(block.succs())
        if len(succs) >= 2:
            succ_1 = succs[0]
            succ_2 = succs[1]

            try: useless_blocks.remove([succ_1.start_ea,succ_1.end_ea])
            except: pass
            try: useless_blocks.remove([succ_2.start_ea,succ_2.end_ea])
            except: pass

            jnz_code = generate_jnz_code(last_ins_ea, jnz_patch[ea][0])
            jmp_code = generate_jmp_code( last_ins_ea+ len(jnz_code), jnz_patch[ea][1])

            patch_bytes(last_ins_ea, jnz_code)
            patch_bytes(last_ins_ea + len(jnz_code), jmp_code)

            nop_start = last_ins_ea + len(jnz_code) + len(jmp_code)

            if succ_1.end_ea > succ_2.end_ea:
                nop_end = succ_1.end_ea
            else:
                nop_end = succ_2.end_ea
            fill_nop(nop_start, nop_end)
            print(f"Patched jnz at {hex(last_ins_ea)} to {hex(jnz_patch[ea][0])} and {hex(jnz_patch[ea][1])}")

def patch_jg():
    global useless_blocks
    for ea in jg_patch.keys():
        block = get_block_by_address(ea)
        start_ea = block.start_ea
        end_ea = block.end_ea
        last_ins_ea = idc.prev_head(end_ea)#

        try: useless_blocks.remove([start_ea,end_ea])
        except: pass

        succs = list(block.succs())
        if len(succs) >= 2:
            succ_1 = succs[0]
            succ_2 = succs[1]

            try: useless_blocks.remove([succ_1.start_ea,succ_1.end_ea])
            except: pass
            try: useless_blocks.remove([succ_2.start_ea,succ_2.end_ea])
            except: pass

            jg_code = generate_jg_code(last_ins_ea, jg_patch[ea][0])
            jmp_code = generate_jmp_code( last_ins_ea+ len(jg_code), jg_patch[ea][1])

            patch_bytes(last_ins_ea, jg_code)
            patch_bytes(last_ins_ea + len(jg_code), jmp_code)

            nop_start = last_ins_ea + len(jg_code) + len(jmp_code)

            if succ_1.end_ea > succ_2.end_ea:
                nop_end = succ_1.end_ea
            else:
                nop_end = succ_2.end_ea
            fill_nop(nop_start, nop_end)
            print(f"Patched jg at {hex(last_ins_ea)} to {hex(jg_patch[ea][0])} and {hex(jg_patch[ea][1])}")

def patch_useless_blocks():
    global useless_blocks
    # print(useless_blocks)
    for useless_block in useless_blocks:
        
        print(f"Nop-ing useless block from {hex(useless_block[0])} to {useless_block[1]}")
        fill_nop(useless_block[0], useless_block[1])
    print("无用块nop完成")

def remove_real_blocks_from_useless():
    global useless_blocks
    for addr in real_blocks_has_no_branch_but_has_pred:
        try:
            block1 = get_block_by_address(addr)
            if not block1: continue
            start_ea1 = block1.start_ea
            end_ea1 = block1.end_ea

            succss = list(block1.succs())
            if len(succss) < 2: continue # 安全检查

            start_ea2 = succss[0].start_ea
            end_ea2 = succss[0].end_ea
            
            start_ea3 = succss[1].start_ea
            end_ea3 = succss[1].end_ea

            succss2 = list(succss[0].succs())
            
            try: useless_blocks.remove([start_ea1,end_ea1])
            except ValueError: pass
            try: useless_blocks.remove([start_ea2,end_ea2])
            except ValueError: pass
            try: useless_blocks.remove([start_ea3,end_ea3])
            except ValueError: pass

            if len(succss2) > 0:
                start_ea4 = succss2[0].start_ea
                end_ea4 = succss2[0].end_ea
                try: useless_blocks.remove([start_ea4,end_ea4])
                except ValueError: pass
        except Exception as e:
            print(f"Error in no_branch_but_pred loop for {hex(addr)}: {e}")

    for addr in real_blocks_has_branch:
        try:
            block = get_block_by_address(addr)
            if not block: continue
            start_ea = block.start_ea
            end_ea = block.end_ea

            succs = list(block.succs())
            if len(succs) < 2: continue # 安全检查

            start_ea1 = succs[0].start_ea
            end_ea1 = succs[0].end_ea

            # [FIX] 这里之前是 succss (Typo)，已修正为 succs
            start_ea2 = succs[1].start_ea
            end_ea2 = succs[1].end_ea

            try: useless_blocks.remove([start_ea,end_ea])
            except ValueError: pass
            try: useless_blocks.remove([start_ea1,end_ea1])
            except ValueError: pass
            try: useless_blocks.remove([start_ea2,end_ea2])
            except ValueError: pass
        except Exception as e:
            print(f"Error in has_branch loop for {hex(addr)}: {e}")
    
    for addr in real_blocks_has_no_branch:
        try:
            block = get_block_by_address(addr)
            if not block: continue
            start_ea = block.start_ea
            end_ea = block.end_ea

            try: useless_blocks.remove([start_ea,end_ea])
            except ValueError: pass
        except Exception as e:
            print(f"Error in no_branch loop for {hex(addr)}: {e}")





get_all_blocks(0x1400016D0)
remove_real_blocks_from_useless()
patch_jz()
patch_jnz()
patch_jg()
patch_jmp()
patch_useless_blocks()
```
patch之前记得把retn上面里面很多没用的0x83给nop了，会影响后面ida的cfg  
然后我们保存patch结果，发现可以正常运行  
![CFG8](https://github.com/Qmeimei10086/qmeimei10086.github.io/blob/main/img/2026-1-29-blog-cfg8.png?raw=true "CFG8")
现在正常多了，不过ida的反编译结果还是怪怪的，不过我们有无敌的ai大人  
ai发现是变异aes
```python
# EzObf1 WriteUp

这是一道修改了 AES 流程的逆向题目。虽然二进制被控制流平坦化（Control Flow Flattening）混淆，但通过分析关键变换块的汇编代码，我们可以还原出其独特的加密逻辑。

## 1. 初始分析

拿到二进制文件 `ezobf1.exe` 后，运行发现它要求输入 Flag，并验证正确性。

### 关键数据提取

通过静态分析或动态调试，我们可以在数据段找到两个关键信息：

1.  **密文 (Ciphertext)**: 存放在 `unk_14000C1C0`。
    
    unsigned char ciphertext[32] = {
        0xF2, 0x65, 0x12, 0xF9, ... // (32 字节)
    };
    
2.  **S-Box**: 存放在 `unk_14000C080`，这是一张非标准的 S-Box。
    =
    unsigned char SBOX[256] = {
        0x45, 0x25, 0x95, ... 
    };
    

密钥被硬编码为 `00 01 02 ... 0F`。

## 2. 混淆与控制流分析

程序使用了控制流平坦化混淆，主函数 `sub_1400016D0` 由一个巨大的 Switch-Case 结构组成。通过 `patch_all_block.py` 提供的映射表，我们可以看到逻辑块之间的跳转关系。

并不是去完全去平坦化，而是根据跳转表（Jump Table）定位到每个 AES 操作对应的真实地址。

通过观察跳转表（如 `d:\reverse\MCP\patch_all_block.py` 中的 `jg_patch` 或 `flow_patch`），我们确定了几个重复出现的代码块地址：
*   `0x140005B86` / `0x140005C6E` / `0x140005D63`
*   `0x140005E4B` (Loop check)
*   `0x1400060F2` (MixColumns area)

## 3. 汇编层面的逻辑拆解

我们编写脚本对上述关键地址进行了反汇编分析。

### (1) ShiftRows (行移位) 的变异

在标准 AES 中，ShiftRows 操作是：
*   Row 0: 不变
*   Row 1: 左移 1
*   Row 2: 左移 2
*   Row 3: 左移 3

查看地址 `0x140005B86` 处的汇编：

0x140005b86: movzx eax, byte ptr [rbp - 0x3f]
0x140005b8b: mov byte ptr [rbp + 0x8af], al  ; 暂存
0x140005b91: movzx eax, byte ptr [rbp - 0x3b]
0x140005b95: mov byte ptr [rbp - 0x3f], al   ; 移位...
...

这段代码明确地在栈上进行字节交换。这对应了 `ShiftRows` 操作。

**关键发现**：在每一轮加密循环中，我们发现这组 ShiftRows 代码被调用了**两次**。
一次是在 MixColumns 之前，一次是在 MixColumns 之后。

### (2) MixColumns (列混合)

在 `0x140006000` 附近的汇编代码中，出现了大量的 `0x1b` 立即数和异或操作，这是典型的有限域乘法（GF(2^8)）特征：


0x1400065eb: mov eax, 0x1b  ; AES 不可约多项式系数
...
0x1400066bb: xor al, byte ptr [rbp + 0x8ae] ; 异或累加

这证实了 `MixColumns` 的存在，且系数是标准的（02, 03, 01, 01）。

### (3) AddRoundKey

在 `0x140008247` 附近，指令从 Expanded Key 数组中读取数据并与 State 进行异或：

0x140008293: xor edx, ecx
0x140008295: mov dword ptr [rax], edx


## 4. 还原加密流程

结合上述分析，该程序的单轮加密逻辑如下（注意顺序变化）：

**标准 AES**:
`SubBytes` -> `ShiftRows` -> `MixColumns` -> `AddRoundKey`

**EzObf1 AES**:
`SubBytes` -> **`ShiftRows`** -> `MixColumns` -> **`ShiftRows`** -> `AddRoundKey`

即 `MixColumns` 被夹在两次 `ShiftRows` 之间。

对于最后一轮（第10轮）：
`SubBytes` -> **`ShiftRows`** -> **`ShiftRows`** -> `AddRoundKey` (无 MixColumns)

## 5. 解密脚本 (Solver)

解密时，必须严格逆序执行所有操作。

*   **标准解密**: `InvShift` -> `InvSub` -> `AddKey` -> `InvMix`
*   **本题解密**:
    1.  `AddRoundKey`
    2.  `InvShiftRows` (抵消第二次 Shift)
    3.  `InvMixColumns`
    4.  `InvShiftRows` (抵消第一次 Shift)
    5.  `InvSubBytes`

（注：AES解密时通常先 AddKey，然后进入逆向循环。根据实现细节，InvShift 和 InvSub 的顺序可以互换，因为它们是按字节操作的，互不影响。）

使用 Python 实现该逻辑：


def decrypt_block(ciphertext, w):
    # ... 初始化 State ...

    # 撤销第 10 轮 (两次移位，无列混合)
    state = add_round_key(state, w, 10)
    state = inv_shift_rows(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    
    # 撤销第 9 到 第 1 轮
    for round_num in range(9, 0, -1):
        state = add_round_key(state, w, round_num)
        
        # 逆序撤销: Shift2 -> Mix -> Shift1 -> Sub
        state = inv_shift_rows(state) 
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        
        state = inv_sub_bytes(state)
    
    # 撤销第 0 轮 (初始轮只有 AddKey)
    state = add_round_key(state, w, 0)
    
    # ... 输出 ...

```
解题脚本
```python

def gmul(a, b):
    p = 0
    for i in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return p

# Custom S-Box
SBOX = [
    0x45, 0x25, 0x95, 0xf4, 0x49, 0x7f, 0x39, 0xfe, 0x2b, 0x5, 0xd7, 0x64, 0xd1, 0x9c, 0x5b, 0x7c, 
    0xa7, 0xd2, 0xac, 0x1d, 0x10, 0xcb, 0xe6, 0xeb, 0xa0, 0x15, 0x2, 0x8, 0x21, 0x96, 0x65, 0x11, 
    0xef, 0x63, 0xc0, 0x94, 0xea, 0x70, 0x84, 0xb8, 0xf1, 0x56, 0x7b, 0x23, 0x4d, 0x37, 0xaf, 0xc8, 
    0x46, 0x8e, 0x13, 0xad, 0x2a, 0x1c, 0x4b, 0xb1, 0x47, 0x2d, 0x2e, 0xa2, 0x3b, 0x9a, 0x8c, 0xf7, 
    0x3e, 0x51, 0x48, 0x8d, 0xb4, 0x2f, 0xed, 0xd5, 0x83, 0x42, 0x69, 0x34, 0x86, 0x6e, 0xe3, 0x36, 
    0xff, 0xa3, 0x33, 0x59, 0xa6, 0xe, 0x8a, 0x7, 0xb7, 0xb, 0xaa, 0xbe, 0xca, 0x87, 0x1f, 0x79, 
    0xc3, 0xec, 0x75, 0xdc, 0x68, 0x6, 0x58, 0xc4, 0x29, 0x89, 0x54, 0xa8, 0x3c, 0xbb, 0x4a, 0x1e, 
    0x1b, 0xe1, 0xbd, 0x71, 0xdb, 0x52, 0x41, 0xe2, 0xda, 0xd3, 0xf9, 0x14, 0x26, 0x7a, 0x53, 0x9b, 
    0x81, 0xcf, 0xc, 0x35, 0x40, 0x9e, 0xce, 0x5d, 0x67, 0xc1, 0xfc, 0x6b, 0x6f, 0x93, 0xfb, 0x9d, 
    0x8b, 0x30, 0x76, 0x4f, 0x5c, 0x6a, 0xf0, 0x1a, 0x1, 0xf2, 0xf3, 0x7e, 0xc6, 0x28, 0xf5, 0xe7, 
    0x99, 0xf8, 0xc7, 0x74, 0xfd, 0x82, 0xe8, 0xee, 0x9, 0x55, 0x77, 0x44, 0x22, 0xae, 0x5e, 0xd8, 
    0x12, 0x4c, 0x88, 0x97, 0xe9, 0x3f, 0x38, 0x98, 0xde, 0x6c, 0xcd, 0x50, 0xe0, 0x6d, 0x32, 0x43, 
    0x61, 0xa1, 0xa, 0xb2, 0x5f, 0xdd, 0x9f, 0xe4, 0x7d, 0xb0, 0x16, 0x3d, 0x2c, 0xfa, 0xc2, 0xa4, 
    0xb9, 0x66, 0xba, 0xd0, 0x92, 0xd6, 0x78, 0xdf, 0xab, 0xb5, 0x27, 0x8f, 0xcc, 0x4, 0x62, 0xd9, 
    0xa5, 0xc9, 0xbc, 0x19, 0x85, 0xd, 0x80, 0x5a, 0x3a, 0xf6, 0x17, 0xb6, 0xb3, 0x31, 0xbf, 0xe5, 
    0x60, 0x18, 0x91, 0x0, 0xd4, 0x73, 0x20, 0xc5, 0xf, 0x90, 0x57, 0x4e, 0x3, 0x72, 0x24, 0xa9
]

# Inverse S-Box
INV_SBOX = [0] * 256
for i in range(len(SBOX)):
    INV_SBOX[SBOX[i]] = i

# Rcon (Standard)
Rcon = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]

def sub_word(word):
    # Use Custom SBox
    return (SBOX[(word >> 24) & 0xFF] << 24) | \
           (SBOX[(word >> 16) & 0xFF] << 16) | \
           (SBOX[(word >> 8) & 0xFF] << 8) | \
           (SBOX[word & 0xFF])

def rot_word(word):
    return ((word << 8) & 0xFFFFFFFF) | (word >> 24)

def key_expansion(key):
    # Key is 16 bytes list
    w = [0] * 44 # 4 words * 11 (10 rounds + 1)
    
    # First 4 words are the key itself
    for i in range(4):
        w[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3]
    
    for i in range(4, 44):
        temp = w[i-1]
        if i % 4 == 0:
            temp = sub_word(rot_word(temp)) ^ (Rcon[i//4 - 1] << 24)
        w[i] = w[i-4] ^ temp
    return w

def add_round_key(state, w, round_num):
    for c in range(4):
        val = w[round_num*4 + c]
        # w is in MSB first (big endian word) ?
        # Code: key[0]<<24.
        # AES treats words as Col 0, Col 1, etc.
        # State[r][c].
        # key[0] is state[0][0]. key[1] is state[1][0]...
        # Wait. Standard AES state:
        # 0  4  8 12
        # 1  5  9 13
        # 2  6 10 14
        # 3  7 11 15
        # key[0] maps to index 0.
        # In my w construction: w[0] = k0 k1 k2 k3.
        # w[0] >> 24 is k0.
        # w[0] >> 16 is k1.
        # Correct.
        state[0][c] ^= (val >> 24) & 0xFF
        state[1][c] ^= (val >> 16) & 0xFF
        state[2][c] ^= (val >> 8) & 0xFF
        state[3][c] ^= val & 0xFF
    return state

def inv_sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_SBOX[state[r][c]]
    return state

def inv_shift_rows(state):
    # Standard InvShiftRows
    # Row 1 rot right 1
    state[1] = state[1][-1:] + state[1][:-1]
    # Row 2 rot right 2
    state[2] = state[2][-2:] + state[2][:-2]
    # Row 3 rot right 3
    state[3] = state[3][-3:] + state[3][:-3]
    return state

def inv_mix_columns(state):
    # Multiply by 0e, 0b, 0d, 09
    # a(x) = {0b}x^3 + {0d}x^2 + {09}x + {0e}
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        state[0][c] = gmul(col[0], 0x0e) ^ gmul(col[1], 0x0b) ^ gmul(col[2], 0x0d) ^ gmul(col[3], 0x09)
        state[1][c] = gmul(col[0], 0x09) ^ gmul(col[1], 0x0e) ^ gmul(col[2], 0x0b) ^ gmul(col[3], 0x0d)
        state[2][c] = gmul(col[0], 0x0d) ^ gmul(col[1], 0x09) ^ gmul(col[2], 0x0e) ^ gmul(col[3], 0x0b)
        state[3][c] = gmul(col[0], 0x0b) ^ gmul(col[1], 0x0d) ^ gmul(col[2], 0x09) ^ gmul(col[3], 0x0e)
    return state

def decrypt_block(ciphertext, w):
    # Helper to convert linear 16 bytes to 4x4 state (Column Major)
    # 0 4 8 12
    # 1 5 9 13 ...
    state = [[0]*4 for _ in range(4)]
    for i in range(16):
        state[i%4][i//4] = ciphertext[i]

    # AddRoundKey (Round 10)
    state = add_round_key(state, w, 10)
    state = inv_shift_rows(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    
    for round_num in range(9, 0, -1):
        state = add_round_key(state, w, round_num)
        state = inv_shift_rows(state) # Second shift reversed
        state = inv_mix_columns(state)
        state = inv_shift_rows(state) # First shift reversed
        state = inv_sub_bytes(state)
    
    # Initial Round (Round 0)
    state = add_round_key(state, w, 0)
    
    # Extract linear
    output = [0]*16
    for i in range(16):
        output[i] = state[i%4][i//4]
    return bytes(output)

# Main
key = bytes(range(16)) # 00 01 ... 0F
w = key_expansion(key)

# Ciphertext unk_14000C1C0 (32 bytes)
ct1 = bytes([
    0xF2, 0x65, 0x12, 0xF9, 0x2F, 0x64, 0x28, 0x7D, 0xC0, 0xD0, 0x45, 0x5B, 0x25, 0xDA, 0x24, 0x15
])
ct2 = bytes([
    0xA6, 0x9C, 0x1D, 0xAC, 0x85, 0x42, 0xAB, 0x28, 0xD3, 0x4C, 0x2C, 0x75, 0xDC, 0xDA, 0x30, 0xC7
])

pt1 = decrypt_block(ct1, w)
pt2 = decrypt_block(ct2, w)

print(f"PT1: {pt1}")
print(f"PT2: {pt2}")
try:
    print(f"Decoded: {(pt1+pt2).decode('utf-8')}")
except:
    print("Decode failed")

```


