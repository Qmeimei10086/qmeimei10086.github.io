---
layout: post
title: " [香港杯 2025]easyre-sse花指令+地址混淆"
date:       2025-12-21
author: "Qmeimei10086"
header-style: text
tags:
  - CTF
  - 逆向
  - 花指令
  - 恢复加密
---

## 前言
哎哎本来想写好多，脚本写完感觉好累，而且感觉也不是特别难的题，就是考验基本功  
## 题目分析
进去一堆乱七八糟的指令，一查原来是sse/avx指令集，叫ai写个去花脚本就行
```python
import idc
import ida_bytes
import ida_funcs
import idautils
import ida_kernwin

def is_sse_instruction(ea):
    """
    Check if the instruction is SSE/AVX/FPU junk.
    """
    mnem = idc.print_insn_mnem(ea).lower()
    
    # 1. Check Mnemonics
    if mnem.startswith('v'): # AVX
        return True
        
    if mnem.startswith('p'): # Packed SSE
        if mnem in ['push', 'pop', 'pushfq', 'popfq', 'pushad', 'popad', 'popcnt', 'pause', 'proc', 'public']:
            return False
        return True
        
    if mnem.startswith('f'): # FPU
        return True

    if any(mnem.endswith(s) for s in ['ps', 'pd', 'ss', 'sd']):
        if mnem == 'movsd' and not ('xmm' in idc.print_operand(ea, 0) or 'xmm' in idc.print_operand(ea, 1)):
            return False 
        return True

    # 2. Check Operands for Vector Registers
    op1 = idc.print_operand(ea, 0).lower()
    op2 = idc.print_operand(ea, 1).lower()
    op3 = idc.print_operand(ea, 2).lower()
    
    for op in [op1, op2, op3]:
        if 'xmm' in op or 'ymm' in op or 'mm' in op:
            return True
            
    return False

def nop_instruction(ea):
    length = idc.get_item_size(ea)
    ida_bytes.patch_bytes(ea, b'\x90' * length)

def patch_range(start_ea, end_ea):
    """
    Patch SSE instructions in the given address range.
    """
    print(f"Scanning range 0x{start_ea:x} - 0x{end_ea:x}...")
    count = 0
    curr = start_ea
    
    # Ensure we align to heads
    if not idc.is_head(idc.get_full_flags(curr)):
        curr = idc.next_head(curr)

    while curr < end_ea and curr != idc.BADADDR:
        if not idc.is_code(idc.get_full_flags(curr)):
            curr = idc.next_head(curr, end_ea)
            continue
        
        length = idc.get_item_size(curr)
        
        if is_sse_instruction(curr):
            nop_instruction(curr)
            count += 1
            
        curr += length
        
    print(f"Done. NOPed {count} instructions.")
    return count

def patch_function(func_id):
    """
    Patch SSE instructions in a function.
    Args:
        func_id: Function name (str) or address (int)
    """
    start_ea = idc.BADADDR
    
    if isinstance(func_id, str):
        start_ea = idc.get_name_ea_simple(func_id)
        if start_ea == idc.BADADDR:
            print(f"Error: Function '{func_id}' not found.")
            return
    elif isinstance(func_id, int):
        start_ea = func_id
    else:
        print("Error: Invalid argument type. Expected string or int.")
        return
    
    func = ida_funcs.get_func(start_ea)
    if not func:
        print(f"Error: Address 0x{start_ea:x} is not inside a function.")
        return
        
    func_name = idc.get_func_name(func.start_ea)
    print(f"Patching function {func_name} (0x{func.start_ea:x} - 0x{func.end_ea:x})...")
    patch_range(func.start_ea, func.end_ea)

# --- Auto-run Logic ---

print("\n" + "="*50)
print("Flexible SSE Patcher Loaded")
print("="*50)

# 1. Auto-patch main (Safe)
main_ea = 0x1400021d0
print(f"Auto-patching main at 0x{main_ea:x}...")
patch_function(main_ea)

# 2. Print instructions
print("\n" + "-"*50)
print("Available Commands (type in IDA Output window):")
print("  patch_function('function_name')   -> Patch by name")
print("  patch_function(0x1400xxxxx)       -> Patch by address")
print("  patch_range(0xStart, 0xEnd)       -> Patch specific range")
print("-"*50 + "\n")
```
patch完主函数发现变量和函数调用都是用基址+偏移的方式调用，拿出计算机慢慢敲吧  
不过值得注意的是这题我看到了isdebugpresent，说明有反调试，但是没断下来，反正再这种简单的在oep下个断点然后scyllahide无脑注入就行  
这题代码写的也挺恶心，简单的xtea被他搞成一堆乱七八糟的取反与或，反正抓住<<4(或者 * 16) >>5 然后传入左右值，有+=啥的，在第一轮断v12还能看到标志性特征0x9E3779B9，这tea家族的delta  
值得注意的个等价表达式  
```
~(~v12 | 0xFFFFFFFC) 等价于 (v12 & 3)
也就是key[sum & 3]
```
加密流程是  
addloop -> sbox_like -> xtea  
反过来就行，直接贴脚本吧  
```c
#include <stdio.h>
#include <stdint.h>
unsigned int delta = 0x9E3779B9;

unsigned int key[4] = {
    0xC77485CD, 0x09C431F1, 0xA3D76A70, 0x560C4937
};
//unsigned int enc[2] = {
//    0xDEDEDEDE, 0xDEDEDEDE
//};

unsigned int table_098[42] = { 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40 };

//unsigned char unk_7FF7D1FD0E30[42] = {
//    0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1,
//    0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1,
//    0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1
//};

uint8_t enc[42] = {
    0xBA, 0x7A, 0xAA, 0x6A, 0x2F, 0x7E, 0xF8, 0x03, 0x2D, 0xB4, 0xAB, 0x92, 0x6B, 0x91, 0x31, 0xDA,
    0x95, 0x37, 0x51, 0x13, 0x1F, 0xCE, 0x1C, 0x62, 0x51, 0xBC, 0x3F, 0xB2, 0xB1, 0xB3, 0x54, 0x17,
    0xEF, 0x28, 0x93, 0xAE, 0x52, 0xCA, 0xCE, 0xA7, 0xDE, 0xC2
};


void xtea_crypt(uint32_t rounds, uint32_t* a2, uint32_t* key) {
    uint32_t v0 = a2[0];
    uint32_t v1 = a2[1];
    uint32_t sum = 0;
    for (uint32_t i = 0; i < rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta; // 被 off_140030078 那坨混淆了
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }
    a2[0] = v0;
    a2[1] = v1;
}

void xtea_decrypt(uint32_t rounds, uint32_t* a2, uint32_t* key) {
    uint32_t v0 = a2[0];
    uint32_t v1 = a2[1];
    uint32_t sum = delta * rounds;
    for (uint32_t i = 0; i < rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta; // 被 off_140030078 那坨混淆了
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        
    }
    a2[0] = v0;
    a2[1] = v1;
}

void generate_sbox(uint8_t* sbox) {
   int i;
   for (i=0; i <= 0xFF; i++) {
       sbox[i] = ~(~(~(~(~(i & 0x7D)
            & ~(~i & 0x82))
            & 0x84)
            & ~(~(i & 0x7D)
                & ~(~i & 0x82)
                & 0x7B)
            & 0x86)
            & ~(~(~(~(~(i & 0x7D)
                & ~(~i & 0x82))
                & 0x84)
                & ~(~(i & 0x7D)
                    & ~(~i & 0x82)
                    & 0x7B))
                & 0x79));
    }
}

void solve_sbox(uint8_t* sbox, uint8_t* enc, int round) {
    int i,j;

    for (i = 0; i < round; i++) {
        for (j = 0; j <= 0xFF; j++) {
            if (sbox[j] == enc[i]) {
                enc[i] = j;
                break;
            }
        }
    }
}

void solve_add_loop(uint8_t* enc,int round){
    int i;
    for (i = 0; i < round; i++) {
        enc[i] -= table_098[i];
    }
}

int main() {
    
    int i;
    uint32_t temp_enc[2];
    /*unsigned char unk_7FF7D1FD0E30[42] = {
    0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1,
    0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1,
    0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1
    };
    solve_add_loop(unk_7FF7D1FD0E30,42);
    for (int i = 0; i < 42; i++) {
        printf("0x%X ", unk_7FF7D1FD0E30[i]);
    }*/

    
    
    //uint8_t sbox[0xFF];
    //generate_sbox(sbox);
    //uint8_t unk_7FF7D1FD0E30[42] = {
    //0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE,
    //0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE,
    //0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE
    //};

    //solve_sbox(sbox, unk_7FF7D1FD0E30, 42);
    //for (int i = 0; i < 42; i++) {
    //    printf("0x%X ", unk_7FF7D1FD0E30[i]);
    //}
    ///*xtea_crypt(0x66, enc, key);
    /*printf("0x%X, 0x%X\n", enc[0], enc[1]);
    xtea_decrypt(0x66, enc, key);
    printf("0x%X, 0x%X\n", enc[0], enc[1]);*/
    
    //first step -> solve xtea
    uint32_t* uint32_enc = (uint32_t*)enc;
    for (i = 0; i < 9; i += 2) {
        temp_enc[0] = uint32_enc[i];
        temp_enc[1] = uint32_enc[i + 1];
        xtea_decrypt(0x66, temp_enc, key);
        uint32_enc[i] = temp_enc[0];
        uint32_enc[i+1] = temp_enc[1];
    }
    uint8_t* uint8_enc = (uint8_t*)uint32_enc;
    //second step -> solve sbox
    uint8_t sbox[256];
    generate_sbox(sbox);
    solve_sbox(sbox, uint8_enc, 42);
    //thrid steop -> solve add_loop
    solve_add_loop(uint8_enc, 42);

    //print result
    for (int i = 0; i < 42; i++) {
        printf("%X ", uint8_enc[i]);
    }

    return 0;
    
    
}
/*
输出的hex丢给cyberchef就行
结果
66 6C 61 67 7B 30 37 39 63 66 63 63 32 2D 64 33 36 38 2D 31 31 66 30 2D 62 64 65 61 2D 66 66 32 39 32 32 66 63 39 36 31 61 7D
flag{079cfcc2-d368-11f0-bdea-ff2922fc961a}
*/
```

