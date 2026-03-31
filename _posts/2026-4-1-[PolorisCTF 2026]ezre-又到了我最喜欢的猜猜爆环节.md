---
layout:     post
title:      "[PolorisCTF 2026]ezre-又到了我最喜欢的猜猜爆环节"
date:       2026-4-1
author:     Qmeimei10086
header-style: text
tags:
    - 控制流平坦化
    - 不透明词
    - 双端调试
---

# 前言
观前提示，本题内涵:  
- 逆向特有的无意义的工作量叠加
- 我最喜欢的玄学数据流追踪
- 黑盒函数我直接猜猜爆
  
请配合https://qmeimei10086.github.io/2026/01/19/angr%E7%AC%A6%E5%8F%B7%E6%89%A7%E8%A1%8C%E5%AF%B9%E6%8A%97ollvm/    食用  
# 题目分析
拿到手是一个client/server的双端题目，着我我一般喜欢先写个假的服务端看看    
client发送aaaaaaaa，拿到  
```text
[+] Accepted connection from ('127.0.0.1', 63312)
[*] Received 4 bytes
[*] Hex: 00 00 00 08
[*] Received 8 bytes
[*] Hex: 99 94 76 ce 00 20 ae dd
[!] Closed connection from ('127.0.0.1', 63312)
```  
可以看到先发送长度，然后再发送密文   
打开发现两个都是有控制流平坦化的，不过我们先做一下数据流分析，尽可能避免直面这种东西   
打开iat发现了BCryptEncrypt家族的加密函数，还有socket家族的函数，但是没发现交叉应用，看到汇编经常出现   
```asm
mov     r11, cs:off_7FF6850D2B08
sub     ecx, r8d
movsxd  rsi, ecx
add     r11, rsi
add     r11, 280h
mov     rcx, r10
mov     rdx, r11
mov     [rsp+508h+var_438], rax
call    r9
```
这种间接跳转，我们直接在iat上下断点  
我在recv上下个断点，client发送88888888，根据x86调用约定记录rcx,rdx,r8的值，然后直接run until return，来到调用处，根据recv定义  
```c
; int (__stdcall *recv)(SOCKET s, char *buf, int len, int flags)
```
rdx就是接受到的数据，第一次拿到08，也就是长度，第二次拿到99 94 76 ce 00 20 ae dd，也就是密文  
我们给这串数据下硬件访问断点，当程序第一次暂停时，发现断在bcrypt.dll的内部，此时我们取消断点，然后继续run until return，来到BCryptEncrypt，再次返回来到  
```asm
.text:000000014000DA86 FF D6                             call    rsi
```
此时发现rsp+30处出现明文    
直接在000000014000DA86下断点也能发现，rdx就是我们收到的密文的地址    
```
.idata:00007FF720B36308                   ; NTSTATUS (__stdcall *BCryptEncrypt)(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, void *pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG dwFlags)
.idata:00007FF720B36308 00 33 23 64 FC 7F __imp_BCryptEncrypt dq offset bcrypt_BCryptEncrypt
```
至于为什么是BCryptEncrypt，希腊奶，反正我们继续追踪rsp+30处出现的明文    
继续给他下硬件断点，我们来到一处系统dll里，然后一直返回，最终来到调用处    
```asm
.text:00007FF720B12E30 4C 8D 84 24 F0 01 lea     r8, [rsp+508h+enc_data] ; encrypted_data
.text:00007FF720B12E30 00 00
.text:00007FF720B12E38 48 8B 8C 24 18 02 mov     rcx, [rsp+508h+recv_data_plaintext] ; recv_data_plaintext
.text:00007FF720B12E38 00 00
.text:00007FF720B12E40 48 8B 15 09 FD 02 mov     rdx, cs:off_7FF720B42B50
.text:00007FF720B12E40 00
.text:00007FF720B12E47 41 B9 C8 AC 1F DC mov     r9d, 0DC1FACC8h
.text:00007FF720B12E4D 44 89 CF          mov     edi, r9d
.text:00007FF720B12E50 8B 9C 24 9C 01 00 mov     ebx, [rsp+508h+var_36C]
.text:00007FF720B12E50 00
.text:00007FF720B12E57 29 DF             sub     edi, ebx
.text:00007FF720B12E59 4C 63 D7          movsxd  r10, edi
.text:00007FF720B12E5C 4C 01 D2          add     rdx, r10
.text:00007FF720B12E5F 4C 8B 15 8A FC 02 mov     r10, cs:off_7FF720B42AF0
.text:00007FF720B12E5F 00
.text:00007FF720B12E66 44 89 CF          mov     edi, r9d
.text:00007FF720B12E69 29 DF             sub     edi, ebx
.text:00007FF720B12E6B 4C 63 DF          movsxd  r11, edi
.text:00007FF720B12E6E 4F 8B 94 1A B0 00 mov     r10, [r10+r11+0B0h]
.text:00007FF720B12E6E 00 00
.text:00007FF720B12E76 41 29 D9          sub     r9d, ebx
.text:00007FF720B12E79 4D 63 D9          movsxd  r11, r9d
.text:00007FF720B12E7C 4D 01 DA          add     r10, r11
.text:00007FF720B12E7F 89 84 24 DC 00 00 mov     [rsp+508h+var_42C], eax
.text:00007FF720B12E7F 00
.text:00007FF720B12E86 41 FF D2          call    r10             ; call 00007FF61F97DE40->core_fun
```
猜测sub_14000DE40就是对第一次输入处理的关键函数    
调用约定也可以看出，rcx是明文，r8里的值在call之后指向的是一块连续的hex    
给这串字符串下硬件断点    
再次断下,然后返回就是strcmp了   
```asm
.text:00007FF720B13072 48 8D 8C 24 F0 01 lea     rcx, [rsp+508h+enc_data]
.text:00007FF720B13072 00 00
.text:00007FF720B1307A 48 8B 15 DF FA 02 mov     rdx, cs:off_7FF720B42B60
.text:00007FF720B1307A 00
.text:00007FF720B13081 B8 C8 AC 1F DC    mov     eax, 0DC1FACC8h
.text:00007FF720B13086 41 89 C0          mov     r8d, eax
.text:00007FF720B13089 44 8B 9C 24 9C 01 mov     r11d, [rsp+508h+var_36C]
.text:00007FF720B13089 00 00
.text:00007FF720B13091 45 29 D8          sub     r8d, r11d
.text:00007FF720B13094 4D 63 C8          movsxd  r9, r8d
.text:00007FF720B13097 4C 01 CA          add     rdx, r9
.text:00007FF720B1309A 4C 8B 0D 4F FA 02 mov     r9, cs:off_7FF720B42AF0
.text:00007FF720B1309A 00
.text:00007FF720B130A1 41 89 C0          mov     r8d, eax
.text:00007FF720B130A4 45 29 D8          sub     r8d, r11d
.text:00007FF720B130A7 4D 63 D0          movsxd  r10, r8d
.text:00007FF720B130AA 4F 8B 8C 11 D0 00 mov     r9, [r9+r10+0D0h]
.text:00007FF720B130AA 00 00
.text:00007FF720B130B2 44 29 D8          sub     eax, r11d
.text:00007FF720B130B5 4C 63 D0          movsxd  r10, eax
.text:00007FF720B130B8 4D 01 D1          add     r9, r10         ; rdx = enc_data
.text:00007FF720B130BB 41 FF D1          call    r9              ; call strcmp
```
此时发现rdx的值我们怎么输入都不变，所以是密文，rcx的值于我们之前看到的连续的hex一样，也就是我们自己的数据加密后的结果   
自此分析结束，关键函数为sub_14000DE40，而且有平坦化特征，无法避免的,老规矩  
寻找真实块   
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

    real_blocks = []

    blocks = idaapi.FlowChart(idaapi.get_func(fun_ea))
    loop_head_addr= 0x14001015D
    loop_head_block = get_basic_block(loop_head_addr)
    blocks =  list(loop_head_block.preds())
    for block in blocks:
        start_ea = block.start_ea
        real_blocks.append(start_ea)
    print("所有真实块地址:", [hex(x) for x in real_blocks],"数量",len(real_blocks))
find_all_real_blocks(0x14000DE40)

所有真实块地址: ['0x14000f50e', '0x14000f513', '0x14000f548', '0x14000f57d', '0x14000f5b2', '0x14000f5d5', '0x14000f6bb', '0x14000f6d3', '0x14000f79e', '0x14000f7b6', '0x14000f87e', '0x14000f8b1', '0x14000f8c9', '0x14000f986', '0x14000f99e', '0x14000fa56', '0x14000fa6e', '0x14000fb27', '0x14000fb3f', '0x14000fbf8', '0x14000fc10', '0x14000fc97', '0x14000fcaf', '0x14000fcd2', '0x14000fd05', '0x14000fdbd', '0x14000fde6', '0x14000fea9', '0x14000fef7', '0x14000ff53', '0x14000ff88', '0x14001001f', '0x140010054', '0x1400100a2', '0x1400100d7', '0x140010128'] 数量 36
```
寻找关系。。。  
```python
from typing import Dict, List, Optional, Set, Tuple

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
from unicorn import (
    Uc,
    UcError,
    UC_ARCH_X86,
    UC_MODE_64,
    UC_HOOK_CODE,
    UC_HOOK_BLOCK,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_MEM_FETCH_UNMAPPED,
)
import unicorn.x86_const as uc_x86_const
from unicorn.x86_const import *


# =========================
# User-configurable section
# =========================
EXE_PATH = r"D:\reverse\xmcve\server.exe"

PROLOGUE_START = 0x14000DE40
PROLOGUE_END = 0x14000DEF6

# If None, derive module base from PROLOGUE_START with 64KB alignment.
MODULE_BASE: Optional[int] = None

REAL_BLOCKS: List[int] = [
    0x14000F50E,
    0x14000F513,
    0x14000F548,
    0x14000F57D,
    0x14000F5B2,
    0x14000F5D5,
    0x14000F6BB,
    0x14000F6D3,
    0x14000F79E,
    0x14000F7B6,
    0x14000F87E,
    0x14000F8B1,
    0x14000F8C9,
    0x14000F986,
    0x14000F99E,
    0x14000FA56,
    0x14000FA6E,
    0x14000FB27,
    0x14000FB3F,
    0x14000FBF8,
    0x14000FC10,
    0x14000FC97,
    0x14000FCAF,
    0x14000FCD2,
    0x14000FD05,
    0x14000FDBD,
    0x14000FDE6,
    0x14000FEA9,
    0x14000FEF7,
    0x14000FF53,
    0x14000FF88,
    0x14001001F,
    0x140010054,
    0x1400100A2,
    0x1400100D7,
    0x140010128,
]

STACK_BASE = 0x00100000
STACK_SIZE = 0x00200000

# Safety limits
MAX_INS_PER_BLOCK = 80000
MAX_SCAN_INS = 120
MAX_SCAN_BYTES = 0x500

# Debug switches
DEBUG = True
TRACE_INSN = True
TRACE_INSN_LIMIT_PER_RUN = 120


class RelationFinder:
    def __init__(self) -> None:
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self.real_blocks: List[int] = sorted(REAL_BLOCKS)
        self.real_blocks_set: Set[int] = set(self.real_blocks)
        self.ready_ctx = None
        self.image_base: Optional[int] = None

        # address -> single successor
        self.single_rel: Dict[int, Optional[int]] = {}
        # address -> (mnem, succ_true, succ_false)
        self.branch_rel: Dict[int, Tuple[str, Optional[int], Optional[int]]] = {}
        self.call_records: List[Tuple[int, Optional[int]]] = []

        self._trace_count = 0

    def log(self, msg: str) -> None:
        if DEBUG:
            print(msg)

    # -------------------------
    # Memory / PE initialization
    # -------------------------
    def load_pe(self) -> None:
        pe = pefile.PE(EXE_PATH)
        preferred_base = pe.OPTIONAL_HEADER.ImageBase
        load_base = MODULE_BASE if MODULE_BASE is not None else (PROLOGUE_START & ~0xFFFF)
        self.image_base = load_base
        self.log(
            f"[load] preferred_base={hex(preferred_base)} load_base={hex(load_base)} "
            f"prologue={hex(PROLOGUE_START)}"
        )

        header_size = (pe.OPTIONAL_HEADER.SizeOfHeaders + 0xFFF) & ~0xFFF
        self.uc.mem_map(load_base, header_size)
        self.uc.mem_write(load_base, pe.header)

        max_addr = load_base + header_size

        for section in pe.sections:
            va = section.VirtualAddress
            vsize = section.Misc_VirtualSize
            data = section.get_data()

            map_addr = load_base + va
            map_start = map_addr & ~0xFFF
            map_end = (map_addr + vsize + 0xFFF) & ~0xFFF

            if map_end > max_addr:
                addr_to_map = max(map_start, max_addr)
                size_to_map = map_end - addr_to_map
                if size_to_map > 0:
                    self.uc.mem_map(addr_to_map, size_to_map)
                    max_addr = map_end

            self.uc.mem_write(load_base + va, data)

        self.log(f"[load] PE mapped complete, max_mapped={hex(max_addr)}")

    # ----------------
    # Unicorn callbacks
    # ----------------
    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        page_start = address & ~0xFFF
        try:
            uc.mem_map(page_start, 0x1000)
            return True
        except Exception:
            return False

    def hook_skip_calls(self, uc, address, size, user_data):
        try:
            code = uc.mem_read(address, size)
            insn = None
            for item in self.cs.disasm(code, address):
                insn = item
                break

            if TRACE_INSN and self._trace_count < TRACE_INSN_LIMIT_PER_RUN and insn is not None:
                self._trace_count += 1
                self.log(f"[insn] {hex(address)}: {insn.mnemonic} {insn.op_str}")

            # Ignore all call instructions unconditionally.
            if insn is not None and insn.mnemonic.lower() == "call":
                target_addr = self._resolve_call_target(insn, address, size)
                self.call_records.append((address, target_addr))
                target_repr = hex(target_addr) if target_addr is not None else "unknown"
                self.log(f"call on {hex(address)}, target addr: {target_repr}")
                uc.reg_write(UC_X86_REG_RAX, 1)
                uc.reg_write(UC_X86_REG_RIP, address + size)
                self.log(f"[call-skip] {hex(address)}")
        except Exception:
            pass

    def _uc_reg_id_from_name(self, name: str) -> Optional[int]:
        uc_name = f"UC_X86_REG_{name.upper()}"
        return getattr(uc_x86_const, uc_name, None)

    def _resolve_call_target(self, insn, address: int, size: int) -> Optional[int]:
        try:
            if not insn.operands:
                return None

            op = insn.operands[0]

            if op.type == X86_OP_IMM:
                return int(op.imm) & 0xFFFFFFFFFFFFFFFF

            if op.type == X86_OP_REG:
                reg_name = insn.reg_name(op.reg)
                reg_id = self._uc_reg_id_from_name(reg_name)
                if reg_id is None:
                    return None
                return int(self.uc.reg_read(reg_id)) & 0xFFFFFFFFFFFFFFFF

            if op.type == X86_OP_MEM:
                mem = op.mem
                eff = int(mem.disp)

                if mem.base != 0:
                    if mem.base == X86_REG_RIP:
                        eff += address + size
                    else:
                        base_name = insn.reg_name(mem.base)
                        base_id = self._uc_reg_id_from_name(base_name)
                        if base_id is not None:
                            eff += int(self.uc.reg_read(base_id))

                if mem.index != 0 and mem.scale != 0:
                    idx_name = insn.reg_name(mem.index)
                    idx_id = self._uc_reg_id_from_name(idx_name)
                    if idx_id is not None:
                        eff += int(self.uc.reg_read(idx_id)) * int(mem.scale)

                ptr = self.uc.mem_read(eff & 0xFFFFFFFFFFFFFFFF, 8)
                return int.from_bytes(ptr, byteorder="little", signed=False)
        except Exception:
            return None

        return None

    def _match_real_block(self, address: int) -> Optional[int]:
        # Some executions may land at block+1 due to prefix or alignment artifacts.
        if address in self.real_blocks_set:
            return address
        if (address - 1) in self.real_blocks_set:
            return address - 1
        return None

    def hook_find_next_real(self, uc, address, size, user_data):
        found = self._match_real_block(address)
        if found is None:
            return

        current = user_data["current_start"]
        if found != current:
            user_data["succ"] = found
            self.log(f"[succ] {hex(current)} -> {hex(found)}")
            uc.emu_stop()

    # --------------
    # Helper routines
    # --------------
    def _mnemonic(self, address: int) -> str:
        try:
            code = self.uc.mem_read(address, 15)
            for insn in self.cs.disasm(code, address):
                return insn.mnemonic.lower()
        except Exception:
            pass
        return ""

    def _is_cmov(self, mnem: str) -> bool:
        return mnem.startswith("cmov") and mnem != "cmovs" and mnem != "cmovns"

    def _find_first_cmov(self, block_addr: int) -> Optional[int]:
        try:
            code = self.uc.mem_read(block_addr, MAX_SCAN_BYTES)
            count = 0
            for insn in self.cs.disasm(code, block_addr):
                if insn.address != block_addr and insn.address in self.real_blocks_set:
                    break
                m = insn.mnemonic.lower()
                if m.startswith("cmov"):
                    return insn.address
                count += 1
                if count >= MAX_SCAN_INS:
                    break
        except Exception:
            return None
        return None

    @staticmethod
    def _set_flags_for_cond(eflags: int, cond: str, take_true: bool) -> int:
        # Only control ZF/SF/OF/CF as needed by x86 condition semantics.
        ZF = 1 << 6
        SF = 1 << 7
        CF = 1 << 0
        OF = 1 << 11
        flags = eflags & ~(ZF | SF | CF | OF)

        def set_zf(v: int):
            nonlocal flags
            if v:
                flags |= ZF

        def set_sf(v: int):
            nonlocal flags
            if v:
                flags |= SF

        def set_cf(v: int):
            nonlocal flags
            if v:
                flags |= CF

        def set_of(v: int):
            nonlocal flags
            if v:
                flags |= OF

        cond = cond.lower()

        if cond in ("e", "z"):
            set_zf(1 if take_true else 0)
        elif cond in ("ne", "nz"):
            set_zf(0 if take_true else 1)
        elif cond == "l":
            if take_true:
                set_sf(1)
                set_of(0)
            else:
                set_sf(0)
                set_of(0)
        elif cond == "le":
            if take_true:
                set_zf(1)
            else:
                set_zf(0)
                set_sf(0)
                set_of(0)
        elif cond == "g":
            if take_true:
                set_zf(0)
                set_sf(0)
                set_of(0)
            else:
                set_zf(1)
        elif cond == "ge":
            if take_true:
                set_sf(0)
                set_of(0)
            else:
                set_sf(1)
                set_of(0)
        elif cond == "b":
            set_cf(1 if take_true else 0)
        elif cond == "be":
            if take_true:
                set_cf(1)
            else:
                set_cf(0)
                set_zf(0)
        elif cond == "a":
            if take_true:
                set_cf(0)
                set_zf(0)
            else:
                set_cf(1)
        elif cond == "ae":
            set_cf(0 if take_true else 1)
        elif cond == "s":
            set_sf(1 if take_true else 0)
        elif cond == "ns":
            set_sf(0 if take_true else 1)
        elif cond == "o":
            set_of(1 if take_true else 0)
        elif cond == "no":
            set_of(0 if take_true else 1)
        else:
            # Conservative fallback: split by ZF only.
            set_zf(1 if take_true else 0)

        return flags

    def _cmov_cond_suffix(self, mnem: str) -> str:
        # cmovz -> z, cmovge -> ge, etc.
        return mnem[4:].lower()

    def _run_from(self, start_addr: int, current_start: int, max_ins: int = MAX_INS_PER_BLOCK) -> Optional[int]:
        self._trace_count = 0
        self.log(f"[run] start={hex(start_addr)} current={hex(current_start)} max_ins={max_ins}")
        user_data = {
            "current_start": current_start,
            "succ": None,
        }
        h_block = self.uc.hook_add(UC_HOOK_BLOCK, self.hook_find_next_real, user_data)
        h_code = self.uc.hook_add(UC_HOOK_CODE, self.hook_skip_calls)
        try:
            self.uc.emu_start(start_addr, 0, 0, max_ins)
        except UcError as e:
            self.log(f"[run-error] start={hex(start_addr)} err={e}")
        except Exception as e:
            self.log(f"[run-exception] start={hex(start_addr)} err={e}")
        finally:
            self.uc.hook_del(h_block)
            self.uc.hook_del(h_code)
        self.log(f"[run-end] start={hex(start_addr)} succ={hex(user_data['succ']) if user_data['succ'] else 'None'}")
        return user_data["succ"]

    # ----------------------
    # Core analysis procedure
    # ----------------------
    def prepare_ready_context(self) -> None:
        self.log("[prepare] begin")
        self.load_pe()
        self.uc.mem_map(STACK_BASE, STACK_SIZE)
        self.uc.reg_write(UC_X86_REG_RSP, STACK_BASE + STACK_SIZE - 0x1000)
        self.log(
            f"[prepare] stack_base={hex(STACK_BASE)} stack_top={hex(STACK_BASE + STACK_SIZE - 0x1000)}"
        )

        self.uc.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
            self.hook_mem_invalid,
        )

        # Execute prologue head -> tail, then save exactly one ready state.
        self.uc.reg_write(UC_X86_REG_RIP, PROLOGUE_START)
        self._trace_count = 0
        h_code = self.uc.hook_add(UC_HOOK_CODE, self.hook_skip_calls)
        try:
            try:
                self.uc.emu_start(PROLOGUE_START, PROLOGUE_END, 0, 50000)
                self.log("[prepare] prologue executed")
            except Exception as e:
                self.log(f"[prepare-error] prologue err={e}")
        finally:
            self.uc.hook_del(h_code)

        self.ready_ctx = self.uc.context_save()
        rip = self.uc.reg_read(UC_X86_REG_RIP)
        rsp = self.uc.reg_read(UC_X86_REG_RSP)
        self.log(f"[prepare] ready_ctx saved rip={hex(rip)} rsp={hex(rsp)}")

    def analyze_one_block(self, block_addr: int) -> None:
        self.log(f"[block] analyze {hex(block_addr)}")
        # Every block starts from the same "prologue tail" state.
        self.uc.context_restore(self.ready_ctx)
        self.uc.reg_write(UC_X86_REG_RIP, block_addr)

        cmov_addr = self._find_first_cmov(block_addr)
        self.log(f"[block] first_cmov={hex(cmov_addr) if cmov_addr else 'None'}")

        if cmov_addr is None:
            succ = self._run_from(block_addr, block_addr)
            self.single_rel[block_addr] = succ
            return

        # Branch-like block (contains cmovxx): split true/false from cmov site.
        mnem = self._mnemonic(cmov_addr)
        cond = self._cmov_cond_suffix(mnem) if mnem.startswith("cmov") else "z"

        self.uc.context_restore(self.ready_ctx)
        self.uc.reg_write(UC_X86_REG_RIP, block_addr)
        self._trace_count = 0
        h_code = self.uc.hook_add(UC_HOOK_CODE, self.hook_skip_calls)
        try:
            self.uc.emu_start(block_addr, cmov_addr, 0, 50000)
        except UcError as e:
            self.log(f"[block-error] to_cmov {hex(block_addr)} err={e}")
        except Exception as e:
            self.log(f"[block-exception] to_cmov {hex(block_addr)} err={e}")
        finally:
            self.uc.hook_del(h_code)

        self.uc.reg_write(UC_X86_REG_RIP, cmov_addr)
        ctx_at_cmov = self.uc.context_save()
        base_flags = self.uc.reg_read(UC_X86_REG_EFLAGS)

        # True path: cmov condition satisfied.
        self.uc.context_restore(ctx_at_cmov)
        self.uc.reg_write(UC_X86_REG_EFLAGS, self._set_flags_for_cond(base_flags, cond, True))
        succ_true = self._run_from(cmov_addr, block_addr)

        # False path: cmov condition not satisfied.
        self.uc.context_restore(ctx_at_cmov)
        self.uc.reg_write(UC_X86_REG_EFLAGS, self._set_flags_for_cond(base_flags, cond, False))
        succ_false = self._run_from(cmov_addr, block_addr)

        self.branch_rel[block_addr] = (mnem, succ_true, succ_false)
        self.log(
            f"[block-branch] {hex(block_addr)} cond={cond} true={hex(succ_true) if succ_true else 'None'} "
            f"false={hex(succ_false) if succ_false else 'None'}"
        )

    def run(self) -> None:
        self.log("[run] start relation analysis")
        try:
            self.prepare_ready_context()
        except Exception as e:
            self.log(f"[fatal] prepare failed: {e}")
            return

        for addr in self.real_blocks:
            try:
                self.analyze_one_block(addr)
            except Exception as e:
                # Ignore block-level analysis errors and continue.
                self.log(f"[warn] block failed {hex(addr)}: {e}")
                continue
        self.log(
            f"[run] done single={len(self.single_rel)} branch={len(self.branch_rel)}"
        )

    # --------
    # Printing
    # --------
    def print_result(self) -> None:
        print("# Call records")
        for call_addr, target_addr in self.call_records:
            t = hex(target_addr) if target_addr is not None else "unknown"
            print(f"call on {hex(call_addr)}, target addr: {t}")

        print("\n# Single successor blocks")
        print("single_rel = {")
        for src in sorted(self.single_rel.keys()):
            dst = self.single_rel[src]
            dst_str = f"{hex(dst)}" if dst is not None else "None"
            print(f"    {hex(src)}: {dst_str},")
        print("}")

        print("\n# Cmov split blocks (left=true, right=false)")
        branch_groups: Dict[str, Dict[int, Tuple[Optional[int], Optional[int]]]] = {}
        for src in sorted(self.branch_rel.keys()):
            mnem, t, f = self.branch_rel[src]
            if mnem not in branch_groups:
                branch_groups[mnem] = {}
            branch_groups[mnem][src] = (t, f)
            
        for mnem in sorted(branch_groups.keys()):
            print(f"\nbranch_{mnem} = {{")
            for src, (t, f) in branch_groups[mnem].items():
                t_str = hex(t) if t is not None else "None"
                f_str = hex(f) if f is not None else "None"
                print(f"    {hex(src)}: ({t_str}, {f_str}),")
            print("}")

        try:
            with open("call_records.log", "w", encoding="utf-8") as f:
                for call_addr, target_addr in self.call_records:
                    t = hex(target_addr) if target_addr is not None else "unknown"
                    f.write(f"call on {hex(call_addr)}, target addr: {t}\n")
        except Exception:
            pass


def main() -> None:
    finder = RelationFinder()
    finder.run()
    finder.print_result()


if __name__ == "__main__":
    main()

```
特别，里面的call reg的我们全部记录call的地址，为了之后把间接call也一并处理了    
```text
call on 0x14000f678, target addr: 0x140010170
call on 0x14000f75c, target addr: 0x14001017c
call on 0x14000f83c, target addr: 0x14001017c
call on 0x14000f902, target addr: 0x140010d10
call on 0x14000f943, target addr: 0x140010d1c
call on 0x14000fa13, target addr: 0x1400101a0
call on 0x14000faa1, target addr: 0x140025570
call on 0x14000fae4, target addr: 0x1400101a6
call on 0x14000fb72, target addr: 0x140025570
call on 0x14000fbb5, target addr: 0x1400101a6
call on 0x14000fc55, target addr: 0x1400101ac
call on 0x14000fe29, target addr: 0x140010d10
call on 0x14000fe6d, target addr: 0x140010d16
call on 0x14000fedc, target addr: 0x1400101b2
call on 0x14000ff2d, target addr: 0x14001019a
call on 0x14000ffbf, target addr: 0x140010d10
call on 0x140010003, target addr: 0x140010d16
call on 0x140010087, target addr: 0x1400101b2
call on 0x14001010d, target addr: 0x14001019a

# Single successor blocks
single_rel = {
    0x14000f50e: 0x14000f513,
    0x14000f5b2: None,
    0x14000f6bb: 0x14000ff53,
    0x14000f79e: 0x14000ff53,
    0x14000f8b1: 0x14000ff53,
    0x14000f986: 0x14000ff53,
    0x14000fa56: 0x14000ff53,
    0x14000fb27: 0x14000ff53,
    0x14000fbf8: 0x14000ff53,
    0x14000fc97: 0x14000ff53,
    0x14000fcaf: 0x14000fcd2,
    0x14000fd05: 0x14000fdbd,
    0x14000fdbd: 0x14000fcd2,
    0x14000fea9: 0x14000fef7,
    0x14000fef7: None,
    0x14000ff88: 0x14001001f,
    0x140010054: 0x1400100a2,
    0x1400100d7: 0x140010128,
    0x140010128: None,
}

# Cmov split blocks (left=true, right=false)

branch_cmovge = {
    0x14000f5d5: (0x14000f6d3, 0x14000f6bb),
    0x14000f6d3: (0x14000f7b6, 0x14000f79e),
    0x14000f7b6: (0x14000f87e, 0x14000f8b1),
    0x14000f99e: (0x14000fa6e, 0x14000fa56),
    0x14000fa6e: (0x14000fb3f, 0x14000fb27),
    0x14000fb3f: (0x14000fc10, 0x14000fbf8),
    0x14000fc10: (0x14000fcaf, 0x14000fc97),
}

branch_cmovl = {
    0x14000fcd2: (0x14000fd05, 0x14000fde6),
}

branch_cmovne = {
    0x14000f513: (0x14000f548, 0x14000f5b2),
    0x14000f548: (0x14000f57d, 0x14000f5b2),
    0x14000f57d: (0x14000f5d5, 0x14000f5b2),
    0x14000f87e: (0x14000f8b1, 0x14000f8c9),
    0x14000f8c9: (0x14000f99e, 0x14000f986),
    0x14000fde6: (0x14000fea9, 0x14000fef7),
    0x14000ff53: (0x14000ff88, 0x14001001f),
    0x14001001f: (0x140010054, 0x1400100a2),
    0x1400100a2: (0x1400100d7, 0x140010128),
}
``` 
然后patch   
```python
import ida_funcs
import idaapi
import idautils
import idc

# Data Dictionaries

call_records = {
    0x14000f678: 0x140010170,
    0x14000f75c: 0x14001017c,
    0x14000f83c: 0x14001017c,
    0x14000f902: 0x140010d10,
    0x14000f943: 0x140010d1c,
    0x14000fa13: 0x1400101a0,
    0x14000faa1: 0x140025570,
    0x14000fae4: 0x1400101a6,
    0x14000fb72: 0x140025570,
    0x14000fbb5: 0x1400101a6,
    0x14000fc55: 0x1400101ac,
    0x14000fe29: 0x140010d10,
    0x14000fe6d: 0x140010d16,
    0x14000fedc: 0x1400101b2,
    0x14000ff2d: 0x14001019a,
    0x14000ffbf: 0x140010d10,
    0x140010003: 0x140010d16,
    0x140010087: 0x1400101b2,
    0x14001010d: 0x14001019a,
}

single_rel = {
    0x14000DE40: 0x14000f513, # Prologue
    0x14000f50e: 0x14000f513,
    0x14000f5b2: None,
    0x14000f6bb: 0x14000ff53,
    0x14000f79e: 0x14000ff53,
    0x14000f8b1: 0x14000ff53,
    0x14000f986: 0x14000ff53,
    0x14000fa56: 0x14000ff53,
    0x14000fb27: 0x14000ff53,
    0x14000fbf8: 0x14000ff53,
    0x14000fc97: 0x14000ff53,
    0x14000fcaf: 0x14000fcd2,
    0x14000fd05: 0x14000fdbd,
    0x14000fdbd: 0x14000fcd2,
    0x14000fea9: 0x14000fef7,
    0x14000fef7: None,
    0x14000ff88: 0x14001001f,
    0x140010054: 0x1400100a2,
    0x1400100d7: 0x140010128,
    0x140010128: None,
}

branch_cmovge = {
    0x14000f5d5: (0x14000f6d3, 0x14000f6bb),
    0x14000f6d3: (0x14000f7b6, 0x14000f79e),
    0x14000f7b6: (0x14000f87e, 0x14000f8b1),
    0x14000f99e: (0x14000fa6e, 0x14000fa56),
    0x14000fa6e: (0x14000fb3f, 0x14000fb27),
    0x14000fb3f: (0x14000fc10, 0x14000fbf8),
    0x14000fc10: (0x14000fcaf, 0x14000fc97),
}

branch_cmovl = {
    0x14000fcd2: (0x14000fd05, 0x14000fde6),
}

branch_cmovne = {
    0x14000f513: (0x14000f548, 0x14000f5b2),
    0x14000f548: (0x14000f57d, 0x14000f5b2),
    0x14000f57d: (0x14000f5d5, 0x14000f5b2),
    0x14000f87e: (0x14000f8b1, 0x14000f8c9),
    0x14000f8c9: (0x14000f99e, 0x14000f986),
    0x14000fde6: (0x14000fea9, 0x14000fef7),
    0x14000ff53: (0x14000ff88, 0x14001001f),
    0x14001001f: (0x140010054, 0x1400100a2),
    0x1400100a2: (0x1400100d7, 0x140010128),
}

jcc_map = {
    "cmovge": 0x8D,
    "cmovl": 0x8C,
    "cmovne": 0x85,
    "cmovnz": 0x85,
}

FUNC_EA = 0x14000DE40
PROLOGUE_START = 0x14000DE40
PROLOGUE_END = 0x14000DE96
MAIN_DISPATCHER_END = 0x14000DEF6
ENABLE_NOP_USELESS_BLOCKS = False

patched_call_sites = {}
patched_double_sites = []
patched_single_sites = []


def build_reserved_ranges_for_calls():
    ranges = []
    for ea in call_records.keys():
        ranges.append((ea, ea + 5))
    return ranges


def range_overlaps(start, size, reserved_ranges):
    end = start + size
    for rs, re in reserved_ranges:
        if not (end <= rs or start >= re):
            return True
    return False

def patch_bytes(addr, data):
    for i, b in enumerate(data):
        idc.patch_byte(addr + i, b)


def fill_nop(start_ea, end_ea):
    size = end_ea - start_ea
    if size > 0:
        patch_bytes(start_ea, b"\x90" * size)


def get_block_by_address(ea):
    func = idaapi.get_func(ea)
    if not func:
        return None
    for block in idaapi.FlowChart(func):
        if block.start_ea <= ea < block.end_ea:
            return block
    return None


def find_patch_site(block, needed_size, reserved_ranges=None):
    """从块尾向前寻找一个安全覆盖 needed_size 字节的起点。"""
    ea = idc.prev_head(block.end_ea)
    if ea == idc.BADADDR or ea < block.start_ea:
        return None
    end = block.end_ea
    while ea != idc.BADADDR and ea >= block.start_ea:
        if end - ea >= needed_size:
            if reserved_ranges and range_overlaps(ea, needed_size, reserved_ranges):
                ea = idc.prev_head(ea)
                continue
            return ea
        ea = idc.prev_head(ea)
    return None


def find_last_jmp_in_block(block):
    cur = idc.prev_head(block.end_ea)
    while cur != idc.BADADDR and cur >= block.start_ea:
        if idc.print_insn_mnem(cur).startswith("jmp"):
            return cur
        cur = idc.prev_head(cur)
    return None


def find_cmov_from_head(head_ea, cmov_name, max_steps=220):
    """从关系字典给出的块头线性向后扫描 cmov，避免 CFG 分块导致漏检。"""
    cur = head_ea
    for _ in range(max_steps):
        if cur == idc.BADADDR:
            break
        mnem = idc.print_insn_mnem(cur)
        if mnem == cmov_name or (cmov_name == "cmovne" and mnem == "cmovnz"):
            return cur
        if mnem == "jmp":
            break
        nxt = idc.next_head(cur)
        if nxt == idc.BADADDR or nxt <= cur:
            break
        cur = nxt
    return None


def generate_rel_jmp(src, dst):
    return b"\xE9" + (dst - (src + 5)).to_bytes(4, "little", signed=True)


def generate_rel_call(src, dst):
    return b"\xE8" + (dst - (src + 5)).to_bytes(4, "little", signed=True)


def generate_rel_jcc(src, dst, opcode_low):
    return bytes([0x0F, opcode_low]) + (dst - (src + 6)).to_bytes(4, "little", signed=True)


def collect_real_block_heads():
    real = set()
    for ea, succ in single_rel.items():
        real.add(ea)
        if succ is not None:
            real.add(succ)
    for branch in (branch_cmovge, branch_cmovl, branch_cmovne):
        for ea, (t, f) in branch.items():
            real.add(ea)
            real.add(t)
            real.add(f)
    return real


def patch_calls():
    print("[*] step1: patch direct calls")
    for call_ea, target_ea in call_records.items():
        next_ea = call_ea
        while next_ea < call_ea + 5:
            size = idc.get_item_size(next_ea)
            if size <= 0:
                size = 1
            next_ea += size

        patch_bytes(call_ea, generate_rel_call(call_ea, target_ea))
        patched_call_sites[call_ea] = target_ea
        if next_ea > call_ea + 5:
            fill_nop(call_ea + 5, next_ea)


def patch_double_successors(branch_dict, cmov_name):
    patched = 0
    jcc_opcode = jcc_map[cmov_name]
    for ea, (true_ea, false_ea) in branch_dict.items():
        cmov_ea = find_cmov_from_head(ea, cmov_name)

        if cmov_ea is None:
            print("[!] no", cmov_name, "near", hex(ea))
            continue

        jcc_code = generate_rel_jcc(cmov_ea, true_ea, jcc_opcode)
        jmp_ea = cmov_ea + len(jcc_code)
        jmp_code = generate_rel_jmp(jmp_ea, false_ea)
        patch_bytes(cmov_ea, jcc_code)
        patch_bytes(jmp_ea, jmp_code)
        patched_double_sites.append((cmov_ea, true_ea, false_ea, jcc_opcode))
        patched += 1

    print("[*] double", cmov_name, "patched:", patched)


def patch_single_successors():
    print("[*] step3: patch single successors")
    patched = 0
    reserved_ranges = build_reserved_ranges_for_calls()
    for ea, succ in single_rel.items():
        block = get_block_by_address(ea)
        if not block:
            print("[!] skip single block, no block:", hex(ea))
            continue

        if succ is None:
            patch_ea = find_patch_site(block, 1)
            if patch_ea is None:
                print("[!] cannot find ret site:", hex(ea))
                continue
            patch_bytes(patch_ea, b"\xC3")
            fill_nop(patch_ea + 1, block.end_ea)
            patched_single_sites.append((patch_ea, None))
            patched += 1
            continue

        patch_ea = find_last_jmp_in_block(block)
        if patch_ea is None:
            patch_ea = find_patch_site(block, 5, reserved_ranges)
        if patch_ea is None:
            print("[!] cannot find jmp site:", hex(ea))
            continue
        if range_overlaps(patch_ea, 5, reserved_ranges):
            print("[!] jmp site overlaps call, skip:", hex(ea), "site:", hex(patch_ea))
            continue
        patch_bytes(patch_ea, generate_rel_jmp(patch_ea, succ))
        fill_nop(patch_ea + 5, block.end_ea)
        patched_single_sites.append((patch_ea, succ))
        patched += 1

    print("[*] single patched:", patched)


def patch_useless_blocks(real_heads):
    print("[*] step4: nop useless blocks")
    func = idaapi.get_func(FUNC_EA)
    if not func:
        print("[!] no function at", hex(FUNC_EA))
        return

    useless = []
    for block in idaapi.FlowChart(func):
        if block.start_ea not in real_heads:
            useless.append((block.start_ea, block.end_ea))

    for start_ea, end_ea in useless:
        fill_nop(start_ea, end_ea)
    print("[*] useless block count:", len(useless))


def final_fixup_patches():
    """最后重写关键跳转/调用，避免被后续 nop 覆盖导致立即数损坏。"""
    print("[*] step5: final fixup patches")

    for call_ea, target_ea in patched_call_sites.items():
        patch_bytes(call_ea, generate_rel_call(call_ea, target_ea))

    for cmov_ea, true_ea, false_ea, jcc_opcode in patched_double_sites:
        jcc_code = generate_rel_jcc(cmov_ea, true_ea, jcc_opcode)
        jmp_ea = cmov_ea + len(jcc_code)
        jmp_code = generate_rel_jmp(jmp_ea, false_ea)
        patch_bytes(cmov_ea, jcc_code)
        patch_bytes(jmp_ea, jmp_code)

    for patch_ea, succ in patched_single_sites:
        if succ is None:
            patch_bytes(patch_ea, b"\xC3")
        else:
            patch_bytes(patch_ea, generate_rel_jmp(patch_ea, succ))

    print("[*] fixup call count:", len(patched_call_sites))
    print("[*] fixup double count:", len(patched_double_sites))
    print("[*] fixup single count:", len(patched_single_sites))


def main():
    print("[*] prologue:", hex(PROLOGUE_START), "-", hex(PROLOGUE_END))
    print("[*] dispatcher end:", hex(MAIN_DISPATCHER_END))

    real_heads = collect_real_block_heads()
    print("[*] real block head count:", len(real_heads))

    patch_calls()
    patch_double_successors(branch_cmovge, "cmovge")
    patch_double_successors(branch_cmovl, "cmovl")
    patch_double_successors(branch_cmovne, "cmovne")
    patch_single_successors()
    if ENABLE_NOP_USELESS_BLOCKS:
        patch_useless_blocks(real_heads)
    else:
        print("[*] step4 skipped: nop useless blocks disabled")
    final_fixup_patches()

    ida_funcs.reanalyze_function(ida_funcs.get_func(FUNC_EA))
    print("[+] done")


if __name__ == "__main__":
    main()

```
f5清晰多了，但是还是有一些offset之类的不透明词，参考我vt那一篇：https://qmeimei10086.github.io/2026/01/22/  %E9%95%BF%E5%9F%8E%E6%9D%AF-2024-vt-%E6%89%B9%E9%87%8F%E5%8E%BB%E8%8A%B1+%E5%8E%BB%E4%B8%8D%E9%80%8F%E6%98%8E%E8%AF%8D+crc32%E7%88%86%E7%A0%B4/    
写个小脚本去除一定范围内的不透明词，地址自己改  
```python
import re
import idaapi
import idautils
import idc

# ===== 用户填写 =====
START_EA = 0x140002000
END_EA = 0x140003A50

# True: 允许把 7 字节的 "mov reg, [rip+off]" 扩成 10 字节 "mov reg, imm64"（会吃掉后续若干字节）
# False: 只做安全替换（能放进原长度时才 patch）
ALLOW_WIDE_PATCH = True

# 仅处理这类模式：mov reg, cs:off_xxx
PATTERN = re.compile(r"^\s*mov\s+([a-z0-9]+)\s*,\s*cs:off_([0-9a-fA-F]+)", re.IGNORECASE)

REG64_ORDER = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
]

REG32_MAP = {
    "rax": "eax", "rcx": "ecx", "rdx": "edx", "rbx": "ebx",
    "rsp": "esp", "rbp": "ebp", "rsi": "esi", "rdi": "edi",
    "r8": "r8d", "r9": "r9d", "r10": "r10d", "r11": "r11d",
    "r12": "r12d", "r13": "r13d", "r14": "r14d", "r15": "r15d",
}


def patch_bytes(addr, data):
    for i, b in enumerate(data):
        idc.patch_byte(addr + i, b)


def fill_nop(start_ea, end_ea):
    sz = end_ea - start_ea
    if sz > 0:
        patch_bytes(start_ea, b"\x90" * sz)


def reg_index64(reg_name):
    reg = reg_name.lower()
    if reg not in REG64_ORDER:
        return None
    return REG64_ORDER.index(reg)


def encode_mov_r64_imm64(reg_name, imm64):
    idx = reg_index64(reg_name)
    if idx is None:
        return None

    low = idx & 0x7
    ext = 1 if idx >= 8 else 0
    rex = 0x48 | ext  # REX.W + optional REX.B
    opcode = 0xB8 + low
    return bytes([rex, opcode]) + int(imm64 & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def encode_mov_r32_imm32_from_r64(reg_name, imm32):
    idx = reg_index64(reg_name)
    if idx is None:
        return None

    low = idx & 0x7
    ext = 1 if idx >= 8 else 0
    prefix = bytes([0x41]) if ext else b""
    opcode = bytes([0xB8 + low])
    return prefix + opcode + int(imm32 & 0xFFFFFFFF).to_bytes(4, "little")


def covered_end_for_size(start_ea, need_size):
    """找到覆盖至少 need_size 的指令边界，用于宽 patch。"""
    cur = start_ea
    covered = 0
    for _ in range(16):
        sz = idc.get_item_size(cur)
        if sz <= 0:
            sz = 1
        covered += sz
        cur += sz
        if covered >= need_size:
            return cur
    return start_ea + need_size


def try_patch_one(ea):
    line = idc.generate_disasm_line(ea, 0)
    if not line:
        return False, ""

    m = PATTERN.match(line)
    if not m:
        return False, ""

    reg = m.group(1).lower()
    off_hex = m.group(2)
    table_ea = int(off_hex, 16)

    qv = idc.get_qword(table_ea)
    old_sz = idc.get_item_size(ea)
    if old_sz <= 0:
        return False, f"bad insn size at {hex(ea)}"

    # 优先安全替换：imm32 可放入 mov r32, imm32（6/5字节）
    if 0 <= qv <= 0xFFFFFFFF:
        code = encode_mov_r32_imm32_from_r64(reg, qv)
        if code is None:
            return False, f"unsupported reg {reg} at {hex(ea)}"
        if len(code) <= old_sz:
            patch_bytes(ea, code)
            fill_nop(ea + len(code), ea + old_sz)
            return True, f"safe {hex(ea)}: mov {REG32_MAP[reg]}, {hex(qv)}"

    # 宽替换：mov r64, imm64 需要 10 字节
    wide_code = encode_mov_r64_imm64(reg, qv)
    if wide_code is None:
        return False, f"unsupported reg {reg} at {hex(ea)}"

    if len(wide_code) <= old_sz:
        patch_bytes(ea, wide_code)
        fill_nop(ea + len(wide_code), ea + old_sz)
        return True, f"in-place {hex(ea)}: mov {reg}, {hex(qv)}"

    if not ALLOW_WIDE_PATCH:
        return False, f"need wide patch at {hex(ea)} (old={old_sz}, new={len(wide_code)})"

    end_ea = covered_end_for_size(ea, len(wide_code))
    patch_bytes(ea, wide_code)
    # 如果覆盖窗口大于 10 字节，把剩余填 NOP
    fill_nop(ea + len(wide_code), end_ea)
    return True, f"wide {hex(ea)}: mov {reg}, {hex(qv)} (cover-> {hex(end_ea)})"


def run():
    ok = 0
    skip = 0
    fail = 0

    print(f"[*] range: {hex(START_EA)} - {hex(END_EA)}")
    print(f"[*] ALLOW_WIDE_PATCH = {ALLOW_WIDE_PATCH}")

    for ea in idautils.Heads(START_EA, END_EA):
        changed, msg = try_patch_one(ea)
        if changed:
            ok += 1
            print("[+]", msg)
            continue

        # 只统计匹配模式但失败的情况
        line = idc.generate_disasm_line(ea, 0)
        if line and PATTERN.match(line):
            fail += 1
            print("[!]", msg if msg else f"failed at {hex(ea)}")
        else:
            skip += 1

    ida_funcs.reanalyze_function(ida_funcs.get_func(FUNC_EA_FROM_START()))
    print(f"[+] done. patched={ok}, failed={fail}, skipped={skip}")


def FUNC_EA_FROM_START():
    f = idaapi.get_func(START_EA)
    if f:
        return f.start_ea
    return START_EA


if __name__ == "__main__":
    run()

```
最终  
```c
__int64 __fastcall core_fun_1_calc_md5(UCHAR *n5566, UCHAR *pbInput_2, __int64 a3)
{
  HANDLE hHeap; // rax
  DWORD dwFlags; // edx
  ULONG cbInput; // eax
  ULONG dwFlags_1; // r9d
  ULONG cbInput_1; // eax
  ULONG dwFlags_2; // r9d
  int v10; // ecx
  HANDLE hHeap_1; // rax
  DWORD dwFlags_3; // edx
  int v13; // r8d
  __int64 v14; // rcx
  PUCHAR pbHashObject_1; // [rsp+50h] [rbp-E8h]
  SIZE_T dwBytes; // [rsp+70h] [rbp-C8h]
  int v17; // [rsp+A4h] [rbp-94h]
  int n16; // [rsp+ACh] [rbp-8Ch]
  UCHAR pbOutput__1[24]; // [rsp+B0h] [rbp-88h] BYREF
  int v20; // [rsp+C8h] [rbp-70h]
  ULONG pcbResult; // [rsp+CCh] [rbp-6Ch] BYREF
  int pbOutput_; // [rsp+D0h] [rbp-68h] BYREF
  ULONG cbHashObject; // [rsp+D4h] [rbp-64h] BYREF
  PUCHAR pbHashObject; // [rsp+D8h] [rbp-60h]
  BCRYPT_HASH_HANDLE phHash; // [rsp+E0h] [rbp-58h] BYREF
  BCRYPT_ALG_HANDLE phAlgorithm; // [rsp+E8h] [rbp-50h] BYREF
  PUCHAR pbInput; // [rsp+F0h] [rbp-48h]
  PUCHAR pbInput_1; // [rsp+F8h] [rbp-40h]
  __int64 v29; // [rsp+100h] [rbp-38h]
  int v30; // [rsp+108h] [rbp-30h]
  int n772741012; // [rsp+110h] [rbp-28h]
  int n772741012_1; // [rsp+114h] [rbp-24h]
  UCHAR *n5566_1; // [rsp+118h] [rbp-20h]

  n772741012 = 772741012;
  n772741012_1 = 772741012;
  v29 = a3;
  pbInput_1 = pbInput_2;
  pbInput = n5566;
  n5566_1 = n5566;
  if ( n5566 && pbInput_1 && v29 )
  {
    phAlgorithm = 0;
    phHash = 0;
    pbHashObject = 0;
    cbHashObject = 0;
    pbOutput_ = 0;
    pcbResult = 0;
    BCryptOpenAlgorithmProvider(&phAlgorithm, (LPCWSTR)(-v17 + 0x191F1D600LL), 0, 0);
    if ( v20 < 0 )
      return (unsigned int)(n772741012_1 - 274964149);
    BCryptGetProperty(
      phAlgorithm,
      (LPCWSTR)(n772741012_1 - 1145153701 - v17 + 0x191F1D5DELL),
      (PUCHAR)&cbHashObject,
      4u,
      &pcbResult,
      0);
    BCryptGetProperty(
      phAlgorithm,
      (LPCWSTR)(n772741012_1 - 699094091 - v17 + 0x191F1D608LL),
      (PUCHAR)&pbOutput_,
      4u,
      &pcbResult,
      0);
    if ( pbOutput_ != 16 )
      return (unsigned int)(n772741012_1 - 274964149);
    dwBytes = cbHashObject;
    hHeap = GetProcessHeap();
    HeapAlloc(hHeap, dwFlags, dwBytes);
    if ( !pbHashObject )
      return (unsigned int)(n772741012_1 - 274964149);
    BCryptCreateHash(phAlgorithm, &phHash, pbHashObject, cbHashObject, 0, 0, 0);
    cbInput = strlen((const char *)pbInput);
    BCryptHashData(phHash, pbInput, cbInput, dwFlags_1);
    cbInput_1 = strlen((const char *)pbInput_1);
    BCryptHashData(phHash, pbInput_1, cbInput_1, dwFlags_2);
    BCryptFinishHash(phHash, pbOutput__1, 0x10u, 0);
    if ( v20 >= 0 )
    {
      for ( n16 = 0; ; ++n16 )
      {
        v10 = n772741012_1 + 522840799;
        if ( n16 >= 16 )
          break;
        *(_BYTE *)(v29 + 2 * n16) = *(_BYTE *)(*(_QWORD *)(v10 - v17 + 0x191F2A0ACLL)
                                             + (((int)pbOutput__1[n16] >> 4) & 0xF));
        *(_BYTE *)(v29 + 2 * n16 + 1) = *(_BYTE *)(*(_QWORD *)(v10 + 0x191F2A0ACLL) + (pbOutput__1[n16] & 0xF));
      }
      *(_BYTE *)(v29 + 32) = 0;
      pbHashObject_1 = pbHashObject;
      hHeap_1 = GetProcessHeap();
      HeapFree(hHeap_1, dwFlags_3, pbHashObject_1);
      if ( v14 )
        v13 = n772741012_1 - 585003008 - v17;
      return v13 - v17 + *(_QWORD *)(v13 - v17 + 0x191F2A59CLL);
    }
    else
    {
      return (unsigned int)(n772741012_1 - 274964149);
    }
  }
  else
  {
    v30 = -1;
    return (unsigned int)(n772741012_1 - 274964149);
  }
}
```
可以看到是md5算法  
然后又不可避免地把main函数也给恢复了。。。。。。浪费时间  ，里面一堆无意义地函数，算一堆乱七八糟的，一眼不透明词，懒得管，我们只追踪核心函数  
sub_140005290是一个奇怪的函数，也有平坦化，这么简单我们直接手动找关系然后去除一下，然后把汇编丢ai  
```c
void sub_140005290(const uint32_t *key_ptr, uint8_t *out_buf)
{
    uint32_t key = *key_ptr;
    int i = 0;

    // 这里等价于从一个“按 key 偏移选择的子表”读取数据
    // base = off_140032BF0 + (0xCD00B688 - key)
    const uint8_t *base = (const uint8_t *)off_140032BF0 + (int32_t)(0xCD00B688 - key);

    while (i < 0x20) {
        uint8_t b = base[i];
        out_buf[i] = b ^ 0x5C;
        i++;
    }

    out_buf[0x20] = 0;
}
```
然后看到他解密出来的就是密文，和strcmp一样  
众所周知MD5乃不可逆算法，只能爆破，于是我发挥猜猜爆技能把得到的密文丢MD5解密网站得到  
E5D489FD91431D5438EB28F7490F9CE0 -> ctfer  
自此用户名分析部分结束  
```c
              strcmp(Str1_1, (const char *)(v31 - 772741012 + 0x191F2B12CLL));              //第一次校验用户名
              if ( v34 )
              {
                v37 = sub_140007EC0(v33 - 1545482024 + 0x191F2B274LL, v33 + 0x191F1D23ELL);
                sub_140009310((__int64)v53, 256, v37 - 1374644940);
                v59[0] = n772741012;
                if ( (unsigned int)sub_140005580(v59, s_3)
                  || (v59[0] = n772741012,
                      sub_140003A20(
                        v59,
                        s_3,
                        (unsigned int)(n772741012 - 772741012),
                        772741012),             // main_logic_check_flag
                      !Str1) )
                {
                  j__free_base(n5566);
                }
                else
                {
                  v59[0] = n772741012;
                  sub_140006230((__int64)v59);
                  strcmp(Str1, Str2);
```
摘自恶臭main代码    
在第二次调用strcmp之前又调用了几个函数   
- sub_140007EC0 
无意义函数  
- sub_140009310 
神秘ollvm函数，先不分析   
- sub_140003A20 
解密收到的用户名时似乎调用过，而且recv，bcryptencrypt都是他调用的，鉴定为接受数据并且解密的函数  
- sub_140006230 
依旧猜猜爆，长得和sub_140005290差不多，鉴定为解密密文   
   
我们断到strcmp时发现rcx为sub_140006230解密出来的密文，rdx就是原原本本的我们的输入的密文的hex  
气晕了这么简单，拿到密文3632303031626536623635373739633634653637646562353630313634373435直接去cyberchef unhex一下62001be6b65779c64e67deb560164745，然后测试一下   
```text
Enter username: ctfer
Sending username: ctfer
Server: OK: username valid, please send serial
Enter serial: 62001be6b65779c64e67deb560164745
Sending serial: 62001be6b65779c64e67deb560164745
Server: OK: welcome ctfer
```
我去真的是你！    

# 后继
写出来的那一个真的有点气笑了，flag竟然根本没有保护，我当时要是直接断strcmp直接就出来   
本文以及相当缩减了，实际上光是数据流追踪，就花了几个小时，各种方法才摸清楚整体走向，并没有文章里那么好想  
然后平坦化和间接调用，基本随便打开一个函数就有这些，如果全搞工作量不小，其实我也去除了不少函数的，只是有些可能无意义的工作，所以不贴出来  
调试的累死了，这题如果仅仅是为了靠去平坦化和不透明词，完全可以只加密一个函数，都加密了并不会增大题目难度，只会增大工作量，不过逆向大抵如此  