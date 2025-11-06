# coding=utf8

"""
reference:
- https://github.com/synacktiv/vmx_intrinsics/blob/master/vmx_intrinsics.py
- https://www.synacktiv.com/publications/ios12-kernelcache-laundering
- https://idasuckless.github.io/the-brk-is-a-lie.html
- https://blog.ret2.io/2020/07/22/ida-pro-avx-decompiler/
"""

import idaapi  # pyright: ignore[reportMissingImports]
import ida_allins  # pyright: ignore[reportMissingImports]
import ida_hexrays  # pyright: ignore[reportMissingImports]

"""
https://elixir.bootlin.com/linux/v6.17.7/source/arch/arm64/include/asm/brk-imm.h#L31

/*
 * #imm16 values used for BRK instruction generation
 * 0x004: for installing kprobes
 * 0x005: for installing uprobes
 * 0x006: for kprobe software single-step
 * 0x007: for kretprobe return
 * Allowed values for kgdb are 0x400 - 0x7ff
 * 0x100: for triggering a fault on purpose (reserved)
 * 0x400: for dynamic BRK instruction
 * 0x401: for compile time BRK instruction
 * 0x800: kernel-mode BUG() and WARN() traps
 * 0x9xx: tag-based KASAN trap (allowed values 0x900 - 0x9ff)
 * 0x55xx: Undefined Behavior Sanitizer traps ('U' << 8)
 * 0x8xxx: Control-Flow Integrity traps
 */
#define KPROBES_BRK_IMM			0x004
#define UPROBES_BRK_IMM			0x005
#define KPROBES_BRK_SS_IMM		0x006
#define KRETPROBES_BRK_IMM		0x007
#define FAULT_BRK_IMM			0x100
#define KGDB_DYN_DBG_BRK_IMM		0x400
#define KGDB_COMPILED_DBG_BRK_IMM	0x401
#define BUG_BRK_IMM			0x800
#define KASAN_BRK_IMM			0x900
#define KASAN_BRK_MASK			0x0ff
#define UBSAN_BRK_IMM			0x5500
#define UBSAN_BRK_MASK			0x00ff

#define CFI_BRK_IMM_TARGET		GENMASK(4, 0)
#define CFI_BRK_IMM_TYPE		GENMASK(9, 5)
#define CFI_BRK_IMM_BASE		0x8000
#define CFI_BRK_IMM_MASK		(CFI_BRK_IMM_TARGET | CFI_BRK_IMM_TYPE)
"""

KPROBES_BRK_IMM = 0x004
UPROBES_BRK_IMM = 0x005
KPROBES_BRK_SS_IMM = 0x006
KRETPROBES_BRK_IMM = 0x007
FAULT_BRK_IMM = 0x100
KGDB_DYN_DBG_BRK_IMM = 0x400
KGDB_COMPILED_DBG_BRK_IMM = 0x401
BUG_BRK_IMM = 0x800
KASAN_BRK_IMM = 0x900
KASAN_BRK_MASK = 0x0FF
UBSAN_BRK_IMM = 0x5500
UBSAN_BRK_MASK = 0x00FF


class MicroInstruction(ida_hexrays.minsn_t):
    def __init__(self, opcode, ea):
        ida_hexrays.minsn_t.__init__(self, ea)
        self.opcode = opcode
        self.l.zero()
        self.r.zero()
        self.d.zero()


class CallBuilder:
    def __init__(
        self, cdg, name, *, return_type=idaapi.tinfo_t(idaapi.BT_VOID), extra_flags=0
    ):
        self.emitted = False
        self.cdg = cdg
        self.callinfo = ida_hexrays.mcallinfo_t()
        self.callinfo.callee = idaapi.BADADDR
        self.callinfo.solid_args = 0x00
        self.callinfo.call_spd = 0x00
        self.callinfo.stkargs_top = 0x00
        self.callinfo.cc = idaapi.CM_CC_FASTCALL
        self.callinfo.return_type = return_type
        self.callinfo.flags = (
            idaapi.FCI_SPLOK | idaapi.FCI_FINAL | idaapi.FCI_PROP | extra_flags
        )
        self.callinfo.role = idaapi.ROLE_UNK

        glbhigh_off = cdg.mba.get_stack_region().off + cdg.mba.get_stack_region().size
        # what memory is visible to the call : GLBLOW - GLBHIGH
        self.callinfo.visible_memory.add(ida_hexrays.ivl_t(0x00, 0x100000))
        self.callinfo.visible_memory.add(
            ida_hexrays.ivl_t(glbhigh_off, 0xFFFFFFFFFFFFFFFF - glbhigh_off)
        )
        # spoiled locations : GLBLOW - GLBHIGH
        self.callinfo.spoiled.mem.add(ida_hexrays.ivl_t(0x00, 0x100000))
        self.callinfo.spoiled.mem.add(
            ida_hexrays.ivl_t(glbhigh_off, 0xFFFFFFFFFFFFFFFF - glbhigh_off)
        )

        self.callins = MicroInstruction(ida_hexrays.m_call, self.cdg.insn.ea)
        self.callins.l.make_helper(name)
        self.callins.d.t = ida_hexrays.mop_f
        self.callins.d.size = 0x00
        self.callins.d.f = self.callinfo

        if return_type.is_void():
            self.ins = self.callins
        else:
            self.callins.d.size = return_type.get_size()
            self.ins = MicroInstruction(ida_hexrays.m_mov, self.cdg.insn.ea)
            self.ins.l.t = ida_hexrays.mop_d
            self.ins.l.d = self.callins
            self.ins.l.size = self.callins.d.size
            self.ins.d.t = ida_hexrays.mop_r
            self.ins.d.r = 0x00
            self.ins.d.size = self.callins.d.size

    def add_register_argument(self, t, operand):
        ca = ida_hexrays.mcallarg_t()
        ca.t = idaapi.mop_r
        ca.r = operand
        ca.type = t
        ca.size = t.get_size()
        self.callinfo.args.push_back(ca)
        self.callinfo.solid_args += 1

    def add_register_address_argument(self, t, operand):
        # Create pointer type first to get correct size
        ptr_type = idaapi.tinfo_t(t)
        ptr_type.create_ptr(ptr_type)

        addr_t = ida_hexrays.mop_addr_t()
        addr_t.t = idaapi.mop_r
        addr_t.r = operand
        addr_t.type = t  # Keep original type for addr_t.type
        # Use pointer size for address operations
        ptr_size = ptr_type.get_size()
        addr_t.size = ptr_size
        addr_t.insize = ptr_size
        addr_t.outsize = ptr_size

        ca = ida_hexrays.mcallarg_t()
        ca.t = idaapi.mop_a
        ca.a = addr_t
        ca.type = ptr_type  # Use pointer type for call argument
        ca.size = ptr_size
        self.callinfo.args.push_back(ca)
        self.callinfo.solid_args += 1

    def set_return_register(self, reg):
        self.ins.d.r = reg

    def emit(self):
        if not self.emitted:
            self.cdg.mb.insert_into_block(self.ins, self.cdg.mb.tail)
            self.emitted = True

    def emit_und_reg(self, reg, size):
        ins = MicroInstruction(ida_hexrays.m_und, self.cdg.insn.ea)
        ins.d.t = idaapi.mop_r
        ins.d.r = reg
        ins.d.size = size
        self.cdg.mb.insert_into_block(ins, self.cdg.mb.tail)

    def emit_reg_equals_number(self, result_reg, reg, number, size):
        ins = MicroInstruction(ida_hexrays.m_setz, self.cdg.insn.ea)
        ins.l.t = idaapi.mop_r
        ins.l.r = reg
        ins.l.size = size
        ins.r.make_number(number, size)
        ins.d.t = idaapi.mop_r
        ins.d.r = result_reg
        ins.d.size = 1
        self.cdg.mb.insert_into_block(ins, self.cdg.mb.tail)

    def load_constant_to_temp_reg(self, value, size):
        """
        Allocate a temporary register and load a constant value into it.
        Returns the register number.
        """
        temp_reg = self.cdg.mba.alloc_kreg(size)
        ins = MicroInstruction(ida_hexrays.m_mov, self.cdg.insn.ea)
        ins.d.t = idaapi.mop_r
        ins.d.r = temp_reg
        ins.d.size = size
        ins.l.make_number(value, size)
        self.cdg.mb.insert_into_block(ins, self.cdg.mb.tail)
        return temp_reg


class brk_stop_ins_t(idaapi.IDP_Hooks):
    def ev_emu_insn(self, insn):
        if insn.itype != idaapi.ARM_brk:
            return False
        return True


class better_arm64_microcode_t(ida_hexrays.microcode_filter_t):
    def __init__(self):
        super().__init__()
        self._handlers = {
            ida_allins.ARM_brk: self.brk,
            ida_allins.ARM_hint: self.hint,
            ida_allins.ARM_prfm: self.prfm,
        }

    def match(self, cdg):
        return cdg.insn.itype in self._handlers

    def apply(self, cdg):
        return self._handlers[cdg.insn.itype](cdg, cdg.insn)

    def brk(self, cdg, insn):
        val = insn.Op1.value

        if val == BUG_BRK_IMM:
            function_name = "BUG_ON"
        else:
            function_name = "__asm_break"
        builder = CallBuilder(cdg, function_name, extra_flags=ida_hexrays.FCI_NORET)
        builder.add_register_argument(
            idaapi.tinfo_t(idaapi.BT_INT | idaapi.BTMT_UNSIGNED), cdg.load_operand(0)
        )
        builder.emit()
        return ida_hexrays.MERR_OK

    def hint(self, cdg, insn):
        val = insn.Op1.value
        if val == 0x14:
            function_name = "__asm_csdb_barrier"
            builder = CallBuilder(cdg, function_name)
            builder.emit()
            return ida_hexrays.MERR_OK
        else:
            return ida_hexrays.MERR_INSN

    def prfm(self, cdg, insn):
        # https://developer.arm.com/documentation/101458/2404/Optimize/Prefetching-with---builtin-prefetch
        op1_val = insn.Op1.value
        function_name = "__builtin_prefetch"
        builder = CallBuilder(cdg, function_name)
        arg1 = cdg.load_operand(1)
        if op1_val == 0x01:  # PLDL1STRM
            arg2 = builder.load_constant_to_temp_reg(0, 4)
            arg3 = builder.load_constant_to_temp_reg(0, 4)
        elif op1_val == 0x04:  # PLDL3KEEP
            arg2 = builder.load_constant_to_temp_reg(0, 4)
            arg3 = builder.load_constant_to_temp_reg(1, 4)
        elif op1_val == 0x02:  # PLDL2KEEP
            arg2 = builder.load_constant_to_temp_reg(0, 4)
            arg3 = builder.load_constant_to_temp_reg(2, 4)
        elif op1_val == 0x00:  # PLDL1KEEP
            arg2 = builder.load_constant_to_temp_reg(0, 4)
            arg3 = builder.load_constant_to_temp_reg(3, 4)
        elif op1_val == 0x11:  # PSTL1STRM
            arg2 = builder.load_constant_to_temp_reg(1, 4)
            arg3 = builder.load_constant_to_temp_reg(0, 4)
        elif op1_val == 0x14:  # PSTL3KEEP
            arg2 = builder.load_constant_to_temp_reg(1, 4)
            arg3 = builder.load_constant_to_temp_reg(1, 4)
        elif op1_val == 0x12:  # PSTL2KEEP
            arg2 = builder.load_constant_to_temp_reg(1, 4)
            arg3 = builder.load_constant_to_temp_reg(2, 4)
        elif op1_val == 0x10:  # PSTL1KEEP
            arg2 = builder.load_constant_to_temp_reg(1, 4)
            arg3 = builder.load_constant_to_temp_reg(3, 4)
        else:
            return ida_hexrays.MERR_INSN

        builder.add_register_address_argument(idaapi.tinfo_t(idaapi.BT_VOID), arg1)
        builder.add_register_argument(idaapi.tinfo_t(idaapi.BT_INT), arg2)
        builder.add_register_argument(idaapi.tinfo_t(idaapi.BT_INT), arg3)
        builder.emit()
        return ida_hexrays.MERR_OK

    def hook(self):
        ida_hexrays.install_microcode_filter(self, True)
        print(
            "Installing brk_better_microcode_t lifter... (%u instr supported)"
            % len(self._handlers)
        )

    def unhook(self):
        ida_hexrays.install_microcode_filter(self, False)
        print("Removing brk_better_microcode_t lifter...")


class BrkGreatAgainPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Make BRK great again."
    help = "Make BRK great again."
    wanted_name = "BrkGreatAgainPlugin"
    wanted_hotkey = ""
    hook_of_brk_stop_ins_t = None
    hook_of_brk_better_microcode_t = None
    hooks = []

    def init(self):
        # fast exit path
        if idaapi.ph_get_id() != idaapi.PLFM_ARM or idaapi.BADADDR <= 0xFFFFFFFF:
            print("[{}] Won't load!".format(self.wanted_name))
            return idaapi.PLUGIN_SKIP

        if not self.hook_of_brk_stop_ins_t:
            print("[{}] start brk_stop_ins_t".format(self.wanted_name))
            self.hook_of_brk_stop_ins_t = brk_stop_ins_t()
            self.hook_of_brk_stop_ins_t.hook()
            self.hooks.append(self.hook_of_brk_stop_ins_t)

        # ensure the decompiler is loaded
        if not ida_hexrays.init_hexrays_plugin():
            print("Missing hexarm Decompiler...")
            return idaapi.PLUGIN_SKIP

        if not self.hook_of_brk_better_microcode_t:
            print("[{}] start better_arm64_microcode_t".format(self.wanted_name))
            self.hook_of_brk_better_microcode_t = better_arm64_microcode_t()
            self.hook_of_brk_better_microcode_t.hook()
            self.hooks.append(self.hook_of_brk_better_microcode_t)

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        for hook in self.hooks:
            hook.unhook()


def PLUGIN_ENTRY():
    return BrkGreatAgainPlugin()
