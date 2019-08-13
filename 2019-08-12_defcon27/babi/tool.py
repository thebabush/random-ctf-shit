"""
Usage: LD_PRELOAD=/usr/lib/libpyqbdi.so PYQBDI_TOOL=./tool.py ./babi
"""

import pyqbdi
import struct
import os

import sys



sys.stdout = open('/tmp/stdout.txt', 'w')


BASE = 0
MALLOCS = { 0x0000000000068190, 0x0000000000068160 }
REALLOCS = { 0x0000000000068180 }
DEALLOCS = { 0x0000000000068170 }


def rq(where):
    return struct.unpack('<Q', pyqbdi.readMemory(where, 8))[0]


funcs = {}
funcs[0x7CCE0] = "babi::php::Parser::fixup::travel"
funcs[0x7CDD0] = "babi::php::Parser::fixup::translate"
funcs[0x07CC97] = "post-translate"
funcs[0x70FA1] = "new-request"
funcs[0x78360] = "print-PhpVar"
funcs[0x07CA4C] = "parsing new element"


chunks = []
mem = {}
rets = set()
wtfs = set()


def mycb(vm, gpr, fpr, data):
    global chunks
    global mem
    global rets

    inst = vm.getInstAnalysis()
    addr = inst.address - BASE
    # print "0x%x: %s" % (inst.address, inst.disassembly)

    if addr in funcs:
        print '\033[92mFUNK: {}\033[0m'.format(funcs[addr])
    
    addr = int(addr)
    if addr in MALLOCS:
        size = vm.getGPRState().rdi
        # print 'malloc({})'.format(size)
        ret = rq(vm.getGPRState().rsp)
        # print 'ret {:08X}'.format(ret)
        chunks.append(size)
        rets.add(ret)
    if inst.address in rets:
        rets.remove(inst.address)
        # MALLOC END
        addr = vm.getGPRState().rax
        size = chunks.pop()
        addr = int(addr)
        if addr in wtfs:
            print 'malloc({:10}) => \033[31m0x{:08X} WTF\033[0m'.format(size, addr)
            for i in range(50):
                print 'stack{:02X}=0x{:08X}'.format(i * 8, rq(vm.getGPRState().rsp + i * 8))
        else:
            print 'malloc({:10}) => 0x{:08X}'.format(size, addr)
        mem[addr] = size

    # REALLOC
    if addr in REALLOCS:
        size = vm.getGPRState().rsi
        ret = rq(vm.getGPRState().rsp)
        chunks.append(size)
        rets.add(ret)

    if addr in DEALLOCS:
        # free whatever
        addr = vm.getGPRState().rdi
        print 'free(0x{:08X})'.format(addr),
        if addr not in mem:
            wtfs.add(int(addr))
            print '\033[31mWTF\033[0m'
        else:
            print '{:4}'.format(mem[addr])
            del mem[addr]


def pyqbdipreload_on_run(vm, start, stop):
    global BASE
    BASE = int(open('/proc/self/maps', 'r').readlines()[0].strip().split('-')[0], 16)
    print('base: {:08X}'.format(BASE))
    vm.addCodeCB(pyqbdi.PREINST, mycb, None)
    # vm.addVMEventCB(pyqbdi.SYSCALL_ENTRY, syskill, None)
    vm.run(start, stop)

