"""
Usage: LD_PRELOAD=/usr/lib/libpyqbdi.so PYQBDI_TOOL=./tool.py ./aoool

(c) 2019 Paolo "babush" Montesel
"""

import struct

import pyqbdi


where = 0


def mycb(vm, gpr, fpr, data):
    global where
    inst = vm.getInstAnalysis()
    addr = inst.address - 0x555555554000
    # if addr == 0xB893:
        # exit()
    # if addr == 0x14560:
        # print "FUCK" # Used to be another message in Italian...
        # exit()
    if addr == 0x18776:
        print 'RCX SHIT: {:08X}'.format(vm.getGPRState().rcx)

    if addr == 0x1814B:
        print 'OPEN'
        exit()

    if addr == 0xB811:
        print "0x%x: %s" % (inst.address, inst.disassembly)

    # Call shellcode stuff
    # if addr == 0x18228:
        # # print 'Shellbiatch:', repr(pyqbdi.readMemory(vm.getGPRState().rax - 0x710, 0x100))
        # print 'Shellbiatch:', repr(pyqbdi.readMemory(vm.getGPRState().rax, 0x300))

    if addr == 0xF6F9:
        state = vm.getGPRState().rax
        STATES = {
             1: 'main',
             2: 'root',
             3: 'log',
             4: 'mode',
             5: 'text',
             6: 'osl',
             7: 'server_name',
             8: 'server',
             9: 'location',
            10: 'print',
            11: 'del',
            12: 'quoted',
            16: '{',
            17: '}',
            22: ';',
            24: 'whitespace',
            28: 'accepting',
        }
        if state not in {28, 24, 13, 29}:
            asd = 'unk'
            if state in STATES:
                asd = STATES[state]
            print('STATE: {} {}'.format(state, asd))
        if state == 29:
            print '='*80
    if addr == 0x11B72:
        where = vm.getGPRState().rdi
        # mem = struct.unpack('<Q', pyqbdi.readMemory(vm.getGPRState().rax + 0x78, 8))[0]
        # print('FLEX: {:08X}'.format(mem))
        arg2 = vm.getGPRState().rsi
        mem = struct.unpack('<Q', pyqbdi.readMemory(arg2 + 616, 8))[0]
        mem = mem & 0xFF;
        # mem = struct.unpack('<B', pyqbdi.readMemory(mem, 1))[0]
        # where = mem
        # # import IPython; IPython.embed(); exit()
        # print('FLEX: {:08X}'.format(mem))
    elif addr == 0x11B75:
        mem = struct.unpack('<I', pyqbdi.readMemory(where, 4))[0]
        what = 'unk'
        WHAT = {
            0x03: 'main',
            0x05: 'log',
            0x06: 'mode',
            0x07: 'text',
            0x09: 'server_name',
            0x0F: 'quoted',
            0x13: '{',
            0x14: '}',
            0x16: ';',
        }
        if mem in WHAT:
            what = WHAT[mem]
        # print('FLEX: {:08X} {}'.format(mem, what))
    # print "0x%x: %s" % (inst.address, inst.disassembly)
    return pyqbdi.CONTINUE


def pyqbdipreload_on_run(vm, start, stop):
    vm.addCodeCB(pyqbdi.PREINST, mycb, None)
    vm.run(start, stop)

