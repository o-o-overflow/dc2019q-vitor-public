#!/usr/bin/env python
import os
from os import system as run
from os.path import *
import sys
from sys import exit

from pwn import *
import yaml
import click

context.log_level = 'info'
debug = False

conf = yaml.load(open(join(dirname(__file__), "info.yml")))
flag = conf['flag']

@click.group()
def cli():
    pass


@cli.command()
@click.argument('shellcode_fp', default='shellcode.bin')
@click.option('--make-exe', is_flag=True)
def genshellcode(shellcode_fp, make_exe):
    # eax: tmp register
    # ebx: &_start
    # ecx: K3
    # edx: will contain saved returned address (to JNI)
    # edi: &flag
    # esi: &p5mem

    first = ';'.join(['nop']*32) + '''
    // _start:
        // get pc
        call myself
    myself:
        pop ebx

        // ebx points to _start
        sub ebx, 5
        // take into account the 32 nops
        sub ebx, 32

        // 1st arg (flag) in edi
        mov edi, dword ptr [esp+4]

        // compute K3 and store it in ecx
        // skip initial OOO{ and go to chunk 4
        xor ecx, ecx
        add edi, 16
        mov edx, 2
    computek3:
        xor ecx, dword ptr [edi]
        // go to chunk 8
        add edi, 16
        sub edx, 1
        jne computek3

        // restore edi to points to flag
        sub edi, 32

        // ecx now contains K3

        // decrypt the gadgets and the chain
        // 50 = 200 bytes / 4
        mov eax, ebx
        // make eax point to gadget/chain
        add eax, 200
        mov edx, 50
    loop:
        // ecx is the encryption key for gadgets and chains
        xor dword ptr [eax], ecx
        add eax, 4
        sub edx, 1
        jne loop

        // add shellcode_start to the chain, those addresses are relative!
        mov eax, ebx
        add eax, 300
        // eax now points to chain
        // 25 = 100 bytes / 4
        mov edx, 25
    loop2:
        // add _start to the chain values
        add dword ptr [eax], ebx
        add eax, 4
        sub edx, 1
        jne loop2

        // jump to rop chain
        // as a test, make eax points to the chains
        mov eax, ebx
        add eax, 300
        // eax points to the chain
        // save current esp in edx
        mov edx, esp

        // load &flag, &p5mem, p5mem_size in edi, esi, ebx
        mov edi, dword ptr [esp+4]
        mov esi, dword ptr [esp+8]
        mov ebx, dword ptr [esp+12]

        // make esp points to the first item in the chain
        mov esp, eax
        ret
    '''
    assert len(asm(first)) <= 200

    epilog = '''
        // restore esp
        mov esp, edx
        // return to the caller
        ret
    '''

    # NOTE: many of these gadgets were only used for debugging stuff
    # these will be at offset 200
    gadgets = []
    curr = 0
    #  g_xor_eax_41414141 = curr; gadgets.append('xor eax, 0x41414141; ret'); curr += 1
    g_mov_eax_0 = curr; gadgets.append('mov eax, 0; ret'); curr += 1
    g_add_eax_4 = curr; gadgets.append('add eax, 4; ret'); curr += 1
    g_ret = curr; gadgets.append('ret'); curr += 1
    g_mov_eax_esi = curr; gadgets.append('mov eax, esi; ret'); curr += 1
    g_mov_eax_ptr_esi = curr; gadgets.append('mov eax, dword ptr [esi]; ret'); curr += 1
    #  g_xor_eax_12345678 = curr; gadgets.append('xor eax, 0x78563412; ret'); curr += 1
    #  g_mov_ebx_4 = curr; gadgets.append('mov ebx, 4; ret'); curr += 1
    #  g_mov_ebx_8 = curr; gadgets.append('mov ebx, 8; ret'); curr += 1
    #  g_xor_ptr_esi_78563412 = curr; gadgets.append('xor dword ptr [esi], 0x78563412; ret'); curr += 1
    g_xor_ptr_esi_ecx = curr; gadgets.append('xor dword ptr [esi], ecx; ret'); curr += 1
    g_add_esi_4 = curr; gadgets.append('add esi, 4; ret'); curr += 1
    g_sub_ebx_4 = curr; gadgets.append('sub ebx, 4; ret'); curr += 1
    g_jle_x_ret_pop_eax = curr; gadgets.append('jle after; ret; after: pop eax; ret'); curr += 1
    g_sub_esp_24 = curr; gadgets.append('sub esp, 24; ret'); curr += 1
    g_mov_eax_9 = curr; gadgets.append('mov eax, 9; ret'); curr += 1
    g_mov_eax_0x31337 = curr; gadgets.append('mov eax, 0x31337; ret'); curr += 1
    g_mov_eax_ebx = curr; gadgets.append('mov eax, ebx; ret'); curr += 1
    g_mov_ebx_ecx = curr; gadgets.append('mov ebx, ecx; ret'); curr += 1
    g_mov_eax_ecx = curr; gadgets.append('mov eax, ecx; ret'); curr += 1
    g_rol_ecx_8 = curr; gadgets.append('rol ecx, 8; ret'); curr += 1
    g_xor_ecx_ecx = curr; gadgets.append('xor ecx, ecx; ret'); curr += 1
    g_xor_ecx_ptr_edi_20 = curr; gadgets.append('xor ecx, dword ptr [edi+20]; ret'); curr += 1
    g_xor_ecx_ptr_edi_40 = curr; gadgets.append('xor ecx, dword ptr [edi+40]; ret'); curr += 1

    #  g_mov_ecx_key = curr; gadgets.append('mov ecx, 0x5d522d56; ret'); curr += 1

    # relevant encryptions keys
    K3 = get_keys(flag)[3]
    print 'K3: 0x%08x' % u32(K3)

    # gadgets offsets
    gof = []
    curr_off = 200
    for g in gadgets:
        gof.append(curr_off)
        curr_off += len(asm(g))
    assert curr_off < 300

    g_chain = [
        # compute the key from the flag, edi=&flag
        g_xor_ecx_ecx,
        g_xor_ecx_ptr_edi_20,
        g_xor_ecx_ptr_edi_40,

        # decrypt p5, esi=&p5 ebx=len(p5) ecx=K4
        g_xor_ptr_esi_ecx,
        g_add_esi_4,
        g_rol_ecx_8,
        g_sub_ebx_4,
        g_jle_x_ret_pop_eax,
        g_sub_esp_24,
        g_mov_eax_0x31337
    ]
    

    # these are relative addresses (from _start), _start will be added later
    chain = ''
    for gc in g_chain:
        chain += p32(gof[gc])
    chain += p32(len(asm(first))) # points to epilog
    assert len(chain) <= 100

    p3main = asm(first + epilog)
    p3main = p3main.ljust(200, '\x90')

    p3gadgets = asm(';'.join(gadgets))
    assert len(p3gadgets) <= 100
    p3gadgets = p3gadgets.ljust(100, '\x90')
    p3gadgets = xor(p3gadgets, K3)

    p3chain = chain
    assert len(p3chain) <= 100
    p3chain = p3chain.ljust(100, '\x00')
    p3chain = xor(p3chain, K3)

    payload = p3main + p3gadgets + p3chain
    assert len(payload) == 400

    with open(shellcode_fp, 'wb') as f:
        f.write(payload)
    print 'Wrote shellcode to %s' % basename(shellcode_fp)

    if make_exe:
        exe_fp = shellcode_fp + '.exe'
        with open(exe_fp, 'wb') as f:
            f.write(make_elf(payload))
        print 'Wrote exe to %s' % basename(exe_fp)


@cli.command()
@click.option('--debug', 'debug_flag', is_flag=True)
def dumpkeys(debug_flag):
    global debug
    debug = debug_flag

    keys = get_keys(flag)
    for kidx in range(5):
        print 'K%d: "%s" "0x%08x"' % (kidx, keys[kidx].encode('hex'), u32(keys[kidx]))


def get_keys(flag):
    core = flag[4:-1]
    assert len(core) == 40

    core_len = len(core)
    chunks = []
    for i in range(core_len/4):
        chunks.append(core[4*i:4*(i+1)])

    keys = []
    for kidx in range(5):
        keys.append('\x00'*4)

    for kidx in range(5):
        if debug:
            print 'computing K%d' % kidx
        for idx, chunk in enumerate(chunks):
            if (idx+1) % (kidx+1) == 0:
                if debug:
                    print '\t%d (%s)' % ((idx+1), chunk.encode('hex'))
                keys[kidx] = xor(keys[kidx], chunk)

    return keys


@cli.command()
@click.argument('p3_fp')
@click.argument('p3enc_fp')
@click.option('--dump-keys', is_flag=True, help="Just dump the keys.")
def encp3(p3_fp, p3enc_fp, dump_keys):

    K2 = get_keys(flag)[2]

    p3_fp = abspath(p3_fp)
    p3enc_fp = abspath(p3enc_fp)

    with open(p3_fp, 'rb') as f:
        p3 = f.read()

    encp3 = ''
    currkey = K2
    i = 0
    mod2_32 = 2**32
    while i < len(p3):
        encp3 += xor(p3[i:i+4], currkey)
        if dump_keys:
            print i, currkey.encode('hex')
            print 'i:%d %s => %s' % (i, p3[4*i:4*i+4].encode('hex'), encp3[i:i+4].encode('hex'))
        currkey = p32((u32(currkey) + 0x31333337) % mod2_32)
        i += 4

        if dump_keys:
            if i > 20:
                break
    encp3 = encp3[:len(p3)]

    if dump_keys:
        exit(0)

    with open(p3enc_fp, 'wb') as f:
        f.write(encp3)

    print 'Generated enc p3: %s => %s' % (p3_fp, p3enc_fp)


@cli.command()
@click.argument('p5_fp')
@click.argument('p5enc_fp')
@click.option('--dump-keys', is_flag=True, help="Just dump the keys.")
def encp5(p5_fp, p5enc_fp, dump_keys):

    K4 = get_keys(flag)[4]

    p5_fp = abspath(p5_fp)
    p5enc_fp = abspath(p5enc_fp)

    with open(p5_fp, 'rb') as f:
        p5 = f.read()

    encp5 = ''
    currkey = K4
    i = 0
    while i < len(p5):
        encp5 += xor(p5[i:i+4], currkey)
        if dump_keys:
            print i, currkey.encode('hex')
            print 'i:%d %s => %s' % (i, p5[4*i:4*i+4].encode('hex'), encp5[i:i+4].encode('hex'))
        currkey = ror(currkey, 1)
        i += 4

        if dump_keys:
            if i > 20:
                break
    encp5 = encp5[:len(p5)]

    if dump_keys:
        exit(0)

    with open(p5enc_fp, 'wb') as f:
        f.write(encp5)

    print 'Generated enc p5: %s => %s' % (p5_fp, p5enc_fp)


@cli.command()
@click.argument('key_idx')
def getkey(key_idx):
    key_idx = int(key_idx)
    kk = get_keys(flag)[key_idx]
    print kk.encode('hex')


@cli.command()
def calcflag():
    ''' DEBUG: calculate flag from the keys. '''
    global flag
    k0, k1, k2, k3, k4 = get_keys(flag)
    f6, f7, f8, f9, f10 = group(4, ' => pHd_1w_e4rL13r;)')
    f5 = xor(k4, f10)
    f4 = xor(k3, f8)
    f3 = xor(xor(k2, f6), f9)
    f2 = xor(xor(xor(xor(k1, f4), f6), f8), f10)
    f1 = xor(xor(xor(xor(xor(k0, k1), f3), f5), f7), f9)

    theflag = 'OOO{' + f1 + f2 + f3 + f4 + f5 + f6 + f7 + f8 + f9 + f10 + '}'
    print theflag


@cli.command()
@click.argument('flag')
def analflag(flag):
    ''' DEBUG: extract keys from flag.'''
    f1, f2, f3, f4, f5, f6, f7, f8, f9, f10 = group(4, flag)
    k1 = xor(f1, xor(f2, xor(f3, xor(f4, xor(f5, xor(f6, xor(f7, xor(f8, xor(f9, f10)))))))))
    k2 = xor(f2, xor(f4, xor(f6, xor(f8, f10))))
    k2 = xor(k2, k1)
    k3 = xor(f3, xor(f6, f9))
    k4 = xor(f4, f8)
    k5 = xor(f5, f10)
    print 'k1: %s' % k1.encode('hex')
    print 'k2: %s' % k2.encode('hex')
    print 'k3: %s' % k3.encode('hex')
    print 'k4: %s' % k4.encode('hex')
    print 'k5: %s' % k5.encode('hex')


if __name__ == '__main__':
    cli()
