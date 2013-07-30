/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013 by Katja Malvoni <kmalvoni at gmail dot com>
 * It is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */

    .text
    .globl _BF_encrypt2
    .type _BF_encrypt2, @function

.macro BF2_2ROUND_A
		and r44, r48, r49
		lsr r23, r48, 0xe 
		and r23, r23, r50
		lsr r24, r48, 0x16 
		and r24, r24, r50
		imul r44, r44, r51
		ldr r23, [r16, +r23] 
		ldr r24, [r26, +r24] 
		lsr r22, r48, 6 
		and r22, r22, r50
		iadd r23, r24, r23 
		ldr r22, [r17, +r22] 
		ldr r27, [r45], 0x1 
		ldr r44, [r18, +r44] 
		lsr r60, r12, 0x18 
		eor r56, r56, r27 
		eor r23, r22, r23 
		imul r60, r60, r51
		and r61, r12, r49
		lsr r63, r12, 0xe 
		and r63, r63, r50
		iadd r23, r23, r44 
		imul r61, r61, r51
		ldr r63, [r20, +r63] 
		ldr r60, [r19, +r60] 
		lsr r62, r12, 6 
		and r62, r62, r50
		eor r56, r56, r23 
		iadd r63, r60, r63 
		ldr r62, [r21, +r62] 
		ldr r27, [r46], 0x1 
		ldr r61, [r25, +r61] 
		lsr r24, r56, 0x18 
		eor r47, r47, r27 
		eor r63, r62, r63 
		imul r24, r24, r51
		and r44, r56, r49
		lsr r23, r56, 0xe 
		and r23, r23, r50
		iadd r63, r63, r61 
		imul r44, r44, r51
		ldr r23, [r16, +r23] 
		ldr r24, [r26, +r24] 
		lsr r22, r56, 6 
		and r22, r22, r50
		eor r47, r47, r63 
		iadd r23, r24, r23 
		ldr r22, [r17, +r22] 
		ldr r27, [r45], 0x1 
		ldr r44, [r18, +r44] 
		lsr r60, r47, 0x18 
		eor r48, r48, r27 
		eor r23, r22, r23 
		imul r60, r60, r51
		and r61, r47, r49
		lsr r63, r47, 0xe 
		and r63, r63, r50
		iadd r23, r23, r44 
		imul r61, r61, r51
		ldr r63, [r20, +r63] 
		ldr r60, [r19, +r60] 
		lsr r62, r47, 6 
		and r62, r62, r50
		eor r48, r48, r23
		iadd r63, r60, r63 
		ldr r62, [r21, +r62] 
		ldr r27, [r46], 0x1 
		ldr r61, [r25, +r61] 
		eor r12, r12, r27 
		eor r63, r62, r63 
		add r63, r63, r61 
		eor r12, r12, r63
.endm

.macro BF2_2ROUND_B P1, P2, P3, P4
		and r44, r48, r49
		lsr r23, r48, 0xe 
		and r23, r23, r50
		lsr r24, r48, 0x16 
		and r24, r24, r50
		imul r44, r44, r51
		ldr r23, [r16, +r23] 
		ldr r24, [r26, +r24] 
		lsr r22, r48, 6 
		and r22, r22, r50
		iadd r23, r24, r23 
		ldr r22, [r17, +r22] 
		ldr r44, [r18, +r44] 
		lsr r60, r12, 0x18 
		eor r56, r56, \P1
		eor r23, r22, r23 
		imul r60, r60, r51
		and r61, r12, r49
		lsr r63, r12, 0xe 
		and r63, r63, r50
		iadd r23, r23, r44 
		imul r61, r61, r51
		ldr r63, [r20, +r63] 
		ldr r60, [r19, +r60] 
		lsr r44, r12, 6 
		and r44, r44, r50
		eor r56, r56, r23 
		iadd r63, r60, r63 
		ldr r44, [r21, +r44] 
		ldr r61, [r25, +r61] 
		lsr r24, r56, 0x18 
		eor r47, r47, \P3
		eor r63, r44, r63 
		imul r24, r24, r51
		and r44, r56, r49
		lsr r23, r56, 0xe 
		and r23, r23, r50
		iadd r63, r63, r61 
		imul r44, r44, r51
		ldr r23, [r16, +r23] 
		ldr r24, [r26, +r24] 
		lsr r22, r56, 6 
		and r22, r22, r50
		eor r47, r47, r63 
		iadd r23, r24, r23 
		ldr r22, [r17, +r22] 
		ldr r44, [r18, +r44] 
		lsr r60, r47, 0x18 
		eor r48, r48, \P2
		eor r23, r22, r23 
		imul r60, r60, r51
		and r61, r47, r49
		lsr r63, r47, 0xe 
		and r63, r63, r50
		iadd r23, r23, r44 
		ldr r63, [r20, +r63] 
		ldr r60, [r19, +r60] 
		imul r61, r61, r51
		lsr r44, r47, 6 
		and r44, r44, r50
		iadd r63, r60, r63 
		eor r48, r48, r23
		ldr r44, [r21, +r44] 
		eor r12, r12, \P4
		ldr r61, [r25, +r61] 
		eor r63, r44, r63
		add r63, r63, r61 
		eor r12, r12, r63
.endm

_BF_encrypt2:		
		isub r52, r1, r0
		mov r20, 0x448
		mov r21, 0x848
		mov r25, 0xc48
		iadd r16, r0, r20
		iadd r17, r0, r21
		iadd r18, r0, r25
		add r26, r0, 72
		add r19, r1, 72
		iadd r20, r1, r20
		iadd r21, r1, r21
		iadd r25, r1, r25
		add r53, r52, 4
		mov r48, 0x0
		mov r56, 0x0
		mov r12, 0x0
		mov r47, 0x0
		mov r51, 0x4
		mov r50, 0x3fc
		mov r49, 0xff
		mov r59, 8
		mov r2, r0 ; ptr
		add r3, r2, 72 ; end

loop1: 
		ldr r27, [r0]
		iadd r45, r0, r51
		eor r48, r27, r48
		ldr r27, [r1]
		iadd r46, r1, r51
		eor r12, r27, r12
		BF2_2ROUND_A
		BF2_2ROUND_A
		BF2_2ROUND_A
		BF2_2ROUND_A
		BF2_2ROUND_A
		BF2_2ROUND_A
		BF2_2ROUND_A
		BF2_2ROUND_A
		ldr r22, [r0, +0x11]
		ldr r23, [r1, +0x11]
		eor r22, r56, r22
		str r22, [r2]
		str r48, [r2, +0x1]
		eor r23, r47, r23
		str r23, [r2, +r52]
		str r12, [r2, +r53]
		iadd r2, r2, r59
		mov r56, r48
		mov r47, r12
		mov r48, r22
		mov r12, r23
		sub r24, r3, r2
		bgtu loop1
		
		add r2, r0, 72
		mov r3, 0x1000
		add r52, r1, 72
		strd r4, [sp, -0x2]
		strd r6, [sp, -0x4]
		strd r32, [sp, -0x6]
		strd r34, [sp, -0x8]
		strd r36, [sp, -0xa]
		strd r38, [sp, -0xc]
		strd r40, [sp, -0xe]
		strd r42, [sp, -0x10]
		strd r8, [sp, -0x12]
		strd r10, [sp, -0x14]
		strd r14, [sp, -0x16]
		strd r28, [sp, -0x18]
		strd r30, [sp, -0x1a]
		iadd r3, r2, r3; end
		ldr r4, [r0, +0x1]
		ldr r5, [r0, +0x2]
		ldr r6, [r0, +0x3]
		ldr r7, [r0, +0x4]
		ldr r32, [r0, +0x5]
		ldr r33, [r0, +0x6]
		ldr r34, [r0, +0x7]
		ldr r35, [r0, +0x8]
		ldr r36, [r0, +0x9]
		ldr r37, [r0, +0xa]
		ldr r38, [r0, +0xb]
		ldr r39, [r0, +0xc]
		ldr r40, [r0, +0xd]
		ldr r41, [r0, +0xe]
		ldr r42, [r0, +0xf]
		ldr r43, [r0, +0x10]
		ldr r8, [r1, +0x1]
		ldr r9, [r1, +0x2]
		ldr r10, [r1, +0x3]
		ldr r11, [r1, +0x4]
		ldr r14, [r1, +0x5]
		ldr r15, [r1, +0x6]
		ldr r27, [r1, +0x7]
		ldr r28, [r1, +0x8]
		ldr r29, [r1, +0x9]
		ldr r30, [r1, +0xa]
		ldr r31, [r1, +0xb]
		ldr r45, [r1, +0xc]
		ldr r46, [r1, +0xd]
		ldr r59, [r1, +0xe]
		ldr r62, [r1, +0xf]
		ldr r53, [r1, +0x10]
		ldr r54, [r0] ; P0[0]
		ldr r55, [r1] ; P1[0]
		ldr r57, [r0, +0x11] ; P0[17]
		ldr r58, [r1, +0x11] ; P1[17]

loop2: 
		eor r48, r54, r48
		eor r12, r55, r12
		BF2_2ROUND_B r4, r5, r8, r9
		BF2_2ROUND_B r6, r7, r10, r11
		BF2_2ROUND_B r32, r33, r14, r15
		BF2_2ROUND_B r34, r35, r27, r28
		BF2_2ROUND_B r36, r37, r29, r30
		BF2_2ROUND_B r38, r39, r31, r45
		BF2_2ROUND_B r40, r41, r46, r59
		BF2_2ROUND_B r42, r43, r62, r53
		eor r22, r56, r57
		str r22, [r2]
		str r48, [r2, +0x1]
		eor r23, r47, r58
		str r23, [r52]
		str r12, [r52, +0x1]
		add r2, r2, 8
		add r52, r52, 8
		mov r56, r48
		mov r47, r12
		mov r48, r22
		mov r12, r23
		sub r24, r3, r2
		bgtu loop2
		ldrd r4, [sp, -0x2]
		ldrd r6, [sp, -0x4]
		ldrd r32, [sp, -0x6]
		ldrd r34, [sp, -0x8]
		ldrd r36, [sp, -0xa]
		ldrd r38, [sp, -0xc]
		ldrd r40, [sp, -0xe]
		ldrd r42, [sp, -0x10]
		ldrd r8, [sp, -0x12]
		ldrd r10, [sp, -0x14]
		ldrd r14, [sp, -0x16]
		ldrd r28, [sp, -0x18]
		ldrd r30, [sp, -0x1a]
		.size	_BF_encrypt2, .-_BF_encrypt2
		.balign 4
