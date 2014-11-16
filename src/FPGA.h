/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2014 by Katja Malvoni <kmalvoni at gmail dot com>
 * It is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, 
 * with or without modification, are permitted.
 */

#include "arch.h"
#include "common.h"
#include "BF_std.h"

#define MAP_SIZE 			4096UL
#define MAP_SIZE_S 			(4096UL * BF_N)
#define MAP_SIZE_OTHERS 		(256UL * BF_N)
#define BCRYPT				0x40420000
#define BCRYPT_S			0x40000000
#define BCRYPT_OTHERS			0x40400000

#define MAP_MASK 			(MAP_SIZE - 1)
#define MAP_MASK_S 			(MAP_SIZE_S - 1)
#define MAP_MASK_OTHERS 		(MAP_SIZE_OTHERS - 1)
#define BF_ROUNDS			16

typedef BF_word BF_key[BF_ROUNDS + 2];

typedef struct {
	BF_key P;
	BF_key exp_key;
	BF_word salt[4];
	BF_word rounds;
} other_data;

typedef struct {
	other_data data[2];
	BF_word dummy[46];
} tiny_bram;

typedef enum {
	HOST_TO_FPGA,
	FPGA_TO_HOST,
} direction;

typedef struct {
	tiny_bram data[(BF_N/2)];
	BF_word S[BF_N][4*0x100];
} FPGA_data;

void FPGA_reset();
void FPGA_start();
void FPGA_done();
void FPGA_transfer_data(FPGA_data *src, direction dir);
