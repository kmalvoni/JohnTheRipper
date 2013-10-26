/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013 by Katja Malvoni <kmalvoni at gmail dot com>
 * It is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, 
 * with or without modification, are permitted.
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include "arch.h"
#include "common.h"
#include "BF_std.h"
#include "FPGA.h"

void BF_fpga(FPGA_data *src)
{	
	int memfd;
	void *mapped_base, *mapped_dev_base;
	off_t dev_base = CDMA_ADDR;

	int memfd_1;
	void *mapped_base_1, *mapped_dev_base_1;
	off_t dev_base_1 = HIGH_OCM;

	int memfd_2;
	void *mapped_base_2, *mapped_dev_base_2;
	off_t dev_base_2 = BCRYPT;

	unsigned int TimeOut = 5;
	unsigned int ResetMask;
	unsigned int RegValue;
	struct timeval start, end;
	
	memfd_2 = open("/dev/mem", O_RDWR | O_SYNC);
	if (memfd_2 == -1) {
		printf("Can't open /dev/mem.\n");
		exit(0);
	}
	
	mapped_base_2 = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, memfd_2, dev_base_2 & ~MAP_MASK);
	if (mapped_base_2 == (void *) -1) {
		printf("Can't map the memory to user space.\n");
		exit(0);
	}
	mapped_dev_base_2 = mapped_base_2 + (dev_base_2 & MAP_MASK);

	/*Software reset*/
	RegValue = 0;
	*((volatile unsigned short *)mapped_dev_base_2 + 0x0) = RegValue;

	if (munmap(mapped_base_2, MAP_SIZE) == -1) {
		printf("Can't unmap memory from user space.\n");
		exit(0);
	}

	close(memfd_2);
	memfd_1 = open("/dev/mem", O_RDWR | O_SYNC);
	if (memfd_1 == -1) {
		printf("Can't open /dev/mem.\n");
		exit(0);
	}
	
	mapped_base_1 = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, memfd_1, dev_base_1 & ~MAP_MASK);
	if (mapped_base_1 == (void *) -1) {
		printf("Can't map the memory to user space.\n");
		exit(0);
	}

	mapped_dev_base_1 = mapped_base_1 + (dev_base_1 & MAP_MASK);
	
	memcpy(mapped_dev_base_1, src, sizeof(FPGA_data) * BF_N);

	if (munmap(mapped_base_1, MAP_SIZE) == -1) {
		printf("Can't unmap memory from user space.\n");
		exit(0);
	}
	close(memfd_1);

	memfd = open("/dev/mem", O_RDWR | O_SYNC);
	if (memfd == -1) {
		printf("Can't open /dev/mem.\n");
		exit(0);
	}
	
	mapped_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, dev_base & ~MAP_MASK);
	if (mapped_base == (void *) -1)
	{
		printf("Can't map the memory to user space.\n");
		exit(0);
	}

	mapped_dev_base = mapped_base + (dev_base & MAP_MASK);
	gettimeofday(&start, NULL);
	//Reset CDMA
	do{
		ResetMask = (unsigned long )XAXICDMA_CR_RESET_MASK;
		*((volatile unsigned long *) (mapped_dev_base + XAXICDMA_CR_OFFSET)) = (unsigned long)ResetMask;
		ResetMask = *((volatile unsigned long *) (mapped_dev_base + XAXICDMA_CR_OFFSET));
		if(!(ResetMask & XAXICDMA_CR_RESET_MASK))
		{
			break;
		}
		TimeOut -= 1;
	}while (TimeOut);
	//enable Interrupt
	RegValue = *((volatile unsigned long *) (mapped_dev_base + XAXICDMA_CR_OFFSET));
	RegValue = (unsigned long)(RegValue | XAXICDMA_XR_IRQ_ALL_MASK );
	*((volatile unsigned long *) (mapped_dev_base + XAXICDMA_CR_OFFSET)) = (unsigned long)RegValue;
	// Checking for the Bus Idle
	RegValue = *((volatile unsigned long *) (mapped_dev_base + XAXICDMA_SR_OFFSET));
	if(!(RegValue & XAXICDMA_SR_IDLE_MASK)) {
		printf("BUS IS BUSY Error Condition\n");
		return;
	}
	// Check the DMA Mode and switch it to simple mode
	RegValue = *((volatile unsigned long *) (mapped_dev_base + XAXICDMA_CR_OFFSET));
	if((RegValue & XAXICDMA_CR_SGMODE_MASK)) {
		RegValue = (unsigned long)(RegValue & (~XAXICDMA_CR_SGMODE_MASK));
		printf("Reading\n");
		*((volatile unsigned long *) (mapped_dev_base + XAXICDMA_CR_OFFSET)) = (unsigned long)RegValue;
	}
	//Set the Source Address
	*((volatile unsigned long *) (mapped_dev_base + XAXICDMA_SRCADDR_OFFSET)) = (unsigned long)HIGH_OCM;
	//Set the Destination Address
	*((volatile unsigned long *) (mapped_dev_base + XAXICDMA_DSTADDR_OFFSET)) = (unsigned long)BRAM_DMA_ADDR;
	RegValue = (unsigned long)(sizeof(FPGA_data) * BF_N);
	// write Byte to Transfer
	*((volatile unsigned long *) (mapped_dev_base + XAXICDMA_BTT_OFFSET)) = (unsigned long)RegValue;
	/*======================================================================================
	STEP 6 : Wait for the DMA transfer Status
	========================================================================================*/
	do {
		RegValue = *((volatile unsigned long *) (mapped_dev_base + XAXICDMA_SR_OFFSET));
	}while(!(RegValue & XAXICDMA_XR_IRQ_ALL_MASK));

	gettimeofday(&end, NULL);
//	printf("Transfer from high OCM to bram: %f us.\n", (double)(end.tv_usec - start.tv_usec));

	//if((RegValue & XAXICDMA_XR_IRQ_IOC_MASK)) {
		//printf("Transfer Completed\n");
	//}
	//if((RegValue & XAXICDMA_XR_IRQ_DELAY_MASK)) {
		//printf("IRQ Delay Interrupt\n");
	//}
	//if((RegValue & XAXICDMA_XR_IRQ_ERROR_MASK)) {
		//printf(" Transfer Error Interrupt\n");
	//}

	if (munmap(mapped_base, MAP_SIZE) == -1) {
			printf("Can't unmap memory from user space.\n");
		exit(0);
	}

	close(memfd);

	memfd_2 = open("/dev/mem", O_RDWR | O_SYNC);
	if (memfd_2 == -1) {
		printf("Can't open /dev/mem.\n");
		exit(0);
	}

	mapped_base_2 = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, memfd_2, dev_base_2 & ~MAP_MASK);
	if (mapped_base_2 == (void *) -1) {
		printf("Can't map the memory to user space.\n");
		exit(0);
	}
	mapped_dev_base_2 = mapped_base_2 + (dev_base_2 & MAP_MASK);
	
	/*Start computation*/
	RegValue = 10;
	*((volatile unsigned long *)mapped_dev_base_2 + 0x0) = RegValue;
	
	/*Wait for done*/
	do {
		RegValue = *((volatile unsigned int*)(mapped_dev_base_2 + 4));
	} while(!RegValue);

	if (munmap(mapped_base_2, MAP_SIZE) == -1) {
		printf("Can't unmap memory from user space.\n");
		exit(0);
	}

	close(memfd_2);

	memfd = open("/dev/mem", O_RDWR | O_SYNC);
	if (memfd == -1)
	{
		printf("Can't open /dev/mem.\n");
		exit(0);
	}
	mapped_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, dev_base & ~MAP_MASK);
	if (mapped_base == (void *) -1)
	{
		printf("Can't map the memory to user space.\n");
		exit(0);
	}
	mapped_dev_base = mapped_base + (dev_base & MAP_MASK);

	gettimeofday(&start, NULL);

	//Reset CDMA
	do{
		ResetMask = (unsigned long )XAXICDMA_CR_RESET_MASK;
		*((volatile unsigned long *) (mapped_dev_base + XAXICDMA_CR_OFFSET)) = (unsigned long)ResetMask;
		/* If the reset bit is still high, then reset is not done	*/
		ResetMask = *((volatile unsigned long *) (mapped_dev_base + XAXICDMA_CR_OFFSET));
		if(!(ResetMask & XAXICDMA_CR_RESET_MASK))
		{
			break;
		}
		TimeOut -= 1;
	}while (TimeOut);
	//enable Interrupt
	RegValue = *((volatile unsigned long *) (mapped_dev_base + XAXICDMA_CR_OFFSET));
	RegValue = (unsigned long)(RegValue | XAXICDMA_XR_IRQ_ALL_MASK );
	*((volatile unsigned long *) (mapped_dev_base + XAXICDMA_CR_OFFSET)) = (unsigned long)RegValue;
	// Checking for the Bus Idle
	RegValue = *((volatile unsigned long *) (mapped_dev_base + XAXICDMA_SR_OFFSET));
	if(!(RegValue & XAXICDMA_SR_IDLE_MASK)) {
		printf("BUS IS BUSY Error Condition\n");
		return;
	}
	// Check the DMA Mode and switch it to simple mode
	RegValue = *((volatile unsigned long *) (mapped_dev_base + XAXICDMA_CR_OFFSET));
	if((RegValue & XAXICDMA_CR_SGMODE_MASK)) {
		RegValue = (unsigned long)(RegValue & (~XAXICDMA_CR_SGMODE_MASK));
		printf("Reading\n");
		*((volatile unsigned long *) (mapped_dev_base + XAXICDMA_CR_OFFSET)) = (unsigned long)RegValue;
	}
	//Set the Source Address
	*((volatile unsigned long *) (mapped_dev_base + XAXICDMA_SRCADDR_OFFSET)) = (unsigned long)BRAM_DMA_ADDR;
	//Set the Destination Address
	*((volatile unsigned long *) (mapped_dev_base + XAXICDMA_DSTADDR_OFFSET)) = (unsigned long)HIGH_OCM;
	RegValue = (unsigned long)(sizeof(FPGA_data) * BF_N);
	// write Byte to Transfer
	*((volatile unsigned long *) (mapped_dev_base + XAXICDMA_BTT_OFFSET)) = (unsigned long)RegValue;
	/*======================================================================================
	STEP 6 : Wait for the DMA transfer Status
	========================================================================================*/
	do {
		RegValue = *((volatile unsigned long *) (mapped_dev_base + XAXICDMA_SR_OFFSET));
	}while(!(RegValue & XAXICDMA_XR_IRQ_ALL_MASK));

	gettimeofday(&end, NULL);
//	printf("Transfer from bram to high OCM: %f us.\n", (double)(end.tv_usec - start.tv_usec));

	//if((RegValue & XAXICDMA_XR_IRQ_IOC_MASK)) {
			//printf("Transfer Completed\n");
	//}
	//if((RegValue & XAXICDMA_XR_IRQ_DELAY_MASK)) {
		//printf("IRQ Delay Interrupt\n");
	//}
	//if((RegValue & XAXICDMA_XR_IRQ_ERROR_MASK)) {
		//printf(" Transfer Error Interrupt\n");
	//}

	if (munmap(mapped_base, MAP_SIZE) == -1) {
			printf("Can't unmap memory from user space.\n");
		exit(0);
	}

	close(memfd);

	memfd_1 = open("/dev/mem", O_RDWR | O_SYNC);
	if (memfd_1 == -1) {
		printf("Can't open /dev/mem.\n");
		exit(0);
	}

	mapped_base_1 = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, memfd_1, dev_base_1 & ~MAP_MASK);
	if (mapped_base_1 == (void *) -1) {
		printf("Can't map the memory to user space.\n");
		exit(0);
	}

	mapped_dev_base_1 = mapped_base_1 + (dev_base_1 & MAP_MASK);
	memcpy(src, mapped_dev_base_1, sizeof(FPGA_data) * BF_N);
	if (munmap(mapped_base_1, MAP_SIZE) == -1) {
		printf("Can't unmap memory from user space.\n");
		exit(0);
	}

	close(memfd_1);
}
