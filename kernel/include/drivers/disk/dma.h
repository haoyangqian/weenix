#pragma once

/* Linux kernel: drivers/ata/libata-sff.c */
#define DMA_COMMAND 0x00
#define DMA_STATUS  0x02
#define DMA_PRD     0x04 /* dword register */

/**
 * Initializes the DMA subsystem.
 */
void dma_init(void);

/* 1/21/17 Commented this out for now; it isn't implemented */
/**
 * Return the DMA status.
 *
 * @param busmaster_addr the address of the busmaster register
 */
/*void dma_status(uint16_t busmaster_addr);*/

/**
 * Resets DMA for its next operation by acknowledging an interrupt,
 * clearing all interrupts and errors.
 *
 * @param busmaster_addr the address of the busmaster register
 */
void dma_reset(uint16_t busmaster_addr);

/**
 * Initialize DMA for an operation
 *
 * @param channel the channel on which to perform the operation
 * @param start the beginning of the buffer in memory
 * @param count the number of bytes to read/write
 */
void dma_load(uint8_t channel, void* start, int count);

/* 1/24/13 Commented this out for now, it isn't used anyway */
/**
 * Cancel the current DMA operation.
 *
 * @param channel the disk channel
 */
/*void dma_stop(uint8_t channel);*/

/**
 * Execute a DMA operation.
 *
 * @param channel the disk channel
 * @param busmaster_addr the address of the busmaster register
 * @param write true if writing, false if reading
 */
void dma_start(uint8_t channel, uint16_t busmaster_addr, int write);
