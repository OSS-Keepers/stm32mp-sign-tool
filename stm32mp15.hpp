// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

#define STM32_MAGIC "STM2" // 0x53544D32

/*******************************************************************
 * https://wiki.st.com/stm32mpu/wiki/STM32_header_for_binary_files *
 *                                                                 *
 * Notes:                                                          *
 * - The signature is calculated over the data starting at offset  *
 *   0x48 (hdr_version field) up to the last byte given by the     *
 *   image_length field (i.e. sizeof(header) + header.length).     *
 * - The ecdsa_pubkey contains the public key (x, y) coordinates   *
 *   of the ECDSA key (64 bytes total).                            *
 *******************************************************************/
struct STM32Header {
    char magic[4];
    unsigned char signature[64];
    uint32_t checksum;
    uint32_t hdr_version;
    uint32_t length;
    uint32_t entry_addr;
    uint32_t reserved1; // Set to 0
    uint32_t load_addr;
    uint32_t reserved2; // Set to 0
    uint32_t rollback_version;
    uint32_t option_flags;
    uint32_t ecdsa_algo;
    unsigned char ecdsa_pubkey[64];
    unsigned char padding[83];
    unsigned char binary_type;
} __attribute__((packed));

static_assert(sizeof(STM32Header) == 256, "STM32 header must be 256 bytes");
