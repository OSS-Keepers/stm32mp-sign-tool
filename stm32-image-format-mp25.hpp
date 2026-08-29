// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "stm32-image-format.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

class OpenSSLSupport;
class Utils;

class STM32ImageFormatMP25 : public STM32ImageFormat {
public:
    STM32ImageFormatMP25(std::shared_ptr<OpenSSLSupport> openSslSupport, std::shared_ptr<Utils> utils);

    int verify(const std::vector<unsigned char>& image) override;
    int sign(std::vector<unsigned char>& image, const std::string& keyDesc, const std::string& passphrase) override;

private:
    // On-disk layout:
    //   [128-byte base header]
    //   [optional authentication extension]
    //   [optional decryption extension]
    //   [padding extension to complete the 512-byte header]
    //   [image payload]
    struct STM32BaseHeaderV2_2 {
        char magic[4];
        unsigned char signature[64];
        uint32_t checksum;
        uint32_t hdr_version;
        uint32_t length;
        uint32_t entry_addr;
        uint32_t reserved[3];
        uint32_t rollback_version;
        uint32_t option_flags;
        uint32_t extensions_length;
        uint32_t binary_type;
        unsigned char padding[16];
    } __attribute__((packed));

    struct STM32AuthenticationExtensionV2_2 {
        uint32_t extension_type;
        uint32_t extension_length;
        uint32_t public_key_index;
        uint32_t public_key_count;
        uint32_t ecdsa_algorithm;
        unsigned char ecdsa_public_key[64];
        unsigned char public_key_hashes[8][32];
    } __attribute__((packed));

    struct STM32DecryptionExtensionV2_2 {
        uint32_t extension_type;
        uint32_t extension_length;
        uint32_t key_size;
        uint32_t derivation_constant;
        unsigned char plaintext_hash[16];
    } __attribute__((packed));

    struct STM32PaddingExtensionHeaderV2_2 {
        uint32_t extension_type;
        uint32_t extension_length;
        // Variable-length zero padding follows this fixed prefix on disk.
    } __attribute__((packed));

    struct STM32PaddingExtensionV2_2 {
        STM32PaddingExtensionHeaderV2_2 header;
        std::vector<unsigned char> padding;
    };

    // Logical representation of the complete header. Unlike the packed
    // structures above, this type does not represent one contiguous wire
    // structure because the extensions are optional and padding is variable.
    struct STM32HeaderV2_2 {
        STM32BaseHeaderV2_2 base_header;
        std::optional<STM32AuthenticationExtensionV2_2> authentication_extension;
        std::optional<STM32DecryptionExtensionV2_2> decryption_extension;
        STM32PaddingExtensionV2_2 padding_extension;
    };

    static_assert(sizeof(STM32BaseHeaderV2_2) == 128, "Invalid STM32 v2.2 base header size");
    static_assert(sizeof(STM32AuthenticationExtensionV2_2) == 340, "Invalid STM32 v2.2 authentication extension size");
    static_assert(sizeof(STM32DecryptionExtensionV2_2) == 32, "Invalid STM32 v2.2 decryption extension size");
    static_assert(sizeof(STM32PaddingExtensionHeaderV2_2) == 8, "Invalid STM32 v2.2 padding extension prefix size");

    STM32BaseHeaderV2_2 unpackBaseHeader(const std::vector<unsigned char>& image);
    void repackBaseHeader(std::vector<unsigned char>& image, const STM32BaseHeaderV2_2& header);

    std::shared_ptr<OpenSSLSupport> openSslSupport;
    std::shared_ptr<Utils> utils;
};
