// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <openssl/ec.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

struct EcKeyDeleter {
    void operator()(EC_KEY* key) const;
};

using EcKeyPtr = std::unique_ptr<EC_KEY, EcKeyDeleter>;

EcKeyPtr get_ec_pubkey(const unsigned char* pubkey, std::size_t pubkey_len, std::uint32_t algo);
std::vector<unsigned char> get_raw_pubkey(EC_KEY* key);
int get_key_algorithm(EC_KEY* key);
EcKeyPtr load_key(const char* key_desc, const char* passphrase);
int hash_pubkey(const char* key_desc, const char* passphrase, const std::string& output_file);
void cleanup_crypto();
