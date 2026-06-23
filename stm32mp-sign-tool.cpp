// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * (C) Copyright 2024
 * Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 3 of
 * the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <cstdint>
#include <iomanip>
#include <memory>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>

#include "cli_options.hpp"
#include "crypto.hpp"
#include "stm32mp15.hpp"

static bool verbose = false;

namespace {
struct BnDeleter {
    void operator()(BIGNUM* bn) const {
        BN_free(bn);
    }
};

struct EcdsaSigDeleter {
    void operator()(ECDSA_SIG* sig) const {
        ECDSA_SIG_free(sig);
    }
};

using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;
using EcdsaSigPtr = std::unique_ptr<ECDSA_SIG, EcdsaSigDeleter>;
}

STM32Header unpack_stm32_header(const std::vector<unsigned char>& image) {
    STM32Header header;
    std::memcpy(&header, image.data(), sizeof(STM32Header));
    return header;
}

void repack_stm32_header(std::vector<unsigned char>& image, const STM32Header& header) {
    std::memcpy(image.data(), &header, sizeof(STM32Header));
}

void print_hex(const std::string& label, const std::vector<unsigned char>& data) {
    if (!verbose) 
        return;
    std::cout << label << ": ";
    for (unsigned char byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl;
}

int verify_stm32_image(const std::vector<unsigned char>& image) {
    if (image.empty()) {
        std::cerr << "Image data is empty" << std::endl;
        return -1;
    }
    STM32Header header = unpack_stm32_header(image);

    if (std::strncmp(header.magic, STM32_MAGIC, sizeof(header.magic)) != 0) {
        std::cerr << "Not an STM32 header (signature FAIL)" << std::endl;
        return -1;
    }

    // The ROM code hashes exactly 'header.length' bytes after the header (256 bytes), so we must not include trailing padding.
    size_t hash_end = sizeof(STM32Header) + header.length;
    if (hash_end > image.size()) {
        std::cerr << "Image too short: expected at least " << hash_end << " bytes, got " << image.size() << std::endl;
        return -1;
    }
    std::vector<unsigned char> buffer_to_hash(image.begin() + offsetof(STM32Header, hdr_version), image.begin() + static_cast<std::ptrdiff_t>(hash_end));
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    if (!SHA256(buffer_to_hash.data(), buffer_to_hash.size(), hash.data())) {
        std::cerr << "Failed to compute SHA-256 hash" << std::endl;
        return -1;
    }
    std::vector<unsigned char> signature(header.signature, header.signature + sizeof(header.signature));
    print_hex("Hash", hash);
    print_hex("Signature", signature);

    EcdsaSigPtr sig(ECDSA_SIG_new());

    if (!sig) {
        std::cerr << "Failed to create ECDSA_SIG structure" << std::endl;
        return -1;
    }

    // Extract r and s from the signature buffer
    BnPtr r(BN_bin2bn(signature.data(), sizeof(header.signature) / 2, nullptr));
    BnPtr s(BN_bin2bn(signature.data() + sizeof(header.signature) / 2, sizeof(header.signature) / 2, nullptr));
    if (!r || !s) {
        std::cerr << "Failed to create BIGNUMs for r and s" << std::endl;
        return -1;
    }

    if (ECDSA_SIG_set0(sig.get(), r.get(), s.get()) == 0) {
        std::cerr << "Failed to set r and s in ECDSA_SIG" << std::endl;
        return -1;
    }
    r.release();
    s.release();

    EcKeyPtr pubkey = get_ec_pubkey(header.ecdsa_pubkey, sizeof(header.ecdsa_pubkey), header.ecdsa_algo);
    if (!pubkey) {
        std::cerr << "Failed to get EC_KEY from public key" << std::endl;
        return -1;
    }
    int verify_status = ECDSA_do_verify(hash.data(), SHA256_DIGEST_LENGTH, sig.get(), pubkey.get());

    if (verify_status == 1) {
        return 0;
    } else {
        std::cerr << "Signature does not match: " << verify_status << std::endl;
        return -1;
    }
}

int sign_stm32_image(std::vector<unsigned char>& image, const char* key_desc, const char* passphrase) {
    if (image.empty()) {
        std::cerr << "Image data is empty" << std::endl;
        return -1;
    }
    if (!key_desc || std::strlen(key_desc) == 0) {
        std::cerr << "Key file path is empty" << std::endl;
        return -1;
    }
    EcKeyPtr key = load_key(key_desc, passphrase);
    if (!key) {
        std::cerr << "Failed to load key" << std::endl;
        return -1;
    }

    STM32Header header = unpack_stm32_header(image);

    if (std::strncmp(header.magic, STM32_MAGIC, sizeof(header.magic)) != 0) {
        std::cerr << "Not an STM32 header (signature FAIL)" << std::endl;
        return -1;
    }

    // Ensure reserved fields are set to 0
    header.reserved1 = 0;
    header.reserved2 = 0;


    // Get the public key from the private key
    std::vector<unsigned char> pubkey = get_raw_pubkey(key.get());
    if (pubkey.empty()) {
        return -1;
    }
    print_hex("Public Key", pubkey);

    std::memcpy(header.ecdsa_pubkey, pubkey.data(), pubkey.size());
    if(get_key_algorithm(key.get()) < 0) {
        return -1;
    }
    header.ecdsa_algo = static_cast<uint32_t>(get_key_algorithm(key.get()));
    header.option_flags = 0;
    std::memset(header.padding, 0, sizeof(header.padding)); // Ensure padding is zeroed
    repack_stm32_header(image, header);

    // The ROM code hashes exactly 'header.length' bytes after the header (256 bytes), so we must not include trailing padding.
    size_t hash_end = sizeof(STM32Header) + header.length;
    if (hash_end > image.size()) {
        std::cerr << "Image too short: expected at least " << hash_end << " bytes, got " << image.size() << std::endl;
        return -1;
    }
    std::vector<unsigned char> buffer_to_hash(image.begin() + offsetof(STM32Header, hdr_version), image.begin() + static_cast<std::ptrdiff_t>(hash_end));

    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    if (!SHA256(buffer_to_hash.data(), buffer_to_hash.size(), hash.data())) {
        std::cerr << "Failed to compute SHA-256 hash" << std::endl;
        return -1;
    }
    print_hex("Hash(sha256)", hash);

    EcdsaSigPtr sig(ECDSA_do_sign(hash.data(), SHA256_DIGEST_LENGTH, key.get()));
    if (sig == nullptr) {
        std::cerr << "Failed to sign the image" << std::endl;
        return -1;
    }

    const BIGNUM* r;
    const BIGNUM* s;
    ECDSA_SIG_get0(sig.get(), &r, &s);

    std::vector<unsigned char> r_bytes(static_cast<size_t>(BN_num_bytes(r)));
    std::vector<unsigned char> s_bytes(static_cast<size_t>(BN_num_bytes(s)));
    if (BN_bn2binpad(r, r_bytes.data(), static_cast<int>(r_bytes.size())) < 0 || BN_bn2binpad(s, s_bytes.data(), static_cast<int>(s_bytes.size())) < 0) {
        std::cerr << "Failed to convert BIGNUM to binary" << std::endl;
        return -1;
    }
    print_hex("ECC key(r)", r_bytes);
    print_hex("ECC key(s)", s_bytes);

    std::vector<unsigned char> signature(sizeof(header.signature));
    std::memset(signature.data(), 0, signature.size());
    std::memcpy(signature.data() + (sizeof(header.signature) / 2 - r_bytes.size()), r_bytes.data(), r_bytes.size());
    std::memcpy(signature.data() + sizeof(header.signature) - s_bytes.size(), s_bytes.data(), s_bytes.size());
    print_hex("Signature", signature);

    std::memcpy(image.data() + offsetof(STM32Header, signature), signature.data(), signature.size());

    // Verify the signature
    return verify_stm32_image(image);

}

int main(int argc, char* argv[]) {
    if (argc == 1) {
        usage(argv[0]);
        return -1;
    }

    CliOptions options;
    if (parse_cli_options(argc, argv, &options) != 0) {
        usage(argv[0]);
        return -1;
    }
    verbose = options.verbose;

    if (reject_unimplemented_options(options) != 0) {
        return -1;
    }

    if (!options.key_desc && !options.no_keys) {
        std::cerr << "Must specify a key file or pkcs11 uri" << std::endl;
        return -1;
    }

    if (options.input_file) {
        std::ifstream image_file(options.input_file, std::ios::binary);
        std::vector<unsigned char> image((std::istreambuf_iterator<char>(image_file)), std::istreambuf_iterator<char>());
        image_file.close();

        if (sign_stm32_image(image, options.key_desc, options.passphrase) != 0) {
            return -1;
        }

        if (options.output_file) {
            std::ofstream output(options.output_file, std::ios::binary);
            output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
            output.close();
        }
    }

    if (options.output_hash) {
        if (hash_pubkey(options.key_desc, options.passphrase, options.output_hash) != 0) {
            return -1;
        }
    }

    cleanup_crypto();

    // Securely erase the passphrase
    if (options.passphrase) {
        OPENSSL_cleanse(static_cast<void*>(const_cast<char*>(options.passphrase)), std::strlen(options.passphrase));
    }

    // Securely erase the key_desc in case it's a pkcs11 uri with pin
    if (options.key_desc) {
        OPENSSL_cleanse(static_cast<void*>(const_cast<char*>(options.key_desc)), std::strlen(options.key_desc));
    }

    return 0;
}
