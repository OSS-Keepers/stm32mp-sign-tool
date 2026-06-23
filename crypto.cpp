// SPDX-License-Identifier: GPL-3.0-or-later

#include "crypto.hpp"

#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>

#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

extern void print_hex(const std::string& label, const std::vector<unsigned char>& data);

namespace {
struct BnDeleter {
    void operator()(BIGNUM* bn) const {
        BN_free(bn);
    }
};

struct EcPointDeleter {
    void operator()(EC_POINT* point) const {
        EC_POINT_free(point);
    }
};

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* pkey) const {
        EVP_PKEY_free(pkey);
    }
};

struct FileDeleter {
    void operator()(FILE* file) const {
        fclose(file);
    }
};

struct EngineDeleter {
    void operator()(ENGINE* engine) const {
        ENGINE_finish(engine);
        ENGINE_free(engine);
    }
};

struct EngineRefDeleter {
    void operator()(ENGINE* engine) const {
        ENGINE_free(engine);
    }
};

using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;
using EcPointPtr = std::unique_ptr<EC_POINT, EcPointDeleter>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using FilePtr = std::unique_ptr<FILE, FileDeleter>;
using EnginePtr = std::unique_ptr<ENGINE, EngineDeleter>;
using EngineRefPtr = std::unique_ptr<ENGINE, EngineRefDeleter>;

EnginePtr engine;
}

void EcKeyDeleter::operator()(EC_KEY* key) const {
    EC_KEY_free(key);
}

EcKeyPtr get_ec_pubkey(const unsigned char* pubkey, std::size_t pubkey_len, std::uint32_t algo) {
    if (!pubkey) {
        std::cerr << "Public key is empty" << std::endl;
        return nullptr;
    }
    if (pubkey_len != 64) {
        std::cerr << "Invalid public key length" << std::endl;
        return nullptr;
    }
    int curve_nid;
    if (algo == 1) {
        curve_nid = NID_X9_62_prime256v1;
    } else if (algo == 2) {
        curve_nid = NID_brainpoolP256t1;
    } else {
        std::cerr << "Unsupported ECDSA algorithm" << std::endl;
        return nullptr;
    }
    EcKeyPtr ec_key(EC_KEY_new_by_curve_name(curve_nid));
    if (!ec_key) {
        std::cerr << "Failed to create EC_KEY object" << std::endl;
        return nullptr;
    }

    BnPtr x(BN_bin2bn(pubkey, 32, nullptr));
    BnPtr y(BN_bin2bn(pubkey + 32, 32, nullptr));
    if (!x || !y) {
        std::cerr << "Failed to create BIGNUMs for public key coordinates" << std::endl;
        return nullptr;
    }

    EcPointPtr point(EC_POINT_new(EC_KEY_get0_group(ec_key.get())));
    if (!point) {
        std::cerr << "Failed to create EC_POINT object" << std::endl;
        return nullptr;
    }

    if (!EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(ec_key.get()), point.get(), x.get(), y.get(), nullptr)) {
        std::cerr << "Failed to set affine coordinates" << std::endl;
        return nullptr;
    }

    if (!EC_KEY_set_public_key(ec_key.get(), point.get())) {
        std::cerr << "Failed to set public key" << std::endl;
        return nullptr;
    }

    if (!EC_KEY_check_key(ec_key.get())) {
        std::cerr << "Invalid EC key" << std::endl;
        return nullptr;
    }

    return ec_key;
}

std::vector<unsigned char> get_raw_pubkey(EC_KEY* key) {
    if (!key) {
        std::cerr << "Invalid EC_KEY" << std::endl;
        return {};
    }
    const EC_POINT* point = EC_KEY_get0_public_key(key);
    const EC_GROUP* group = EC_KEY_get0_group(key);
    std::vector<unsigned char> pubkey(64);
    BnPtr x(BN_new());
    BnPtr y(BN_new());
    if (!x || !y) {
        std::cerr << "Failed to allocate BIGNUM" << std::endl;
        return {};
    }
    if (!EC_POINT_get_affine_coordinates_GFp(group, point, x.get(), y.get(), nullptr)) {
        std::cerr << "Failed to get affine coordinates" << std::endl;
        return {};
    }
    if (BN_bn2binpad(x.get(), pubkey.data(), 32) != 32 || BN_bn2binpad(y.get(), pubkey.data() + 32, 32) != 32) {
        std::cerr << "Failed to convert BIGNUM to binary" << std::endl;
        return {};
    }
    return pubkey;
}

int get_key_algorithm(EC_KEY* key) {
    if (!key) {
        std::cerr << "Invalid EC_KEY" << std::endl;
        return -1;
    }
    const EC_GROUP* group = EC_KEY_get0_group(key);
    int nid = EC_GROUP_get_curve_name(group);
    if (nid == NID_X9_62_prime256v1) {
        return 1;
    }
    else if (nid == NID_brainpoolP256t1) {
        return 2;
    }
    std::cerr << "Unsupported ECDSA curve" << std::endl;
    return -1;
}

EcKeyPtr load_key(const char* key_desc, const char* passphrase) {
    if (!key_desc || std::strlen(key_desc) == 0) {
        std::cerr << "Invalid arguments" << std::endl;
        return nullptr;
    }
    if (std::strncmp(key_desc, "pkcs11:", 7) == 0) {
        ENGINE_load_builtin_engines();
        EngineRefPtr raw_engine(ENGINE_by_id("pkcs11"));
        if (!raw_engine) {
            std::cerr << "Failed to load PKCS#11 engine" << std::endl;
            return nullptr;
        }

        if (!ENGINE_init(raw_engine.get())) {
            std::cerr << "Failed to initialize PKCS#11 engine" << std::endl;
            return nullptr;
        }
        engine.reset(raw_engine.release());

        if (passphrase && !ENGINE_ctrl_cmd_string(engine.get(), "PIN", passphrase, 0)) {
            engine.reset();
            std::cerr << "Failed to set PKCS#11 PIN" << std::endl;
            return nullptr;
        }

        EvpPkeyPtr pkey(ENGINE_load_private_key(engine.get(), key_desc, nullptr, nullptr));
        if (!pkey) {
            engine.reset();
            std::cerr << "Failed to load private key from PKCS#11" << std::endl;
            return nullptr;
        }

        EcKeyPtr ec_key(EVP_PKEY_get1_EC_KEY(pkey.get()));
        if (!ec_key) {
            engine.reset();
            std::cerr << "Failed to extract EC_KEY from EVP_PKEY" << std::endl;
            return nullptr;
        }
        return ec_key;
    }

    FilePtr key_fp(fopen(key_desc, "r"));
    if (!key_fp) {
        std::cerr << "Failed to open key file" << std::endl;
        return nullptr;
    }

    EcKeyPtr ec_key(PEM_read_ECPrivateKey(key_fp.get(), nullptr, nullptr, static_cast<void*>(const_cast<char*>(passphrase))));
    if (!ec_key) {
        std::cerr << "Failed to read key from file" << std::endl;
        return nullptr;
    }
    return ec_key;
}

int hash_pubkey(const char* key_desc, const char* passphrase, const std::string& output_file) {
    if (!key_desc || output_file.empty()) {
        std::cerr << "Invalid arguments" << std::endl;
        return -1;
    }
    EcKeyPtr key = load_key(key_desc, passphrase);
    if (!key) {
        std::cerr << "Failed to load key" << std::endl;
        return -1;
    }
    std::vector<unsigned char> pubkey = get_raw_pubkey(key.get());
    if (pubkey.empty()) {
        std::cerr << "Failed to get raw public key" << std::endl;
        return -1;
    }

    std::vector<unsigned char> phash(SHA256_DIGEST_LENGTH);
    SHA256(pubkey.data(), pubkey.size(), phash.data());
    print_hex("Pubkey(sha256)", phash);

    std::ofstream output(output_file, std::ios::binary);
    if (!output) {
        std::cerr << "Failed to open output file: " << output_file << std::endl;
        return -1;
    }
    output.write(reinterpret_cast<const char*>(phash.data()), static_cast<std::streamsize>(phash.size()));
    output.close();

    return 0;
}

void cleanup_crypto() {
    engine.reset();
}
