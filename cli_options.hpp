// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <vector>

struct CliOptions {
    const char* key_desc = nullptr;
    const char* passphrase = nullptr;
    const char* input_file = nullptr;
    const char* output_file = nullptr;
    const char* output_hash = nullptr;

    std::vector<const char*> public_keys;
    const char* load_address = nullptr;
    const char* entry_point = nullptr;
    const char* image_version = nullptr;
    const char* algorithm = nullptr;
    const char* option_flags = nullptr;
    const char* binary_type = nullptr;
    const char* enc_dc = nullptr;
    const char* enc_key = nullptr;
    const char* dump_header = nullptr;
    const char* header_version = nullptr;

    bool option_flags_set = false;
    bool silent = false;
    bool no_keys = false;
    bool verbose = false;
};

void usage(const char* argv0);
int parse_cli_options(int argc, char* argv[], CliOptions* options);
int reject_unimplemented_options(const CliOptions& options);
