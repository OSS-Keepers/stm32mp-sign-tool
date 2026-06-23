// SPDX-License-Identifier: GPL-3.0-or-later

#include "cli_options.hpp"

#include <cstring>
#include <iostream>
#include <string>

namespace {
bool is_option(const char* arg) {
    return arg && arg[0] == '-';
}

bool option_matches(const std::string& arg, const char* option) {
    const std::string opt(option);
    return arg == opt || arg.rfind(opt + "=", 0) == 0;
}

const char* option_value(const char* arg, const char* option) {
    const std::size_t len = std::strlen(option);
    if (std::strncmp(arg, option, len) == 0 && arg[len] == '=') {
        return arg + len + 1;
    }
    return nullptr;
}

bool matches_any(const std::string& arg, const char* a, const char* b = nullptr, const char* c = nullptr) {
    return option_matches(arg, a) ||
           (b && option_matches(arg, b)) ||
           (c && option_matches(arg, c));
}

int read_value(int argc, char* argv[], int* index, const char* option, const char** value) {
    const std::string arg(argv[*index]);
    const char* inline_value = option_value(argv[*index], option);
    if (inline_value) {
        *value = inline_value;
        return 0;
    }

    if (*index + 1 >= argc || is_option(argv[*index + 1])) {
        std::cerr << "Missing value for option: " << arg << std::endl;
        return -1;
    }

    ++(*index);
    *value = argv[*index];
    return 0;
}

int read_value_any(int argc, char* argv[], int* index, const char** value, const char* a, const char* b = nullptr, const char* c = nullptr) {
    const char* inline_value = option_value(argv[*index], a);
    if (!inline_value && b) {
        inline_value = option_value(argv[*index], b);
    }
    if (!inline_value && c) {
        inline_value = option_value(argv[*index], c);
    }
    if (inline_value) {
        *value = inline_value;
        return 0;
    }

    return read_value(argc, argv, index, a, value);
}
}

void usage(const char* argv0) {
    std::cout << "Usage: " << argv0
              << " -k|-prvk key_desc [-p|-pwd passphrase/pin] [-i|-in|-bin input_file] [-o output_file] [-h hash_file]"
              << std::endl
              << "       Also accepts ST-style options: -pubk, -la, -ep, -iv, -a, -of, -s, -type, -encdc, -enck, -dump, -hv, -nk"
              << std::endl;
}

int parse_cli_options(int argc, char* argv[], CliOptions* options) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);

        if (matches_any(arg, "-k", "--private-key", "-prvk")) {
            if (read_value_any(argc, argv, &i, &options->key_desc, "-k", "--private-key", "-prvk") != 0) {
                return -1;
            }
        } else if (matches_any(arg, "-p", "--password", "-pwd")) {
            if (read_value_any(argc, argv, &i, &options->passphrase, "-p", "--password", "-pwd") != 0) {
                return -1;
            }
        } else if (matches_any(arg, "-i", "--input", "-in")) {
            if (read_value_any(argc, argv, &i, &options->input_file, "-i", "--input", "-in") != 0) {
                return -1;
            }
        } else if (matches_any(arg, "--binary-image", "-bin")) {
            if (read_value_any(argc, argv, &i, &options->input_file, "--binary-image", "-bin") != 0) {
                return -1;
            }
        } else if (matches_any(arg, "-o", "--output")) {
            if (read_value_any(argc, argv, &i, &options->output_file, "-o", "--output") != 0) {
                return -1;
            }
        } else if (arg == "-v") {
            options->verbose = true;
        } else if (arg == "-s" || arg == "--silent") {
            options->silent = true;
        } else if (arg == "-nk" || arg == "--no-keys") {
            options->no_keys = true;
        } else if (matches_any(arg, "-h")) {
            if (read_value(argc, argv, &i, "-h", &options->output_hash) != 0) {
                return -1;
            }
        } else if (matches_any(arg, "--public-key", "-pubk")) {
            const char* inline_value = option_value(argv[i], "--public-key");
            if (!inline_value) {
                inline_value = option_value(argv[i], "-pubk");
            }
            if (inline_value) {
                options->public_keys.push_back(inline_value);
            } else {
                while (i + 1 < argc && !is_option(argv[i + 1]) && options->public_keys.size() < 8) {
                    ++i;
                    options->public_keys.push_back(argv[i]);
                }
            }
            if (options->public_keys.empty()) {
                std::cerr << "Missing value for option: " << arg << std::endl;
                return -1;
            }
        } else if (matches_any(arg, "--load-address", "-la")) {
            if (read_value_any(argc, argv, &i, &options->load_address, "--load-address", "-la") != 0) {
                return -1;
            }
        } else if (matches_any(arg, "--entry-point", "-ep")) {
            if (read_value_any(argc, argv, &i, &options->entry_point, "--entry-point", "-ep") != 0) {
                return -1;
            }
        } else if (matches_any(arg, "--image-version", "-iv")) {
            if (read_value_any(argc, argv, &i, &options->image_version, "--image-version", "-iv") != 0) {
                return -1;
            }
        } else if (matches_any(arg, "--algorithm", "-a")) {
            if (read_value_any(argc, argv, &i, &options->algorithm, "--algorithm", "-a") != 0) {
                return -1;
            }
        } else if (matches_any(arg, "--option-flags", "-of")) {
            if (read_value_any(argc, argv, &i, &options->option_flags, "--option-flags", "-of") != 0) {
                return -1;
            }
            options->option_flags_set = true;
        } else if (matches_any(arg, "--binary-type", "-type")) {
            if (read_value_any(argc, argv, &i, &options->binary_type, "--binary-type", "-type") != 0) {
                return -1;
            }
        } else if (matches_any(arg, "--enc-dc", "-encdc")) {
            if (read_value_any(argc, argv, &i, &options->enc_dc, "--enc-dc", "-encdc") != 0) {
                return -1;
            }
        } else if (matches_any(arg, "--enc-key", "-enck")) {
            if (read_value_any(argc, argv, &i, &options->enc_key, "--enc-key", "-enck") != 0) {
                return -1;
            }
        } else if (matches_any(arg, "--dump-header", "--dump", "-dump")) {
            if (read_value_any(argc, argv, &i, &options->dump_header, "--dump-header", "--dump", "-dump") != 0) {
                return -1;
            }
        } else if (matches_any(arg, "--header-version", "-hv")) {
            if (read_value_any(argc, argv, &i, &options->header_version, "--header-version", "-hv") != 0) {
                return -1;
            }
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            return -1;
        }
    }

    return 0;
}

int reject_unimplemented_options(const CliOptions& options) {
    if (!options.public_keys.empty()) {
        std::cerr << "Option --public-key/-pubk is not implemented yet" << std::endl;
        return -1;
    }
    if (options.load_address) {
        std::cerr << "Option --load-address/-la is not implemented yet" << std::endl;
        return -1;
    }
    if (options.entry_point) {
        std::cerr << "Option --entry-point/-ep is not implemented yet" << std::endl;
        return -1;
    }
    if (options.image_version) {
        std::cerr << "Option --image-version/-iv is not implemented yet" << std::endl;
        return -1;
    }
    if (options.algorithm) {
        std::cerr << "Option --algorithm/-a is not implemented yet" << std::endl;
        return -1;
    }
    if (options.option_flags_set) {
        std::cerr << "Option --option-flags/-of is not implemented yet" << std::endl;
        return -1;
    }
    if (options.silent) {
        std::cerr << "Option --silent/-s is not implemented yet" << std::endl;
        return -1;
    }
    if (options.binary_type) {
        std::cerr << "Option --binary-type/-type is not implemented yet" << std::endl;
        return -1;
    }
    if (options.enc_dc) {
        std::cerr << "Option --enc-dc/-encdc is not implemented yet" << std::endl;
        return -1;
    }
    if (options.enc_key) {
        std::cerr << "Option --enc-key/-enck is not implemented yet" << std::endl;
        return -1;
    }
    if (options.dump_header) {
        std::cerr << "Option --dump-header/--dump/-dump is not implemented yet" << std::endl;
        return -1;
    }
    if (options.header_version) {
        std::cerr << "Option --header-version/-hv is not implemented yet" << std::endl;
        return -1;
    }
    if (options.no_keys) {
        std::cerr << "Option --no-keys/-nk is not implemented yet" << std::endl;
        return -1;
    }

    return 0;
}
