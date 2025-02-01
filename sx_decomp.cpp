#include <iostream>
#include <fstream>
#include <ostream>
#include <filesystem>
#include <map>
#include "opcodes.h"
#include <magic_enum.hpp>

namespace fs = std::filesystem;

static int get_dsize(opcode_arg_t arg_type)
{
    if (arg_type == OP_ARG_WORD || arg_type == OP_ARG_PCR || arg_type == OP_ARG_SPR || arg_type == OP_ARG_POPO)
        return 2;
    else
        return 4;
}

static void assemble(const char* path, const char* out)
{
    std::ifstream file(path);
    std::ofstream assembled_file(out, std::ios::binary);
    std::string line;
    while (std::getline(file, line)) {
        size_t pipe = line.find('|');
        if (pipe == std::string::npos)              return;
        if (line.find('#') != std::string::npos)    continue;

        std::istringstream iss(line.substr(pipe + 1));
        std::vector<std::string> tokens;
        std::string token;
        while (iss >> token)
            tokens.push_back(token);

        if (tokens.size() >= 1) {
            opcode_t opcode = magic_enum::enum_cast<opcode_t>(tokens[0]).value();
            opcode_arg_t arg_type = tokens.size() > 1 ?
                                        magic_enum::enum_cast<opcode_arg_t>(tokens[1]).value_or(OP_ARG_NULL)
                                        : OP_ARG_NULL;
            
            assembled_file.write(reinterpret_cast<char*>(&arg_type), 1);
            assembled_file.write(reinterpret_cast<char*>(&opcode), 1);

            if (arg_type != OP_ARG_NULL && tokens.size() > 2) {
                auto dsize = get_dsize(arg_type);
                uint32_t val = 0;
                if (arg_type == OP_ARG_NUM) {
                    float fval = std::stof(tokens[2]);
                    val = *reinterpret_cast<uint32_t*>(&fval);
                }
                else
                    val = std::stoul(tokens[2], nullptr, 16);

                if (dsize == 4)
                    val = (val & 0xFFFF) << 16 | (((val >> 16) & 0xFFFF));

                assembled_file.write(reinterpret_cast<char*>(&val), dsize);
            }
        }
    }
    assembled_file.close();
}

static void disassemble(char* path, const bool verbose)
{
    fs::path base = path;
    std::ifstream file(path, std::ios::binary);
    std::vector<std::string> ss_tbl;
    if (!verbose) {
        std::ifstream sstbl(base.replace_extension(".xbsst"), std::ios::binary);
        if (sstbl.good()) {
            std::string line;
            std::getline(sstbl, line);
            if (line == "strngtbl") {
                std::getline(sstbl, line);
                size_t count = std::stoi(line);
                while (count-- && std::getline(sstbl, line))
                    ss_tbl.push_back(line);
            }
            sstbl.close();
        }
    }

    int PC = 0, prev_PC = 0;
    while (file.good()) {
        uint16_t op;
        file.seekg(PC, std::ios::beg);
        file.read(reinterpret_cast<char*>(&op), 2);
        if (file.eof() || op == 0)       // adding nothing? impossible.
            break;

        opcode_t opcode = (opcode_t)(op >> 8);
        bool has_arg = (op & OP_ARGTYPE_MASK) != 0;
        if ((op & OP_DSIZE_FLAG) != 0)
            PC += 2;

        int tmp_datasize = 0, arg = 0;
        opcode_arg_t arg_type = (opcode_arg_t)(op & OP_ARGTYPE_MASK);
        if (has_arg && arg_type != OP_ARG_NULL) {
            tmp_datasize = get_dsize(arg_type);
            file.seekg(PC + 2, std::ios::beg);
            file.read(reinterpret_cast<char*>(&arg), tmp_datasize);
            if (tmp_datasize == 4 && arg_type == OP_ARG_NUM)
                arg = ((uint16_t)arg) << 16 | (uint16_t)(arg >> 16);
            else
                arg = ((int16_t)arg);
        }
        PC += 2 + tmp_datasize;

        printf("0x%08X:  ", prev_PC);
        if (verbose) {
            std::vector<char> bytes;
            size_t op_len = PC - prev_PC;
            bytes.resize(op_len);
            file.seekg(prev_PC, std::ios::beg);
            file.read(reinterpret_cast<char*>(&bytes.data()[0]), op_len);
            for (const auto& c : bytes)
                printf("%02hhX ", c);

            size_t bytes_len = bytes.size() * 3 - 1;
            if (bytes_len < 20)
                printf("%*s", int(20 - bytes_len), "");
        }

        printf("| %-10s \t%-10s \t", std::string(magic_enum::enum_name(opcode)).substr(3).c_str(), arg_type != OP_ARG_NULL ? std::string(magic_enum::enum_name(arg_type)).c_str() : "");
        if (has_arg)
            if (arg_type == OP_ARG_NUM)
                printf("%f", *reinterpret_cast<float*>(&arg));
            else if (!verbose && opcode == OP_PSH && arg_type == OP_ARG_STR)
                printf("%s", ss_tbl[arg].c_str());
            else
                printf("0x%-8X", !verbose && arg_type == OP_ARG_PCR ? PC + ((int16_t)arg) : arg);
        printf("\n");
        prev_PC = PC;
    }
    file.close();
}

int main(int argc, char ** argp)
{
    if (strstr(argp[1], "-d")) 
        disassemble(argp[2], (bool)strstr(argp[1], "v"));
    else if (strstr(argp[1], "-a"))
        assemble(argp[2], argp[3]);
    return 0;
}