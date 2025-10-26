#include <iostream>
#include <fstream>
#include <ostream>
#include <filesystem>
#include <map>
#include "opcodes.h"
#include <magic_enum.hpp>

namespace fs = std::filesystem;

std::map<uint16_t, uint16_t> ps2_pc_global_slc_funcremap = {
        { 0x00F4, 0x5     },
        { 0x0056, 0x4     },
        { 0x0034, 0x4     },
        { 0x00E2, 0x5     },
        { 0x01B5, 0xC    },
        { 0x0059, 0x4     },
        { 0x0035, 0x4     },
        { 0x0088, 0x4     },
        { 0x010D, 0x6     },
        { 0x0044, 0x4     },
        { 0x011E, 0xC     },
        { 0x0030, 0x4     },
        { 0x01A2, 0x4     },
        { 0x012B, 0xC     },
        { 0x012A, 0xC     },
        { 0x00EC, 0x7     },
        { 0x00ED, 0x7     },
        { 0x00DE, 0x6     },
        { 0x0087, 0x4     },
        { 0x00EF, 0x6     },
        { 0x01A7, 0xE     },
        { 0x0096, 0x4     },
        { 0x009F, 0x4     },
        { 0x00A2, 0x4     },
        { 0x007B, 0x4     },
        { 0x0023, 0x4     },
        { 0x0153, 0xC     },
        { 0x0051, 0x4     },
        { 0x0019, 0x4     },
        { 0x001B, 0x4     },
        { 0x0122, 0xC     },
        { 0x0014, 0x4     },
        { 0x00D3, 0x4     },
        { 0x00A9, 0x4     },
        { 0x0105, 0x6     },
        { 0x00F2, 0x5     },
        { 0x010A, 0x6     },
        { 0x00E1, 0x5     },
        { 0x018F, 0xD     },
        { 0x00FF, 0x4     },
        { 0x0151, 0xC     },
        { 0x0041, 0x4     },
        { 0x0017, 0x4     },
        { 0x0075, 0x4     },
        { 0x0064, 0x4     },
        { 0x005B, 0x4     },
        { 0x004D, 0x4     },
        { 0x0038, 0x4     },
        { 0x0018, 0x4     },
        { 0x0031, 0x4     },
        { 0x01A5, 0xE     },
        { 0x01B3, 0xC    },
        { 0x00E3, 0x5     },
        { 0x00CE, 0x5     },
};

#pragma pack(push, 1)
struct script_executable
{
    char mash_hdr[0x10];                    // standard mashable header
    char name[32];                          // name of this script
    int sx_exe_image;                       // ---- (internally used as ptr)
    int sx_exe_image_size;                  // actual bytecode len
    int script_objects;                     // ---- (internally used as ptr)
    int script_objects_by_name;             
    int total_script_objects;
    int global_script_object;
    int permanent_string_table;             // ---- (internally used as ptr)
    int permanent_string_table_size;        // number of strings in this script
    int system_string_table;                // ---- (internally used as ptr)
    int system_string_table_size;           // number of ? in this script(?)
    int script_object_dummy_list;
    int script_allocated_stuff_map;
    int flags;
    int info_t;
    int field_58;
    int field_5C;
};
#pragma pack(pop)

static int get_dsize(opcode_arg_t arg_type)
{
    if (arg_type == OP_ARG_WORD || arg_type == OP_ARG_PCR || arg_type == OP_ARG_SPR || arg_type == OP_ARG_POPO)
        return 2;
    else
        return 4;
}

static bool assemble(const char* path, const char* out)
{
    std::ifstream file(path);
    std::ofstream assembled_file(out, std::ios::binary);
    std::string line;
    while (std::getline(file, line)) {
        size_t pipe = line.find('|');
        if (pipe == std::string::npos || line.find('#') != std::string::npos) 
            continue;

        std::istringstream iss(line.substr(pipe + 1));
        std::vector<std::string> tokens;
        std::string token;
        while (iss >> token)
            tokens.push_back(token);

        if (tokens.size() >= 1) {
            opcode_t opcode = magic_enum::enum_cast<opcode_t>(std::string("OP_").append(tokens[0])).value();
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
    if (!assembled_file.good())
        return false;
    assembled_file.close();
    return true;
}

static bool disassemble(char* path, const bool verbose)
{
    fs::path base = path;
    std::ifstream file(path, std::ios::binary);

    script_executable hdr;
    auto hdr_size = sizeof script_executable;
    file.read(reinterpret_cast<char*>(&hdr), hdr_size);

    // if this is a PC script, then we read 4 bytes too many
    // as it seems that the last field was removed from the header on PC
    if (base.extension().compare(".PCSX") == 0) {
        file.seekg(-4, std::ios::cur);
        hdr_size -= 4;
    }

    const bool isPS2Version = hdr_size == 0x70;
    int end = hdr_size + hdr.sx_exe_image_size;
    if (verbose) {
#       if _DEBUG
            printf("Name: %s\n", std::string(hdr.name, 32).c_str());
            printf("hdr.sx_exe_image_size = 0x%08X\n", hdr.sx_exe_image_size);
            printf("hdr_size = 0x%08X\n", hdr_size);
            printf("end = 0x%08X\n", end);
            printf("isPS2Version = %d\n", (int)isPS2Version);
#       endif
    }

    int PC = (int)file.tellg(), prev_PC = (int)file.tellg();
    while (file.good() && (PC + 2) < end) {
        uint16_t op;
        file.seekg(PC, std::ios::beg);
        file.read(reinterpret_cast<char*>(&op), 2);
        if (!file.good() || file.eof())
            return false;

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
            else if (tmp_datasize != 4)
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
        if (has_arg) {
            if (arg_type == OP_ARG_NUM)
                printf("%f", *reinterpret_cast<float*>(&arg));
            /*bool is_sst_var = opcode == OP_PSH && arg_type == OP_ARG_STR;
            if (is_sst_var) {
                // @todo: fixup with actual data using hdr
            }*/
            else if (arg_type == OP_ARG_LFR || arg_type == OP_ARG_CLV) {
                short arg1 = static_cast<short>(arg & 0xFFFF);
                short arg2 = static_cast<short>((arg >> 16) & 0xFFFF);
                classes_ tmpclass = static_cast<classes_>(arg1);
                printf("%s 0x%04X", std::string(magic_enum::enum_name(tmpclass)).c_str(), arg2);
            }
            else
                printf("0x%-8X", !verbose && arg_type == OP_ARG_PCR ? PC + ((int16_t)arg) : arg);
        }
        printf("\n");
        prev_PC = PC;
    }
    file.close();
    return true;
}

struct decoded_insn_t {
    int offset;            
    opcode_t opcode;       
    opcode_arg_t arg_type; 
    int arg;               
    int size;              
};

bool decode_insn(std::ifstream& file, int offset, const int code_end, decoded_insn_t& out) {
    if (offset + 2 > code_end) return false;

    uint16_t op_raw;
    file.seekg(offset, std::ios::beg);
    file.read(reinterpret_cast<char*>(&op_raw), 2);
    if (!file.good()) return false;

    opcode_t opcode = (opcode_t)(op_raw >> 8);
    opcode_arg_t arg_type = (opcode_arg_t)(op_raw & OP_ARGTYPE_MASK);
    bool has_arg = (op_raw & OP_ARGTYPE_MASK) != 0;
    bool dsize_flag = (op_raw & OP_DSIZE_FLAG) != 0;

    int size = 2 + (dsize_flag ? 2 : 0);
    int arg = 0;
    int tmp_datasize = 0;

    if (has_arg && arg_type != OP_ARG_NULL) {
        tmp_datasize = get_dsize(arg_type);
        file.seekg(offset + size, std::ios::beg);
        file.read(reinterpret_cast<char*>(&arg), tmp_datasize);

        if (tmp_datasize == 4 && arg_type == OP_ARG_NUM)
            arg = ((uint16_t)arg) << 16 | (uint16_t)(arg >> 16);
        else if (tmp_datasize != 4)
            arg = ((int16_t)arg);

        size += tmp_datasize;
    }

    out = {
        .offset = offset,
        .opcode = opcode,
        .arg_type = arg_type,
        .arg = arg,
        .size = size
    };
    return true;
}

bool convert_script(const char* path, const char* out_path)
{
    std::ifstream file(path, std::ios::binary);
    std::ofstream out_f(out_path, std::ios::binary | std::ios::trunc);
    if (!file.good() || !out_f.good())
        return false;

    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();


    script_executable* hdr = reinterpret_cast<script_executable*>(buffer.data());
    int hdr_size = sizeof(script_executable);

    fs::path base = path;
    buffer.erase(buffer.begin() + 0x6C, buffer.begin() + 0x70);
    hdr_size -= 4;

    int end = hdr_size + hdr->sx_exe_image_size;
    int PC = hdr_size;

    std::ifstream file_patch(path, std::ios::binary);
    if (!file_patch.good())
        return false;

    while (PC + 2 < end) {
        decoded_insn_t insn;
        if (!decode_insn(file_patch, PC, end, insn))
            break;

        if (insn.opcode == OP_BSL && insn.arg_type == OP_ARG_LFR) {
            uint16_t arg2 = (insn.arg >> 16) & 0xFFFF;
            auto iter = ps2_pc_global_slc_funcremap.find(arg2);
            if (iter != ps2_pc_global_slc_funcremap.end()) {
                uint16_t new_idx = arg2 + iter->second;
                int new_arg = (insn.arg & 0xFFFF) | (new_idx << 16);
                memcpy(&buffer[(insn.offset - 4) + (insn.size - 4)], &new_arg, 4);
                printf("%x %x %x type: %x \t0x%X\n", insn.opcode , new_arg, arg2, insn.arg_type, insn.offset);
            }
        }

        PC += insn.size;
    }

    file_patch.close();
    out_f.write(buffer.data(), buffer.size());
    out_f.close();
    return true;
}

int main(int argc, char ** argp)
{
    if (strstr(argp[1], "-d")) 
        return disassemble(argp[2], (bool)strstr(argp[1], "v"));
    else if (strstr(argp[1], "-a"))
        return assemble(argp[2], argp[3]);
    else if (strstr(argp[1], "-c"))
        return convert_script(argp[2], argp[3]);
    return 0;
}