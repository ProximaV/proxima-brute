// Copyright 2010       Sven Peter <svenpeter@gmail.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#ifndef TYPES_H__
#define TYPES_H__

#include "stdint.h"

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;


struct elf_phdr {
        u32 p_type;
        u64 p_off;
        u64 p_vaddr;
        u64 p_paddr;
        u64 p_filesz;
        u64 p_memsz;
        u32 p_flags;
        u64 p_align;

        void *ptr;
};

struct elf_shdr {
        u32 sh_name;
        u32 sh_type;
        u32 sh_flags;
        u64 sh_addr;
        u64 sh_offset;
        u32 sh_size;
        u32 sh_link;
        u32 sh_info;
        u32 sh_addralign;
        u32 sh_entsize;
};

#define ET_NONE         0
#define ET_REL          1
#define ET_EXEC         2
#define ET_DYN          3
#define ET_CORE         4
#define ET_LOOS         0xfe00
#define ET_HIOS         0xfeff
#define ET_LOPROC       0xff00
#define ET_HIPROC       0xffff
struct elf_hdr {
        char e_ident[16];
        u16 e_type;
        u16 e_machine;
        u32 e_version;
        u64 e_entry;
        u64 e_phoff;
        u64 e_shoff;
        u32 e_flags;
        u16 e_ehsize;
        u16 e_phentsize;
        u16 e_phnum;
        u16 e_shentsize;
        u16 e_shnum;
        u16 e_shtrndx;
};

typedef struct {
 uint64_t data_offset;
 uint64_t data_size;
 uint32_t type; // 1 = shdr, 2 == phdr, 3 == unknown
 uint32_t program_idx;
 uint32_t hashed; //2=yes
 uint32_t sha1_idx;
 uint32_t encrypted; // 3=yes; 1=no
 uint32_t key_idx;
 uint32_t iv_idx;
 uint32_t compressed; // 2=yes; 1=no
} METADATA_SECTION_HEADER;





static  u8 be8(u8 *p)
{
        return *p;
}

static  u8 le8(u8 *p)
{
        return *p;
}

static  u16 be16(u8 *p)
{
        u16 a;

        a  = p[0] << 8;
        a |= p[1];

        return a;
}
static  u16 le16(u8 *p)
{
        u16 a;

        a  = p[1] << 8;
        a |= p[0];

        return a;
}

static  u32 be32(u8 *p)
{
        u32 a;

        a  = p[0] << 24;
        a |= p[1] << 16;
        a |= p[2] <<  8;
        a |= p[3] <<  0;

        return a;
}
static  u32 le32(u8 *p)
{
        u32 a;

        a  = p[3] << 24;
        a |= p[2] << 16;
        a |= p[1] <<  8;
        a |= p[0] <<  0;

        return a;
}

static  u64 be64(u8 *p)
{
        u32 a, b;

        a = be32(p);
        b = be32(p + 4);

        return ((u64)a<<32) | b;
}
static  u64 le64(u8 *p)
{
        u32 a, b;

        b = le32(p);
        a = le32(p + 4);

        return ((u64)a<<32) | b;
}

static  void wbe16(u8 *p, u16 v)
{
        p[0] = (u8)(v >>  8);
        p[1] = (u8)v;
}
static  void wle16(u8 *p, u16 v)
{
        p[1] = (u8)(v >>  8);
        p[0] = (u8)v;
}

static  void wbe32(u8 *p, u32 v)
{
        p[0] = v >> 24;
        p[1] = v >> 16;
        p[2] = v >>  8;
        p[3] = v;
}
static  void wle32(u8 *p, u32 v)
{
        p[3] = v >> 24;
        p[2] = v >> 16;
        p[1] = v >>  8;
        p[0] = v;
}
static  void wbe64(u8 *p, u64 v)
{
        wbe32(p + 4, (u32)v);
        v >>= 32;
        wbe32(p, (u32)v);
}
static  void wle64(u8 *p, u64 v)
{
        wbe32(p , (u32)v);
        v >>= 32;
        wbe32(p+4, (u32)v);
}

#endif