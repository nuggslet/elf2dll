#pragma once

#include <elfio/elfio.hpp>
#include "types.h"

#define SHN_MIPS_SCOMMON  (0xFF03)

#define R_MIPS_32         (2)
#define R_MIPS_HI16       (5)
#define R_MIPS_LO16       (6)

#define R_MIPS_GOT16      (9)

#define R_MIPS_CALL16     (11)
#define R_MIPS_GPREL32    (12)

#define R_MIPS_JALR       (37)

#define MIPS_NOP          (0x00000000)
#define MIPS_ADDU_GP_T9   (0x0399E021)
#define MIPS_ADDIU_GP_I16 (0x279C0000)
#define MIPS_LUI_GP_I16   (0x3C1C0000)
#define MIPS_ORI_GP_I16   (0x379C0000)

#define MIPS_OPMASK       (0xFC000000)
#define MIPS_ARGMASK      (0x03FFFFFF)
#define MIPS_DSTMASK      (0x00FFFFFF)

#define MIPS_RS_GP        (0x03000000)
#define MIPS_ADDIU        (0x24000000)
#define MIPS_LW           (0x8C000000)

#define DINO_GOTEND       (0xFFFFFFFE)
#define DINO_GPTEND       (0xFFFFFFFD)
#define DINO_DATEND       (0xFFFFFFFF)

#define DINO_TABMIN       (3 * sizeof(u32))
#define DINO_NONE         (0xFFFFFFFF)

typedef struct {
	u8 header_size[4];
	u8 data_offset[4];
	u8 rodata_offset[4];
	u8 export_count[2];
	u8 padding[2];
} dino_dll_header;

using namespace std;
using namespace ELFIO;

class dino_dll {
public:
	int build(string elf_file, string dll_file);
private:
	elfio elf;

	size_t dll_size;
	size_t header_size;
	size_t text_offset;
	size_t rodata_offset;
	size_t data_offset;
	size_t bss_offset;
	size_t bss_size;

	size_t exports_offset;
	size_t table_offset;
	size_t gp_offset;

	u8* dll;
	u8* text;
	u8* rodata;
	u8* data;

	u8* exports;
	u8* table;
	u8* gotable;
	u8* gptable;
	u8* datable;

	int gotable_number;

	dino_dll_header* header;

	bool create(void);
	void elf_dump(void);

	bool header_build(void);
	bool sections_copy(void);

	section* section_by_name(string name);
	const char* section_data(string name);
	int section_index(string name);
	bool section_exists(string name);

	size_t section_offset(string name);
	size_t section_offset(u16 id);

	size_t section_size(string name);
	size_t section_size(u16 id);

	bool table_build(void);
	size_t table_size(void);

	bool gpstub_patch(void);
	bool exports_patch(void);

	bool rotable_build(void);
	bool gotable_entry(u8* buffer, Elf_Half id, Elf64_Addr value);
	int gotable_section(Elf_Half id);
	s64 gotable_value(Elf_Half id, Elf64_Addr value);
	int gotable_exists(Elf_Half id, Elf64_Addr value);

	bool exports_build(void);
	int exports_count(void);
	size_t exports_size(void);

	bool gotable_build(void);
	int gotable_count(void);
	size_t gotable_size(void);

	bool gptable_build(void);
	int gptable_count(void);
	size_t gptable_size(void);

	bool datable_build(void);
	int datable_count(void);
	size_t datable_size(void);

	void err_unk_sym(const char* section, Elf64_Addr offset, string name, Elf_Word symbol);
	void err_unk_rel(int i, Elf_Word type, const char* section, Elf64_Addr offset, string name, Elf_Word symbol);
};
