#include <elfio/elfio.hpp>
#include <elfio/elfio_dump.hpp>

#include <list>
#include <algorithm>

using namespace std;
using namespace ELFIO;

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

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

void putbe32(u8* p, u32 n)
{
	p[3] = (u8)n;
	p[2] = (u8)(n >> 8);
	p[1] = (u8)(n >> 16);
	p[0] = (u8)(n >> 24);
}

void putbe16(u8* p, u16 n)
{
	p[1] = (u8)n;
	p[0] = (u8)(n >> 8);
}

u32 getbe32(const u8* p)
{
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | (p[3] << 0);
}

u32 getbe16(const u8* p)
{
	return (p[0] << 8) | (p[1] << 0);
}

u32 align(u32 offset, u32 alignment)
{
	u32 mask = ~(u32)(alignment - 1);
	return (offset + (alignment - 1)) & mask;
}

class dino_dll {
public:
	dino_dll(void);
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

	dino_dll_header* header;

	bool dll_create(void);

 	bool header_build(void);
	bool sections_copy(void);

	section* section_by_name(string name);
	const char* section_data(string name);
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
	int gotable_number;
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

section* dino_dll::section_by_name(string name)
{
	for (int i = 0; i < elf.sections.size(); i++)
	{
		section* sec = elf.sections[i];
		if (sec->get_name() == name)
			return sec;
	}

	return NULL;
}

const char* dino_dll::section_data(string name)
{
	section* sec = section_by_name(name);
	if (!sec) return NULL;

	return sec->get_data();
}

bool dino_dll::section_exists(string name)
{
	section* sec = section_by_name(name);
	if (!sec) return false;

	if (sec->get_size() == 0)
		return false;

	return true;
}

size_t dino_dll::section_offset(string name)
{
	if (name == ".text")
		return text_offset - header_size;
	if (name == ".rodata")
		return rodata_offset - header_size;
	if (name == ".data")
		return data_offset - header_size;
	if (name == ".bss")
		return bss_offset - header_size;

	return 0;
}

size_t dino_dll::section_offset(u16 id)
{
	if (id >= elf.sections.size()) return 0;

	section* sec = elf.sections[id];
	if (!sec) return 0;

	return section_offset(sec->get_name());
}

size_t dino_dll::section_size(u16 id)
{
	if (id >= elf.sections.size()) return 0;

	section* sec = elf.sections[id];
	if (!sec) return 0;

	return (size_t) sec->get_size();
}

size_t dino_dll::section_size(string name)
{
	section* sec = section_by_name(name);
	if (!sec) return 0;

	return section_size(sec->get_index());
}

bool dino_dll::gpstub_patch(void)
{
	if (!text) return true;

	section* sec_reltext = section_by_name(".rel.text");
	if (!sec_reltext) return false;

	relocation_section_accessor reltext(elf, sec_reltext);
	symbol_section_accessor symbols(elf, elf.sections[sec_reltext->get_link()]);

	Elf64_Addr offset = 0; Elf_Word symbol = 0, type = 0; Elf_Sxword addend = 0;
	Elf64_Addr value = 0; Elf_Xword size = 0; Elf_Half section = 0;
	unsigned char bind = 0, symbolType = 0, other = 0; string name;

	for (unsigned int i = 0; i < reltext.get_entries_num(); i++)
	{
		reltext.get_entry(i, offset, symbol, type, addend);
		symbols.get_symbol(symbol, name, value, size, bind, symbolType, section, other);

		// replace "addiu $gp, $gp, #imm16" with "ori $gp, $gp, #imm16"
		// nop the "addu $gp, $t9"
		if (name == "_gp_disp" && type == R_MIPS_HI16)
		{
			u8* buffer = text + offset;
			//u32 insn = 0;

			putbe32(buffer + sizeof(u32) * 0, MIPS_LUI_GP_I16);
			putbe32(buffer + sizeof(u32) * 1, MIPS_ORI_GP_I16);
			putbe32(buffer + sizeof(u32) * 2, MIPS_NOP);
			/*insn = getbe32(buffer);
			if (insn == MIPS_ADDIU_GP_I16)
				putbe32(buffer, MIPS_ORI_GP_I16);

			insn = getbe32(buffer + sizeof(u32));
			if (insn == MIPS_ADDU_GP_T9)
				putbe32(buffer + sizeof(u32), MIPS_NOP);*/
		}
	}
	
	return true;
}

int dino_dll::gptable_count(void)
{
	section* sec_reltext = section_by_name(".rel.text");
	if (!sec_reltext) return 0;

	relocation_section_accessor reltext(elf, sec_reltext);
	symbol_section_accessor symbols(elf, elf.sections[sec_reltext->get_link()]);

	Elf64_Addr offset = 0; Elf_Word symbol = 0, type = 0; Elf_Sxword addend = 0;
	Elf64_Addr value = 0; Elf_Xword size = 0; Elf_Half section = 0;
	unsigned char bind = 0, symbolType = 0, other = 0; string name;

	int count = 0;

	for (unsigned int i = 0; i < reltext.get_entries_num(); i++)
	{
		reltext.get_entry(i, offset, symbol, type, addend);
		symbols.get_symbol(symbol, name, value, size, bind, symbolType, section, other);

		if (name == "_gp_disp" && type == R_MIPS_HI16)
			count++;
	}

	return count;
}

size_t dino_dll::gptable_size(void)
{
	return gptable_count() * sizeof(u32);
}

bool dino_dll::gptable_build(void)
{
	section* sec_reltext = section_by_name(".rel.text");
	if (!sec_reltext) return true;

	relocation_section_accessor reltext(elf, sec_reltext);
	symbol_section_accessor symbols(elf, elf.sections[sec_reltext->get_link()]);

	Elf64_Addr offset = 0; Elf_Word symbol = 0, type = 0; Elf_Sxword addend = 0;
	Elf64_Addr value = 0; Elf_Xword size = 0; Elf_Half section = 0;
	unsigned char bind = 0, symbolType = 0, other = 0; string name;

	int pos = 0;

	for (unsigned int i = 0; i < reltext.get_entries_num(); i++)
	{
		reltext.get_entry(i, offset, symbol, type, addend);
		symbols.get_symbol(symbol, name, value, size, bind, symbolType, section, other);

		if (name == "_gp_disp" && type == R_MIPS_HI16)
		{
			u8* buffer = gptable + (pos * sizeof(u32));
			putbe32(buffer, (u32) offset);
			pos++;
		}
	}

	return true;
}

int dino_dll::exports_count(void)
{
	section* sec_relexports = section_by_name(".rel.exports");
	if (!sec_relexports) return 0;

	relocation_section_accessor relexports(elf, sec_relexports);
	int count = (int) relexports.get_entries_num() - 2; // sans constructor/destructor
	return max(count, 0);
}

size_t dino_dll::exports_size(void)
{
	int count = exports_count();
	count += 2; // constructor/destructor
	count += 2; // unused fields

	return count * sizeof(u32);
}

bool dino_dll::exports_build(void)
{
	section* sec_relexports = section_by_name(".rel.exports");
	if (!sec_relexports) return false;

	relocation_section_accessor relexports(elf, sec_relexports);
	symbol_section_accessor symbols(elf, elf.sections[sec_relexports->get_link()]);

	Elf64_Addr offset = 0; Elf_Word symbol = 0, type = 0; Elf_Sxword addend = 0;
	Elf64_Addr value = 0; Elf_Xword size = 0; Elf_Half section = 0;
	unsigned char bind = 0, symbolType = 0, other = 0; string name;

	int pos = 0;
	u8* buffer = NULL;

	for (int j = 0; j < 2; j++)
	{
		int start = 0, count = 0;

		switch (j)
		{
			case 0:
				start = 0;
				count = 2;
				break;

			case 1:
				start = 2;
				count = (int) relexports.get_entries_num() - start;
				break;
		}

		for (int i = start; i < start + count; i++)
		{
			relexports.get_entry(i, offset, symbol, type, addend);
			symbols.get_symbol(symbol, name, value, size, bind, symbolType, section, other);

			buffer = exports + (pos * sizeof(u32));
			putbe32(buffer, (u32) value);
			pos++;
		}

		buffer = exports + (pos * sizeof(u32));
		putbe32(buffer, 0);
		pos++;
	}

	return true;
}

bool dino_dll::exports_patch(void)
{
	if (!exports) return false;
	u8* size = exports + (2 * sizeof(u32));

	// unofficial - this is to avoid having to output a separate file containing just the .bss size
	// if this field is zero, a repacker should use the original DLLS.tab size (DLL was not recompiled)
	// if this field is DINO_NONE, the .bss size is zero and should be set to zero in DLLS.tab
	// otherwise this field contains the true .bss size to set in DLLS.tab
	// though harmless, the repacker should clear this back to zero, its usage is temporary and unofficial
	if (bss_size == 0)
		putbe32(size, DINO_NONE);
	else
		putbe32(size, bss_size);

	return true;
}

int dino_dll::gotable_count(void)
{
	if (gotable_number) return gotable_number;

	section* sec_reltext = section_by_name(".rel.text");
	if (!sec_reltext) return false;

	relocation_section_accessor reltext(elf, sec_reltext);
	symbol_section_accessor symbols(elf, elf.sections[sec_reltext->get_link()]);

	Elf64_Addr offset = 0; Elf_Word symbol = 0, type = 0; Elf_Sxword addend = 0;
	Elf64_Addr value = 0; Elf_Xword size = 0; Elf_Half section = 0;
	unsigned char bind = 0, symbolType = 0, other = 0; string name;

	list<u32> entries;

	int count = 0;
	{
		count++; // .text
		//entries.push_back(section_offset(".text"));
		count++; // .rodata
		//entries.push_back(section_offset(".rodata"));
		count++; // .data
		//entries.push_back(section_offset(".data"));
		count++; // .bss
		//entries.push_back(section_offset(".bss"));
	}

	//printf("%d\n", reltext.get_entries_num());
	for (unsigned int i = 0; i < reltext.get_entries_num(); i++)
	{
		reltext.get_entry(i, offset, symbol, type, addend);
		symbols.get_symbol(symbol, name, value, size, bind, symbolType, section, other);

		switch (type)
		{
			/*case R_MIPS_LO16:
			{
				if (name == "_gp_disp") continue;
				count++;
				break;
			}*/

			case R_MIPS_GOT16:
			case R_MIPS_CALL16:
				//if (find(entries.begin(), entries.end(), gotable_value(section, value)) == entries.end())
				//{
				if (gotable_value(section, value) < 0) continue;
				entries.push_back((u32) gotable_value(section, value));
				//count++;
				//}
				continue;

			default:
				continue;
		}
	}

	entries.sort();
	entries.unique();
	count += entries.size();

	//for (auto const& i : entries) {
	//	//printf("0x%X\n", i);
	//}

	//printf("%d\n", count);
	gotable_number = count;
	return count;
}

size_t dino_dll::gotable_size(void)
{
	return gotable_count() * sizeof(u32);
}

void dino_dll::err_unk_rel(int i, Elf_Word type, const char* section, Elf64_Addr offset, string name, Elf_Word symbol)
{
	cerr << "Unsupported relocation " << i << " of type " << type << " for " << section << " @ 0x" << hex << offset << dec << " for symbol \"" << name << "\" (" << symbol << ")." << endl;
}

void dino_dll::err_unk_sym(const char* section, Elf64_Addr offset, string name, Elf_Word symbol)
{
	cerr << "Undefined symbol \"" << name << "\" (" << symbol << ") in " << section << " @ 0x" << hex << offset << dec << "." << endl;
}

int dino_dll::gotable_section(Elf_Half id)
{
	if (id >= elf.sections.size()) return -1;

	section* sec = elf.sections[id];
	int index = 0;

	if (section_exists(".text"))
	{
		if (sec->get_name() == ".text") return index;
		index++;
	}
	if (section_exists(".rodata"))
	{
		if (sec->get_name() == ".rodata") return index;
		index++;
	}
	if (section_exists(".data"))
	{
		if (sec->get_name() == ".data") return index;
		index++;
	}
	if (section_exists(".bss"))
	{
		if (sec->get_name() == ".bss") return index;
		index++;
	}

	return -1;
}

s64 dino_dll::gotable_value(Elf_Half id, Elf64_Addr value)
{
	switch (id)
	{
		case SHN_UNDEF:
		case SHN_MIPS_SCOMMON:
			return -1;

		case SHN_ABS: break;

		default:
		{
			return (u32) value + section_offset(id);
			break;
		}
	}

	return (u32) value;
}

int dino_dll::gotable_exists(Elf_Half id, Elf64_Addr value)
{
	if (!gotable) return -1;

	u32 entry = (u32) value;
	switch (id)
	{
		case SHN_UNDEF:
		case SHN_MIPS_SCOMMON:
			return -1;

		case SHN_ABS: break;

		default:
		{
			entry = (u32) value + section_offset(id);
			break;
		}
	}

	for (int i = 4; i < gotable_count(); i++) // FIXME
	{
		u32 address = getbe32(gotable + (i * sizeof(u32)));
		if (address == entry) return i;
	}

	return -1;
}

bool dino_dll::gotable_entry(u8* buffer, Elf_Half id, Elf64_Addr value)
{
	switch (id)
	{
		case SHN_UNDEF:
		case SHN_MIPS_SCOMMON:
			return false;

		case SHN_ABS:
		{
			putbe32(buffer, (u32) value);
			break;
		}

		default:
		{
			putbe32(buffer, (u32) value + section_offset(id));
			break;
		}
	}

	return true;
}

bool dino_dll::gotable_build(void)
{
	memset(gotable, 0xFF, gotable_size());

	section* sec_reltext = section_by_name(".rel.text");
	if (!sec_reltext) return true;

	relocation_section_accessor reltext(elf, sec_reltext);
	symbol_section_accessor symbols(elf, elf.sections[sec_reltext->get_link()]);

	Elf64_Addr offset = 0; Elf_Word symbol = 0, type = 0; Elf_Sxword addend = 0;
	Elf64_Addr value = 0; Elf_Xword size = 0; Elf_Half section = 0;
	unsigned char bind = 0, symbolType = 0, other = 0; string name;

	bool ret = true;

	u8* buffer = NULL;
	int pos = 0;
	u32 insn = 0;

	{
		buffer = gotable + (pos * sizeof(u32));
		putbe32(buffer, section_offset(".text"));
		pos++;

		buffer = gotable + (pos * sizeof(u32));
		putbe32(buffer, section_offset(".rodata"));
		pos++;

		buffer = gotable + (pos * sizeof(u32));
		putbe32(buffer, section_offset(".data"));
		pos++;

		buffer = gotable + (pos * sizeof(u32));
		putbe32(buffer, section_offset(".bss"));
		pos++;
	}

	list<u32> entries;

	for (unsigned int i = 0; i < reltext.get_entries_num(); i++)
	{
		reltext.get_entry(i, offset, symbol, type, addend);
		symbols.get_symbol(symbol, name, value, size, bind, symbolType, section, other);

		buffer = gotable + (pos * sizeof(u32));

		switch (type)
		{
			case R_MIPS_LO16:
			{
				//if (name == "_gp_disp") continue;

				/*if (gotable_exists(section, value) >= 0)
				{
					gotable_exists(section, value);
					pos--;
				}
				else if (!gotable_entry(buffer, section, value))
				{
					err_unk_sym(".text", offset, name, symbol);
					ret = false;
					continue;
				}*/

				continue;
				//break;
			}

			case R_MIPS_GOT16:
			case R_MIPS_CALL16:
			{
				int index = pos;

				/*if (gotable_section(section) >= 0)
				{
					index = gotable_section(section);
					pos--;

					insn = getbe32(text + offset + sizeof(u32));
					insn |= value;
					putbe32(text + offset + sizeof(u32), insn);
				}
				else*/
				//if (value == 0) printf("hi\n");
				if (gotable_exists(section, value) >= 0)
				{
					index = gotable_exists(section, value);
					pos--;
				}
				else
				{
					if (!gotable_entry(buffer, section, value))
					{
						err_unk_sym(".text", offset, name, symbol);
						ret = false;
						continue;
					}
					else
						entries.push_back(getbe32(buffer));
				}

				insn = getbe32(text + offset);
				insn |= index * sizeof(u32);
				putbe32(text + offset, insn);

				break;
			}

			case R_MIPS_HI16:
			{
				if (name == "_gp_disp") continue;

				err_unk_rel(i, type, ".text", offset, name, symbol);
				ret = false;
				continue;
			}

			// cool story bro
			case R_MIPS_JALR:
				continue;

			default:
			{
				err_unk_rel(i, type, ".text", offset, name, symbol);
				ret = false;
				continue;
			}
		}

		pos++;
	}

	entries.sort();

	//for (auto const& i : entries) {
		//printf("0x%X\n", i);
	//}

	//printf("%d\n", pos);
	return ret;
}

bool dino_dll::rotable_build(void)
{
	section* sec_relrodata = section_by_name(".rel.rodata");
	if (!sec_relrodata) return true;

	relocation_section_accessor relrodata(elf, sec_relrodata);
	symbol_section_accessor symbols(elf, elf.sections[sec_relrodata->get_link()]);

	Elf64_Addr offset = 0; Elf_Word symbol = 0, type = 0; Elf_Sxword addend = 0;
	Elf64_Addr value = 0; Elf_Xword size = 0; Elf_Half section = 0;
	unsigned char bind = 0, symbolType = 0, other = 0; string name;

	bool ret = true;

	for (unsigned int i = 0; i < relrodata.get_entries_num(); i++)
	{
		relrodata.get_entry(i, offset, symbol, type, addend);
		symbols.get_symbol(symbol, name, value, size, bind, symbolType, section, other);

		switch (type)
		{
			case R_MIPS_GPREL32:
			{
				value = getbe32(rodata + offset);

				if (value < gp_offset)
					value = -((s32) gp_offset - (s32) (value + section_offset(section)));
				else
					value = (value + section_offset(section)) - gp_offset;

				putbe32(rodata + offset, (u32) value);
				break;
			}

			default:
			{
				err_unk_rel(i, type, ".rodata", offset, name, symbol);
				ret = false;
				continue;
			}
		}
	}

	return ret;
}

int dino_dll::datable_count(void)
{
	section* sec_reldata = section_by_name(".rel.data");
	if (!sec_reldata) return 0;

	return (int)(sec_reldata->get_size() / sec_reldata->get_entry_size());
}

size_t dino_dll::datable_size(void)
{
	return datable_count() * sizeof(u32);
}

bool dino_dll::datable_build(void)
{
	section* sec_reldata = section_by_name(".rel.data");
	if (!sec_reldata) return true;

	relocation_section_accessor reldata(elf, sec_reldata);
	symbol_section_accessor symbols(elf, elf.sections[sec_reldata->get_link()]);

	Elf64_Addr offset = 0; Elf_Word symbol = 0, type = 0; Elf_Sxword addend = 0;
	Elf64_Addr value = 0; Elf_Xword size = 0; Elf_Half section = 0;
	unsigned char bind = 0, symbolType = 0, other = 0; string name;

	bool ret = true;

	u8* buffer = NULL;
	int pos = 0;

	for (unsigned int i = 0; i < reldata.get_entries_num(); i++)
	{
		reldata.get_entry(i, offset, symbol, type, addend);
		symbols.get_symbol(symbol, name, value, size, bind, symbolType, section, other);

		switch (type)
		{
			case R_MIPS_32:
			{
				value += section_offset(section);
				value -= section_offset(".data"); // %$?!
				value += getbe32(data + offset);
				putbe32(data + offset, (u32) value);
				break;
			}

			default:
			{
				err_unk_rel(i, type, ".data", offset, name, symbol);
				ret = false;
				continue;
			}
		}

		buffer = datable + (pos * sizeof(u32));
		putbe32(buffer, (u32) offset);

		pos++;
	}

	return ret;
}

size_t dino_dll::table_size(void)
{
	size_t size = DINO_TABMIN;
	size += gotable_size();
	size += gptable_size();
	size += datable_size();

	// don't insert a placeholder table if the rodata section doesn't exist
	if (size == DINO_TABMIN && section_by_name(".rodata") == 0)
		return 0;

	return size;
}

bool dino_dll::table_build(void)
{
	bool ret = false;
	if (!table) return true;

	gotable = table;
	u8* gotend = gotable + gotable_size();
	putbe32(gotend, DINO_GOTEND);

	gptable = gotable + gotable_size() + sizeof(u32);
	u8* gptend = gptable + gptable_size();
	putbe32(gptend, DINO_GPTEND);

	datable = gptable + gptable_size() + sizeof(u32);
	u8* datend = datable + datable_size();
	putbe32(datend, DINO_DATEND);

	ret |= !gotable_build();
	ret |= !gptable_build();
	ret |= !datable_build();
	ret |= !rotable_build();

	return !ret;
}

dino_dll::dino_dll(void)
{

}

bool dino_dll::header_build(void)
{
	putbe32(header->header_size, header_size);
	putbe32(header->data_offset, data ? data_offset : DINO_NONE);
	putbe32(header->rodata_offset, table ? table_offset : DINO_NONE);
	putbe16(header->export_count, exports_count());
	putbe16(header->padding, 0);

	return true;
}

bool dino_dll::sections_copy(void)
{
	if (text) memcpy(text, section_data(".text"), section_size(".text"));
	if (rodata) memcpy(rodata, section_data(".rodata"), section_size(".rodata"));
	if (data) memcpy(data, section_data(".data"), section_size(".data"));

	return true;
}

bool dino_dll::dll_create(void)
{
	text_offset = 0;
	rodata_offset = 0;
	data_offset = 0;
	bss_offset = 0;

	if (section_by_name(".text"))
		text_offset = (size_t) section_by_name(".text")->get_offset();

	if (section_by_name(".rodata"))
		rodata_offset = (size_t) section_by_name(".rodata")->get_offset();

	if (section_by_name(".data"))
		data_offset = (size_t) section_by_name(".data")->get_offset();

	if (section_by_name(".bss"))
		bss_offset = (size_t) section_by_name(".bss")->get_offset();

	gotable_number = 0;

	dll_size = sizeof(dino_dll_header);

	exports_offset = dll_size;
	dll_size += exports_size();

	header_size = dll_size;

	text_offset = dll_size;
	dll_size += align(section_size(".text"), 16);

	table_offset = dll_size;
	dll_size += table_size();

	rodata_offset = dll_size;
	dll_size += align(section_size(".rodata"), 16);

	data_offset = dll_size;
	dll_size += align(section_size(".data"), 16);

	bss_offset = dll_size;
	dll_size = align(dll_size, 16);

	bss_size = 0; // jfc.
	if (section_size(".bss") >= (dll_size - bss_offset))
		bss_size = section_size(".bss") - (dll_size - bss_offset);

	dll = new u8[dll_size];
	memset(dll, 0, dll_size);

	header = (dino_dll_header*) dll;
	exports = dll + exports_offset;

	text = dll + text_offset;
	if (!section_exists(".text")) text = NULL;

	rodata = dll + rodata_offset;
	if (!section_exists(".rodata")) rodata = NULL;

	data = dll + data_offset;
	if (!section_exists(".data")) data = NULL;

	table = dll + table_offset;
	if (table_size() == 0) table = NULL;

	if (table)
		gp_offset = table_offset - header_size;
	else if (rodata)
		gp_offset = rodata_offset - header_size;

	return true;
}

int dino_dll::build(string elf_file, string dll_file)
{
	if (!elf.load(elf_file))
	{
		cerr << elf_file << " is not a valid ELF file." << endl;
		return 1;
	}

	bool ret = true;

	if (ret) ret = dll_create();

	if (ret) ret = header_build();
	if (ret) ret = sections_copy();

	if (ret) ret = exports_build();
	if (ret) ret = gpstub_patch();
	if (ret) ret = table_build();

	if (ret) ret = exports_patch();

	if (!ret)
	{
		delete[] dll;
		return 1;
	}

	fstream out;
	out.open(dll_file, ios::out | ios::binary);
	out.write((char*) dll, dll_size);
	out.close();

	delete[] dll;

	/*dump::header(cout, elf);
	dump::section_headers(cout, elf);
	dump::segment_headers(cout, elf);
	dump::symbol_tables(cout, elf);
	dump::notes(cout, elf);
	dump::modinfo(cout, elf);
	dump::dynamic_tags(cout, elf);
	dump::section_datas(cout, elf);
	dump::segment_datas(cout, elf);*/

	return 0;
}

int main(int argc, const char* argv[])
{
	if (argc < 3)
	{
		cerr << "Usage: " << argv[0] << " <input-elf> <output-dll>" << endl;
		return 1;
	}

	dino_dll dll;
	return dll.build(argv[1], argv[2]);
}