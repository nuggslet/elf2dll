// Dinosaur Planet DLL converter
// by nuggs#1832 / nuggslet
// saved from ruin by Zest

#include "elf2dll.hpp"

#include <list>
#include <algorithm>

#include "utils.h"

#include <elfio/elfio_dump.hpp>

using namespace std;
using namespace ELFIO;

//#define DINO_DEBUG

int dino_dll::build(string elf_file, string dll_file)
{
	if (!elf.load(elf_file))
	{
		cerr << elf_file << " is not a valid ELF file." << endl;
		return 1;
	}

	bool ret = true;

	if (ret) ret = create();

	if (ret) ret = header_build();
	if (ret) ret = sections_copy();

	if (ret) ret = exports_build();
	if (ret) ret = gpstub_patch();
	if (ret) ret = table_build();

#ifdef DINO_BSSHACK
	if (ret) ret = exports_patch();
#endif

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

#ifdef DINO_DEBUG
	elf_dump();
#endif

	return 0;
}

bool dino_dll::create(void)
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

			putbe32(buffer + sizeof(u32) * 0, MIPS_LUI_GP_I16);
			putbe32(buffer + sizeof(u32) * 1, MIPS_ORI_GP_I16);
			putbe32(buffer + sizeof(u32) * 2, MIPS_NOP);
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
		count++; // .rodata
		count++; // .data
		count++; // .bss
	}

	for (unsigned int i = 0; i < reltext.get_entries_num(); i++)
	{
		reltext.get_entry(i, offset, symbol, type, addend);
		symbols.get_symbol(symbol, name, value, size, bind, symbolType, section, other);

		switch (type)
		{
			case R_MIPS_GOT16:
			case R_MIPS_CALL16:
				if (gotable_value(section, value) < 0) continue;
				entries.push_back((u32) gotable_value(section, value));
				continue;

			default:
				continue;
		}
	}

	entries.sort();
	entries.unique();
	count += entries.size() - 1;

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

	if (entry == section_offset(".text") && id == section_index(".text"))
		return 0;
	if (entry == section_offset(".rodata") && id == section_index(".rodata"))
		return 1;
	if (entry == section_offset(".data") && id == section_index(".data"))
		return 2;
	if (entry == section_offset(".bss") && id == section_index(".bss"))
		return 3;

	for (int i = 0; i < gotable_count(); i++)
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
				continue;

			case R_MIPS_GOT16:
			case R_MIPS_CALL16:
			{
				int index = pos;

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

void dino_dll::elf_dump(void)
{
	dump::header(cout, elf);
	dump::section_headers(cout, elf);
	dump::segment_headers(cout, elf);
	dump::symbol_tables(cout, elf);
	dump::notes(cout, elf);
	dump::modinfo(cout, elf);
	dump::dynamic_tags(cout, elf);
	dump::section_datas(cout, elf);
	dump::segment_datas(cout, elf);
}

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

int dino_dll::section_index(string name)
{
	section* sec = section_by_name(name);
	if (!sec) return -1;

	return sec->get_index();
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
