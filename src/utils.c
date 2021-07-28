#include "utils.h"

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
