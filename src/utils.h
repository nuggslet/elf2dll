#pragma once

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

void putbe32(u8* p, u32 n);
void putbe16(u8* p, u16 n);
u32 getbe32(const u8* p);
u32 getbe16(const u8* p);

u32 align(u32 offset, u32 alignment);

#ifdef __cplusplus
}
#endif
