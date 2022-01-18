#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>

using u32 = uint32_t;
using u16 = uint16_t;
using u8 = uint8_t;

using s32 = int32_t;
using s16 = int16_t;
using s8 = int8_t;

inline void perror_panic(const char *str)
{
    perror(str);
    exit(1);
}

template<typename T>
inline T handle_read(const u8 *buf, u32 offset)
{
    T v;
    memcpy(&v,&buf[offset],sizeof(v));
    return v;
}

template<typename T>
inline T handle_read(const std::vector<u8> &buf, u32 offset)
{
    return handle_read<T>(buf.data(),offset);
}

template<typename T>
inline void handle_write(u8 *buf,u32 offset, T v)
{
    memcpy(&buf[offset],&v,sizeof(v));
}

// TODO: make this use compilier builtins where avaible
template<typename T>
inline T bswap(T x)
{
	unsigned char *buf = reinterpret_cast<unsigned char *>(&x);
	for(size_t i = 0; i < sizeof(x) / 2; i++)
	{
		std::swap(buf[i],buf[sizeof(x)-i-1]);
	}
	memcpy(&x,buf,sizeof(x));
	return x;
}

inline void zero_mem(u8 *buf, u32 size)
{
    memset(buf,0,size);    
}

inline void fill_byte(u8 *buf, u8 v, u32 size)
{
    for(u32 i = 0; i < size; i++)
    {
        buf[i] = v;
    }
}


#define UNUSED(x) (void)(x)