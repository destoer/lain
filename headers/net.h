#pragma once
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <net/ethernet.h> 
#include <fcntl.h>
#include <unistd.h>


static constexpr u32 MAX_PACKET_SIZE = 65536;

static constexpr u16 PROTO_ARP = 0x0806;
static constexpr u32 ETH_HDR_SIZE = 14;
static constexpr u32 ARP_HDR_SIZE = 28;
static constexpr u32 MAC_SIZE = 6;
static constexpr u32 IP_SIZE = 4;

static constexpr u16 HTYPE_ETH = 0x0001;
static constexpr u16 PTYPE_IP = 0x0800;
static constexpr u16 ARP_REQ = 0x0001;
static constexpr u16 ARP_REPLY = 0x0002;


static constexpr u16 IP_HDR_SIZE = 20;

static constexpr u8 DSCP_DF = 0;

struct EthHdr
{
    u8 dmac[MAC_SIZE];
    u8 smac[MAC_SIZE];
    u16 type;
};

template<typename T>
inline T read_host(const u8 *buf, u32 offset)
{
    T v;
    memcpy(&v,&buf[offset],sizeof(v));
    return bswap(v);
}

template<typename T>
inline T read_host(const std::vector<u8> &buf, u32 offset)
{
    return read_host<T>(buf.data(),offset);
}

template<typename T>
inline void write_network(u8 *buf,u32 offset, T v)
{
    v = bswap(v);
    memcpy(&buf[offset],&v,sizeof(v));
}

// TODO: generalise this for TCP/UDP
inline u16 csum(const u8 *buf)
{
    u32 v = 0;

    for(u32 i = 0; i < IP_HDR_SIZE; i += 2)
    {
        // ignore the csum allready there
        if(i == 10)
        {
            continue;
        }

        v += read_host<u16>(buf,i);
    }

    if(v >= 0xffff)
    {
        v = u16(v);
        v += 1;
    }

    v = ~v;

    return v;
}