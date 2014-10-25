#ifndef __BM_IFACE__H_
#define __BM_IFACE__H_

struct bm_iface
{
    char my_ip_addr[20];
    unsigned short port;
    char peer_ip_addr[20];
}__attribute__( ( packed ) );

#endif
