#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "bm_iface.h"

int main(int argc,char **argv)
{
    int fd = open("/dev/bm0",O_WRONLY);
    if(fd) {
        struct bm_iface bm_iface;
        int rc;
        printf("device opened\n");
        sprintf(bm_iface.my_ip_addr,"10.0.0.2");
        sprintf(bm_iface.peer_ip_addr,"0.0.0.0");
        bm_iface.port = 7777;
        if((rc = write(fd,&bm_iface,sizeof(struct bm_iface))) != sizeof(struct bm_iface)) {
             printf("write returned %d\n",rc);
        }
        while(1);
        close(fd);
    }
    else
        printf("cannot open device\n");
    return 0;
}
