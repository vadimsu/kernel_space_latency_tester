#include <linux/module.h>	/* Needed by all modules */
#include <linux/moduleparam.h>
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <net/net_namespace.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/inet.h>
#include <net/ip.h>
#include <net/inet_hashtables.h>
#include <net/inet_common.h>
#include <net/tcp.h>
#include <linux/workqueue.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <asm/msr.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include "bm_iface.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vadim Suraev");
#define MODULE_NAME "ksocket"
static void bm_stats_fn(struct work_struct *work);
static void client_connection_opener_fn(struct work_struct *work);
static void server_connection_opener_fn(struct work_struct *work);
static void server_connection_accepter_fn(struct work_struct *work);
static void client_connection_closer_fn(struct work_struct *work);
static void server_connection_closer_fn(struct work_struct *work);
static void (*sock_def_readable)(struct sock *sk);
static void (*sock_def_write_space)(struct sock *sk);
static void reader_fn(struct work_struct *work);
static void writer_fn(struct work_struct *work);
static void (*sock_def_wakeup)(struct sock *sk);

static struct class *bm_class = NULL;

struct sock_state
{
    struct socket *socket;
    void *data;
};

struct sock_work
{
    struct work_struct read_work;
    struct work_struct write_work;
    struct sock_state sock_state;
}__attribute__( ( packed ) );
struct sock_work listener_work;
struct sock_work accepted_work;
struct sock_work client_sock_work;

struct bm_device {
   struct module           *owner;
   struct device           *dev;
   int                     minor;
//   atomic_t                event;
//   struct fasync_struct    *async_queue;
//   wait_queue_head_t       wait;
//   struct uio_info         *info;
   struct bm_iface bm_iface;
   struct kobject          *map_dir;
   struct kobject          *portio_dir;
};
struct bm_device bm_dev;

DECLARE_DELAYED_WORK(bm_stats,bm_stats_fn);
int serverMode = 0;
int rr_count = 0;

static unsigned int inet_addr(char *str)
{
    int a,b,c,d;
    char arr[4];
    sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d);
    arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
    return *(unsigned int*)arr;
}
static void open_client_socket(void);
static void open_server_socket(void);
static void close_client_socket(void);
static void close_server_socket(void);

static inline void format_ts_msg(unsigned char *addr,u64 ts)
{
    addr[0] = 0xF7;
    addr[1] = 0x7F;
    addr[2] = 0xA5;
    addr[3] = 0x5A;
    memcpy(&addr[4],&ts,sizeof(ts));
    addr[4+sizeof(u64)] = 0x5A;
    addr[5+sizeof(u64)] = 0xA5;
    addr[6+sizeof(u64)] = 0x7F;
    addr[7+sizeof(u64)] = 0xF7;
}

static inline is_msg_valid(unsigned char *addr)
{
    return ((addr[0] == 0xF7)&&(addr[1] == 0x7F)&&(addr[2] == 0xA5)&&(addr[3] == 0x5A)&& \
            (addr[4+sizeof(u64)] == 0x5A)&&(addr[5+sizeof(u64)] == 0xA5)&&(addr[6+sizeof(u64)] == 0x7F)&&(addr[7+sizeof(u64)] == 0xF7));
}

static inline u64 get_ts_from_msg(unsigned char *addr)
{
    u64 ts;
    memcpy(&ts,&addr[4],sizeof(ts));
    return ts;
}

static void reader_fn(struct work_struct *work)
{
    struct msghdr msg;
    struct kvec vec;
    struct page *p;
    int rc;
    u64 tsc_now,tsc_sent;
    struct sock_work *sock_work = container_of(work,struct sock_work,read_work);
//    printk(KERN_INFO "read work\n");
    p = alloc_page(GFP_KERNEL);
    if(!p) {
        printk(KERN_INFO "Cannot allocate page\n");
        return;
    }
    vec.iov_base = page_address(p);
    vec.iov_len = 4096;
    memset(&msg,0,sizeof(msg));
    rc = kernel_recvmsg(sock_work->sock_state.socket, &msg,&vec, 1, 4096, O_NONBLOCK);
  //  printk(KERN_INFO "received %d\n",rc);
    
    if(rc < (7+sizeof(u64))) {
        printk(KERN_INFO " short msg %s %d\n",__FILE__,__LINE__);
        return;
    }
    if(!is_msg_valid(/*vec.iov_base*/page_address(p))) {
        unsigned char *pp = (unsigned char *)vec.iov_base;
        if(page_address(p) != pp)
           printk(KERN_INFO "addr mismatch\n");
        printk(KERN_INFO " malformatted message %s %d %x %x %x %x %x %x %x %x\n",__FILE__,__LINE__,p[0],p[1],p[2],p[3],p[4+sizeof(u64)],p[5+sizeof(u64)],p[6+sizeof(u64)],p[7+sizeof(u64)]);
        return;
    }
    tsc_sent = get_ts_from_msg(/*vec.iov_base*/page_address(p));
    if(serverMode) {
        format_ts_msg(/*vec.iov_base*/page_address(p),tsc_sent);
        rc = kernel_sendpage(sock_work->sock_state.socket, p, 0/*offset*/,1448 /*size */, O_NONBLOCK);
//        printk(KERN_INFO " echoed %s %d %d\n",__FILE__,__LINE__,rc);
    }
    else {
       rdtscll(tsc_now);
       printk(KERN_INFO "received %u\n",tsc_now - tsc_sent);
       if(rr_count == 100) {
        return;
       }
       rdtscll(tsc_now);
       format_ts_msg(/*vec.iov_base*/page_address(p),tsc_now);
       rc = kernel_sendpage(sock_work->sock_state.socket, p, 0/*offset*/,1448 /*size */, O_NONBLOCK);
    }
    //free_page(p);
}
static void writer_fn(struct work_struct *work)
{
    struct sock_work *sock_work = container_of(work,struct sock_work,write_work);
    struct page *p;
    int rc;
    u64 tsc_now;

    //printk(KERN_INFO "client write work\n");
    if(serverMode) {
        return;
    }
    if(rr_count > 0) {
        return;
    }
    p = alloc_page(GFP_KERNEL);
    if(!p) {
        printk(KERN_INFO "Cannot allocate page\n");
        return;
    }
    rdtscll(tsc_now);
    format_ts_msg(page_address(p),tsc_now);
    rc = kernel_sendpage(sock_work->sock_state.socket, p, 0/*offset*/,1448 /*size */, O_NONBLOCK);
    rr_count++;
    //printk(KERN_INFO " returned %d\n",rc);
}
static void app_glue_sock_write_space(struct sock *sk)
{
    struct sock_work *sock_work;
//    printk(KERN_INFO " WRITABLE %s %d\n",__FILE__,__LINE__);

    if((sk->sk_state != TCP_ESTABLISHED)&&(sk->sk_socket->type == SOCK_STREAM)) {
        return;
    }
    if(!sk->sk_socket) {
        return;
    }
    if(sk->sk_user_data == &listener_work) {
        return;
    }
    sock_work = sk->sk_user_data;

    if(work_pending(&sock_work->write_work))
        return;
    INIT_WORK(&sock_work->write_work,writer_fn);
    schedule_work(&sock_work->write_work);
}

static void app_glue_sock_readable(struct sock *sk, int len)
{
    struct sock_work *sock_work;
//    printk(KERN_INFO "READABLE %s %d\n",__FILE__,__LINE__);

    if((sk->sk_state != TCP_ESTABLISHED)&&(sk->sk_socket->type == SOCK_STREAM)) {
        return;
    }
    if(!sk->sk_socket) {
        return;
    }
    if(sk->sk_user_data == &listener_work) {
        return;
    }
    sock_work = sk->sk_user_data;
    
    if(work_pending(&sock_work->read_work))
        return;
    INIT_WORK(&sock_work->read_work,reader_fn);
    schedule_work(&sock_work->read_work);
}
static void server_connection_accepter_fn(struct work_struct *work)
{
    struct socket *newsock = NULL;

    printk(KERN_INFO "%s %d\n",__FILE__,__LINE__);

    if(kernel_accept(listener_work.sock_state.socket, &newsock, O_NONBLOCK) != 0) {
        printk(KERN_INFO "%s %d\n",__FILE__,__LINE__);
        return;
    }
    if(newsock) {
        newsock->sk->sk_user_data = &accepted_work;
        accepted_work.sock_state.socket = newsock;
        sock_reset_flag(newsock->sk,SOCK_USE_WRITE_QUEUE);
        sock_def_readable = newsock->sk->sk_data_ready;
        sock_def_write_space = newsock->sk->sk_write_space;
        newsock->sk->sk_data_ready = app_glue_sock_readable;
        newsock->sk->sk_write_space = app_glue_sock_write_space;
        INIT_WORK(&accepted_work.read_work,reader_fn);
        schedule_work(&accepted_work.read_work);
        printk(KERN_INFO "%s %d\n",__FILE__,__LINE__);
    }
    printk(KERN_INFO "%s %d\n",__FILE__,__LINE__);
}
static void app_glue_sock_wakeup(struct sock *sk, int len)
{ 
    struct sock *sock;
    struct tcp_sock *tp;
    tp = tcp_sk(sk);
    printk(KERN_INFO "%s %d %x %x %x %x %d\n",
__FILE__,__LINE__,
sk->__sk_common.skc_daddr,sk->__sk_common.skc_dport,sk->__sk_common.skc_rcv_saddr,tp->inet_conn.icsk_inet.inet_sport,sk->sk_state);
    sock = inet_lookup_listener(&init_net,&tcp_hashinfo,sk->__sk_common.skc_daddr,sk->__sk_common.skc_dport,sk->__sk_common.skc_rcv_saddr,
               tp->inet_conn.icsk_inet.inet_sport,sk->sk_bound_dev_if);
    if(sock) {
        INIT_WORK(&listener_work.read_work,server_connection_accepter_fn);
        schedule_work(&listener_work.read_work);
    }
}
static void bm_stats_fn(struct work_struct *work)
{
    printk(KERN_INFO "%s %d\n",__FILE__,__LINE__);
    schedule_delayed_work_on(0,&bm_stats,1000);
}
static void open_client_socket()
{
    struct sockaddr_in addr;
    if(sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &client_sock_work.sock_state.socket)) {
        printk(KERN_INFO "cannot create socket\n");
        return;
    }
    else
        printk(KERN_INFO "socket created %s %d\n",bm_dev.bm_iface.peer_ip_addr,bm_dev.bm_iface.port);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(bm_dev.bm_iface.port);
    addr.sin_addr.s_addr = inet_addr(bm_dev.bm_iface.peer_ip_addr);
    kernel_connect(client_sock_work.sock_state.socket, (struct sockaddr *)&addr, sizeof(addr),O_NONBLOCK);
    sock_reset_flag(client_sock_work.sock_state.socket->sk,SOCK_USE_WRITE_QUEUE);
    client_sock_work.sock_state.socket->sk->sk_data_ready = app_glue_sock_readable;
    client_sock_work.sock_state.socket->sk->sk_write_space = app_glue_sock_write_space;
    client_sock_work.sock_state.socket->sk->sk_user_data = &client_sock_work;
}
static void open_server_socket()
{
     struct sockaddr_in addr;
     if(sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &listener_work.sock_state.socket)) {
        printk(KERN_INFO "cannot create socket\n");
        return;
    }
    else
        printk(KERN_INFO "server socket created %s %d\n",bm_dev.bm_iface.my_ip_addr,bm_dev.bm_iface.port);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(bm_dev.bm_iface.port);
    addr.sin_addr.s_addr = inet_addr(bm_dev.bm_iface.my_ip_addr);
    if(kernel_bind(listener_work.sock_state.socket, (struct sockaddr *)&addr, sizeof(addr)))
        printk(KERN_INFO "cannot bind\n");
    else {
        if(listener_work.sock_state.socket->sk) {
            sock_def_wakeup = listener_work.sock_state.socket->sk->sk_state_change;
            listener_work.sock_state.socket->sk->sk_state_change = app_glue_sock_wakeup;
        }
        kernel_listen(listener_work.sock_state.socket, 10000);
    }
}
static void close_client_socket()
{
    if(client_sock_work.sock_state.socket) {
          client_sock_work.sock_state.socket->sk->sk_data_ready = app_glue_sock_readable;
          client_sock_work.sock_state.socket->sk->sk_write_space = app_glue_sock_write_space;
          kernel_sock_shutdown(client_sock_work.sock_state.socket,SHUT_RDWR);
//          inet_release(client_sock_work.sock_state.socket);
          client_sock_work.sock_state.socket = NULL;
    }
}

static void close_server_socket()
{
    if(listener_work.sock_state.socket) {
          listener_work.sock_state.socket->sk->sk_state_change = sock_def_wakeup;
          kernel_sock_shutdown(listener_work.sock_state.socket,SHUT_RDWR); 
          inet_release(listener_work.sock_state.socket);
          listener_work.sock_state.socket = NULL;
    }
    if(accepted_work.sock_state.socket) {
         accepted_work.sock_state.socket->sk->sk_data_ready = sock_def_readable;
         accepted_work.sock_state.socket->sk->sk_write_space = sock_def_write_space;
         kernel_sock_shutdown(accepted_work.sock_state.socket,SHUT_RDWR);
         accepted_work.sock_state.socket = NULL;
    }
}
static void client_connection_opener_fn(struct work_struct *work)
{
    open_client_socket();
}
static void server_connection_opener_fn(struct work_struct *work)
{
    open_server_socket();
}
static void client_connection_closer_fn(struct work_struct *work)
{
    close_client_socket();
}
static void server_connection_closer_fn(struct work_struct *work)
{
    close_server_socket();
}
static int bm_major;
static struct cdev *bm_cdev;

static int bm_open(struct inode *inode, struct file *filep)
{
    printk(KERN_INFO "%s %d\n",__FILE__,__LINE__);
    return 0;
}

static int bm_release(struct inode *inode, struct file *filep)
{
     printk(KERN_INFO "%s %d\n",__FILE__,__LINE__);
     return 0;
}
static ssize_t bm_read(struct file *filep, char __user *buf,
                        size_t count, loff_t *ppos)
{
     printk(KERN_INFO "%s %d\n",__FILE__,__LINE__);
     return 0;
}
static ssize_t bm_write(struct file *filep, const char __user *buf,
                        size_t count, loff_t *ppos)
{
#if 0
     printk(KERN_INFO "my ip %s peers ip %s port %d\n",myipaddress,peeripaddress,port);
     memset(&client_sock_work,0,sizeof(client_sock_work));
     memset(&listener_work,0,sizeof(client_sock_work));
     memset(&accepted_work,0,sizeof(client_sock_work));
     INIT_WORK(&client_sock_work.write_work,client_connection_opener_fn);
     INIT_WORK(&listener_work.write_work,server_connection_opener_fn);
     if(peeripaddress[0] == '0') {
         serverMode = 1;
         schedule_work(&listener_work.write_work);
     }
     else {
         schedule_work(&client_sock_work.write_work);
     }
#else
    struct bm_iface bm_iface;
    if(sizeof(struct bm_iface) != count) {
        printk(KERN_INFO "invalide size of structure %d\n",count);
        return -1;
    }
    copy_from_user(&bm_iface,buf,sizeof(struct bm_iface));
    printk(KERN_INFO "my ip %s peer ip %s port %d\n",bm_iface.my_ip_addr,bm_iface.peer_ip_addr,bm_iface.port);
    memcpy(bm_dev.bm_iface.my_ip_addr,bm_iface.my_ip_addr,sizeof(bm_iface.my_ip_addr));
    memcpy(bm_dev.bm_iface.peer_ip_addr,bm_iface.peer_ip_addr,sizeof(bm_iface.peer_ip_addr));
    bm_dev.bm_iface.port = bm_iface.port;
    memset(&client_sock_work,0,sizeof(client_sock_work));
    memset(&listener_work,0,sizeof(client_sock_work));
    memset(&accepted_work,0,sizeof(client_sock_work));
    INIT_WORK(&client_sock_work.write_work,client_connection_opener_fn);
    INIT_WORK(&listener_work.write_work,server_connection_opener_fn);
    if(bm_dev.bm_iface.peer_ip_addr[0] == '0') {
        serverMode = 1;
        schedule_work(&listener_work.write_work);
    }
    else {
        schedule_work(&client_sock_work.write_work);
    }
#endif
     return sizeof(struct bm_iface);
}
static const struct file_operations bm_fops = {
        .owner          = THIS_MODULE,
        .open           = bm_open,
        .release        = bm_release,
        .read           = bm_read,
        .write          = bm_write,
//        .mmap           = uio_mmap,
//        .poll           = uio_poll,
//        .fasync         = uio_fasync,
        .llseek         = noop_llseek,
};
static int major_init()
{
       static const char name[] = "bm";
       struct cdev *cdev = NULL;
       dev_t bm_dev = 0;
       int result;

       result = alloc_chrdev_region(&bm_dev, 0, 1/*MAX_DEVICES*/, name);
       if (result)
               goto out;
       result = -ENOMEM;
       cdev = cdev_alloc();
       if (!cdev)
               goto out_unregister;
       cdev->owner = THIS_MODULE;
       cdev->ops = &bm_fops;
       kobject_set_name(&cdev->kobj, "%s", name);
       result = cdev_add(cdev, bm_dev, 1/*MAX_DEVICES*/);
       if (result)
               goto out_put;
       bm_major = MAJOR(bm_dev);
       bm_cdev = cdev;
       return 0;
out_put:
       kobject_put(&cdev->kobj);
out_unregister:
       unregister_chrdev_region(bm_dev, 1/*UIO_MAX_DEVICES*/);
out:
       return result;
}

static int create_device()
{
    bm_dev.minor = 0;
    bm_dev.dev = device_create(bm_class, NULL,
                               MKDEV(bm_major, bm_dev.minor), &bm_dev,
                               "bm%d", bm_dev.minor);
    if (IS_ERR(bm_dev.dev)) {
            printk(KERN_ERR "BM: device register failed\n");
            return PTR_ERR(bm_dev.dev);
    }
    return 0;
}
int init_module(void)
{
        int err;
        if(major_init() != 0) {
            printk(KERN_INFO "cannot init bm major\n");
            return -1;
        }
        bm_class = class_create(THIS_MODULE, "bm");
        if (IS_ERR(bm_class)) {
                err = PTR_ERR(bm_class);
                pr_err("Error %d creating bm class\n", err);
                return err;
        }
        if(create_device() != 0) {
            printk(KERN_INFO "cannot create bm device\n");
            return -1;
        }
        printk(KERN_INFO "%s %d\n",__FILE__,__LINE__);
	return 0;
}

void cleanup_module(void)
{
//        schedule_work(&server_connection_opener);
//        schedule_work(&client_connection_opener);
//        while(client_sock || server_sock);
   //     close_client_socket();
   //     close_server_socket();
 //       cancel_delayed_work_sync(&bm_stats);
	printk(KERN_INFO "Goodbye world 1.\n");
}
