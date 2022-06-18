let install_filter = null, syscall_thread_ptr, call_task, lock, unlock, findSoinfoByAddr, solist_get_head_ptr, get_soname, get_base, get_size, maps = [];
const MAX_STACK_TRACE_DEPTH = 10;
const Target_NR = 207;
const prctl_ptr = Module.findExportByName(null, 'prctl')
const strcpy_ptr = Module.findExportByName(null, 'strcpy')
const fopen_ptr = Module.findExportByName(null, 'fopen')
const fclose_ptr = Module.findExportByName(null, 'fclose')
const fgets_ptr = Module.findExportByName(null, 'fgets')
const strtoul_ptr = Module.findExportByName(null, 'strtoul')
const strtok_ptr = Module.findExportByName(null, 'strtok')
const malloc_ptr = Module.findExportByName(null, 'malloc')
const __android_log_print_ptr = Module.findExportByName(null, '__android_log_print')
const pthread_create_ptr = Module.findExportByName(null, 'pthread_create')
const pthread_mutex_init_ptr = Module.findExportByName(null, 'pthread_mutex_init')
const pthread_mutex_lock_ptr = Module.findExportByName(null, 'pthread_mutex_lock')
const pthread_mutex_unlock_ptr = Module.findExportByName(null, 'pthread_mutex_unlock')
const pthread_join_ptr = Module.findExportByName(null, 'pthread_join')
const syscall_ptr = Module.findExportByName(null, 'syscall')
var linker = null;
var syscalls = null;
var syscalls_name = null;
var cm = null;
var isArm64 = null
if (Process.arch == "arm") {
    isArm64 = false
    linker = Process.findModuleByName("linker");
} else if (Process.arch == "arm64") {
    linker = Process.findModuleByName("linker64");
    isArm64 = true
}

// const linker = Process.findModuleByName("linker64");
const linker_symbols = linker.enumerateSymbols()
for (let index = 0; index < linker_symbols.length; index++) {
    const element = linker_symbols[index];
    if (element.name.indexOf("solist_get_head") != -1) {
        console.log(JSON.stringify(element))
    }
    if (element.name == '__dl__Z15solist_get_headv') {
        solist_get_head_ptr = element.address
        console.log("solist_get_head_ptr=", solist_get_head_ptr)
    } else if (element.name == '__dl__ZNK6soinfo10get_sonameEv') {
        get_soname = new NativeFunction(element.address, "pointer", ["pointer"])
    }
}

if (Process.arch == "arm") {
    // https://syscalls.w3challs.com/
    // https://syscalls.w3challs.com/?arch=arm_strong
    // http://androidxref.com/kernel_3.18/xref/arch/arm/include/uapi/asm/unistd.h
    // syscalls = [
    //     [322, "openat", 0x142, "int dfd", "const char *filename", "int flags", "umode_t mode"],
    //     [3, "read", 0x3, "unsigned int fd", "char *buf", "size_t count", "-"],
    // ];
    syscalls_name = {
        "322": "openat", // [322, "openat", 0x142, "int dfd", "const char *filename", "int flags", "umode_t mode"],
        "3": "read", // [3, "read", 0x3, "unsigned int fd", "char *buf", "size_t count", "-"],
        "4": "write", // [3, "read", 0x3, "unsigned int fd", "char *buf", "size_t count", "-"],
    }
    cm = new CModule(`
#include <stdio.h>
#include <gum/gumprocess.h>
#define BPF_STMT(code,k) { (unsigned short) (code), 0, 0, k }
#define BPF_JUMP(code,k,jt,jf) { (unsigned short) (code), jt, jf, k }
#define BPF_LD 0x00
#define BPF_W 0x00
#define BPF_ABS 0x20
#define BPF_JEQ 0x10
#define BPF_JMP 0x05
#define BPF_K 0x00
#define BPF_RET 0x06


#define PR_SET_SECCOMP	22
#define PR_SET_NO_NEW_PRIVS	38
#define SECCOMP_MODE_FILTER	2
#define SECCOMP_RET_TRAP 0x00030000U
#define SECCOMP_RET_ALLOW 0x7fff0000U

#define SIGSYS  12
#define SIG_UNBLOCK     2

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef unsigned long sigset_t;
typedef long pthread_t;

typedef struct {
    uint32_t flags;
    void* stack_base;
    size_t stack_size;
    size_t guard_size;
    int32_t sched_policy;
    int32_t sched_priority;
  #ifdef __LP64__
    char __reserved[16];
  #endif
  } pthread_attr_t;

typedef struct {
#if defined(__LP64__)
  int32_t __private[10];
#else
  int32_t __private[1];
#endif
} pthread_mutex_t;

typedef struct {
    int type;
    int isTask;
    void *args;
    int isReturn;
    void *ret;
    pthread_t thread;
    pthread_mutex_t mutex;
} thread_syscall_t;

typedef struct{
    const void *phdr;
    size_t phnum;
    uint32_t base;
    size_t size;
    void *dynamic;
    void *next;
} soinfo;

extern char* strcpy(char* __dst, const char* __src);
extern void* fopen(const char* __path, const char* __mode);
extern int fclose(void* __fp);
extern char* fgets(char* __buf, int __size, void* __fp);
extern unsigned long strtoul(const char* __s, char** __end_ptr, int __base);
extern char* strtok(char* __s, const char* __delimiter);
extern soinfo *solist_get_head();
extern int __android_log_print(int prio, const char* tag, const char* fmt, ...);
extern void *malloc(size_t __byte_count);
extern long syscall(long __number, ...);
extern int pthread_create(pthread_t* __pthread_ptr, pthread_attr_t const* __attr, void* (*__start_routine)(void*), void*);
extern int pthread_mutex_init(pthread_mutex_t* __mutex, const void* __attr);
extern int pthread_mutex_lock(pthread_mutex_t* __mutex);
extern int pthread_mutex_unlock(pthread_mutex_t* __mutex);
extern int pthread_join(pthread_t __pthread, void** __return_value_ptr);
extern void on_message(const gchar *message);
extern void on_messageInt(int a);
extern int prctl(int __option, ...);

uint32_t get_base(soinfo *si){
    return si->base;
}

size_t get_size(soinfo *si){
    return si->size;
}

soinfo *findSoinfoByAddr(void *addr_v) {
    uint32_t addr = (uint32_t) addr_v;
    // auto addr = (uintptr_t*)(addr_v) % sizeof(uint32_t);
    // on_messageInt(addr);
    // on_messageInt(addr);
    // on_message(addr_v);
    // on_message((void *)solist_get_head());
    for (soinfo *si = (soinfo *)solist_get_head(); si != NULL; si = si->next) {
        // on_messageInt(si->base);
        // on_messageInt(addr);
        // on_messageInt(addr+0xffffffff);
        // on_messageInt(si->base + si->size);
      if (addr >= si->base && addr < (si->base + si->size)) {
        return si;
      }
    }
    return NULL;
}

int lock(thread_syscall_t *syscall_thread){
    return pthread_mutex_lock(&syscall_thread->mutex);
}

int unlock(thread_syscall_t *syscall_thread){
    return pthread_mutex_unlock(&syscall_thread->mutex);
}

void *call_syscall(void *args){
    void **d_args = (void **)args;
    void *ret = (void *)syscall((long)d_args[0] ,d_args[1] ,d_args[2] ,d_args[3], d_args[4], d_args[5], d_args[6]);
    return ret;
}

void *call_read_maps(void *args){
    uint32_t addr = (uint32_t) args;
    FILE *fp = fopen("/proc/self/maps", "r");
    char line[1024];
    char _line[1024];
    uint32_t start, end;
    while (fgets(line, sizeof(line), fp) != NULL) {
        strcpy(_line, line);
        start = (uint32_t) strtoul(strtok(line, "-"), NULL, 16);
        end = (uint32_t) strtoul(strtok(NULL, " "), NULL, 16);
        if (addr >= start && addr < end) {
          break;
        }
    }
    fclose(fp);
    return (void *)_line;
}

void *call_task(thread_syscall_t *syscall_thread,void *args,int type){
    if(syscall_thread->isTask == 0){
        syscall_thread->args = args;
        syscall_thread->type = type;
        syscall_thread->isTask = 1;
    }
    do{
        if(syscall_thread->isReturn){
            syscall_thread->isReturn = 0;
            return syscall_thread->ret;
        }
    }while(1);
}

void *call_log(void *args){
    __android_log_print(3, "seccomp", (const char *)args);
    return NULL;
}

void *pthread_syscall(void *args){
    thread_syscall_t *syscall_thread = (thread_syscall_t *)args;
    while(1){
        if(syscall_thread->isTask){
            if(syscall_thread->type == 0){
                syscall_thread->ret = call_syscall(syscall_thread->args);
            }else if(syscall_thread->type == 1){
                syscall_thread->ret = call_log(syscall_thread->args);
            }else if(syscall_thread->type == 2){
                syscall_thread->ret = call_read_maps(syscall_thread->args);
            }
            syscall_thread->args = NULL;
            syscall_thread->isReturn = 1;
            syscall_thread->isTask = 0;
        }
    }
    return NULL;
}

//syscall线程创建

thread_syscall_t *pthread_syscall_create(){
    thread_syscall_t *syscall_thread = (thread_syscall_t *)malloc(sizeof(thread_syscall_t));
    syscall_thread->type = 0;
    syscall_thread->isTask = 0;
    syscall_thread->args = NULL;
    syscall_thread->ret = NULL;
    syscall_thread->isReturn = 0;
    pthread_mutex_init(&syscall_thread->mutex, NULL);
    pthread_t threadId;
    pthread_create(&threadId, NULL, &pthread_syscall, (void *)syscall_thread);
    syscall_thread->thread = threadId;
    return syscall_thread;
}

struct seccomp_data {
    int nr;
    __u32 arch;
    __u64 instruction_pointer;
    __u64 args[6];
};

struct sock_filter {
    __u16 code;
    __u8 jt;
    __u8 jf;
    __u32 k;
};

struct sock_fprog {
    unsigned short len;
    struct sock_filter * filter;
};

int install_filter(__u32 nr) {
    // log("install_filter(%lu)",nr);
    struct sock_filter filter[] = {
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, nr, 0, 1),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
            .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
            .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        on_message("prctl(NO_NEW_PRIVS)");
        return 1;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        on_message("prctl(PR_SET_SECCOMP)");
        return 1;
    }
    return 0;
}

    `, {
        malloc: malloc_ptr,
        prctl: prctl_ptr,
        fopen: fopen_ptr,
        fclose: fclose_ptr,
        fgets: fgets_ptr,
        strtok: strtok_ptr,
        strcpy: strcpy_ptr,
        strtoul: strtoul_ptr,
        __android_log_print: __android_log_print_ptr,
        pthread_create: pthread_create_ptr,
        // pthread_join: pthread_join_ptr,
        pthread_mutex_init: pthread_mutex_init_ptr,
        pthread_mutex_lock: pthread_mutex_lock_ptr,
        pthread_mutex_unlock: pthread_mutex_unlock_ptr,
        syscall: syscall_ptr,
        solist_get_head: solist_get_head_ptr,
        on_message: new NativeCallback(messagePtr => {
            // const message = messagePtr.readUtf8String();
            console.log("messagePtr=", messagePtr)
        }, 'void', ['pointer']),
        on_messageInt: new NativeCallback(messageInt => {
            // const message = messagePtr.readUtf8String();
            console.log("messageInt=", messageInt)
        }, 'void', ['int'])
    })
} else if (Process.arch == "arm64") {
    // https://thog.github.io/syscalls-table-aarch64/latest.html
    // http://androidxref.com/kernel_3.18/xref/include/uapi/asm-generic/unistd.h
    syscalls = [
        [56, "openat", 0x38, "int dfd", "const char *filename", "int flags", "umode_t mode"],
        [59, "pipe2", 0x3b, "int *fildes", "int flags", "-", "-"],
        [63, "read", 0x3f, "unsigned int fd", "char *buf", "size_t count", "-"],
        [64, "write", 0x40, "unsigned int fd", "const char *buf", "size_t count", "-"],
        [65, "readv", 0x41, "unsigned long fd", "const struct iovec *vec", "unsigned long vlen", "-"],
        [66, "writev", 0x42, "unsigned long fd", "const struct iovec *vec", "unsigned long vlen", "-"],
    ];
    syscalls_name = {
        "56": "openat", // [56, "openat", 0x38, "int dfd", "const char *filename", "int flags", "umode_t mode"],
        "59": "pipe2", // [59, "pipe2", 0x3b, "int *fildes", "int flags", "-", "-"],
        "63": "read", // [63, "read", 0x3f, "unsigned int fd", "char *buf", "size_t count", "-"],
        "64": "write", // [64, "write", 0x40, "unsigned int fd", "const char *buf", "size_t count", "-"],
        "65": "readv", // [65, "readv", 0x41, "unsigned long fd", "const struct iovec *vec", "unsigned long vlen", "-"],
        "66": "writev", // [66, "writev", 0x42, "unsigned long fd", "const struct iovec *vec", "unsigned long vlen", "-"],
    }
    // CModule模块编写
    cm = new CModule(`
#include <stdio.h>
#include <gum/gumprocess.h>
#define BPF_STMT(code,k) { (unsigned short) (code), 0, 0, k }
#define BPF_JUMP(code,k,jt,jf) { (unsigned short) (code), jt, jf, k }
#define BPF_LD 0x00
#define BPF_W 0x00
#define BPF_ABS 0x20
#define BPF_JEQ 0x10
#define BPF_JMP 0x05
#define BPF_K 0x00
#define BPF_RET 0x06


#define PR_SET_SECCOMP	22
#define PR_SET_NO_NEW_PRIVS	38
#define SECCOMP_MODE_FILTER	2
#define SECCOMP_RET_TRAP 0x00030000U
#define SECCOMP_RET_ALLOW 0x7fff0000U

#define SIGSYS  12
#define SIG_UNBLOCK     2

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef unsigned long sigset_t;
typedef long pthread_t;

typedef struct {
    uint32_t flags;
    void* stack_base;
    size_t stack_size;
    size_t guard_size;
    int32_t sched_policy;
    int32_t sched_priority;
  #ifdef __LP64__
    char __reserved[16];
  #endif
  } pthread_attr_t;

typedef struct {
#if defined(__LP64__)
  int32_t __private[10];
#else
  int32_t __private[1];
#endif
} pthread_mutex_t;

typedef struct {
    int type;
    int isTask;
    void *args;
    int isReturn;
    void *ret;
    pthread_t thread;
    pthread_mutex_t mutex;
} thread_syscall_t;

typedef struct{
    const void *phdr;
    size_t phnum;
    uint64_t base;
    size_t size;
    void *dynamic;
    void *next;
} soinfo;

extern char* strcpy(char* __dst, const char* __src);
extern void* fopen(const char* __path, const char* __mode);
extern int fclose(void* __fp);
extern char* fgets(char* __buf, int __size, void* __fp);
extern unsigned long strtoul(const char* __s, char** __end_ptr, int __base);
extern char* strtok(char* __s, const char* __delimiter);
extern soinfo *solist_get_head();
extern int __android_log_print(int prio, const char* tag, const char* fmt, ...);
extern void *malloc(size_t __byte_count);
extern long syscall(long __number, ...);
extern int pthread_create(pthread_t* __pthread_ptr, pthread_attr_t const* __attr, void* (*__start_routine)(void*), void*);
extern int pthread_mutex_init(pthread_mutex_t* __mutex, const void* __attr);
extern int pthread_mutex_lock(pthread_mutex_t* __mutex);
extern int pthread_mutex_unlock(pthread_mutex_t* __mutex);
extern int pthread_join(pthread_t __pthread, void** __return_value_ptr);
extern void on_message(const gchar *message);
extern void on_messageInt(int a);
extern int prctl(int __option, ...);

uint64_t get_base(soinfo *si){
    return si->base;
}

size_t get_size(soinfo *si){
    return si->size;
}

soinfo *findSoinfoByAddr(void *addr_v) {
    uint64_t addr = (uint64_t) addr_v;
    // on_message(addr_v);
    // on_messageInt(addr);
    for (soinfo *si = (soinfo *)solist_get_head(); si != NULL; si = si->next) {
      if (addr >= si->base && addr < (si->base + si->size)) {
        return si;
      }
    }
    return NULL;
}

static void log(const gchar *format, ...)
{
    gchar *message;
    va_list args;
    va_start(args, format);
    message = g_strdup_vprintf(format, args);
    va_end(args);
    on_message(message);
    g_free(message);
}

int lock(thread_syscall_t *syscall_thread){
    return pthread_mutex_lock(&syscall_thread->mutex);
}

int unlock(thread_syscall_t *syscall_thread){
    return pthread_mutex_unlock(&syscall_thread->mutex);
}

void *call_syscall(void *args){
    void **d_args = (void **)args;
    void *ret = (void *)syscall((long)d_args[0] ,d_args[1] ,d_args[2] ,d_args[3], d_args[4], d_args[5], d_args[6]);
    return ret;
}

void *call_log(void *args){
    __android_log_print(3, "seccomp", (const char *)args);
    return NULL;
}

void *call_read_maps(void *args){
    uint64_t addr = (uint64_t) args;
    FILE *fp = fopen("/proc/self/maps", "r");
    char line[1024];
    char _line[1024];
    uint64_t start, end;
    while (fgets(line, sizeof(line), fp) != NULL) {
        strcpy(_line, line);
        start = (uint64_t) strtoul(strtok(line, "-"), NULL, 16);
        end = (uint64_t) strtoul(strtok(NULL, " "), NULL, 16);
        if (addr >= start && addr < end) {
          break;
        }
    }
    fclose(fp);
    return (void *)_line;
}

void *call_task(thread_syscall_t *syscall_thread,void *args,int type){
    if(syscall_thread->isTask == 0){
        syscall_thread->args = args;
        syscall_thread->type = type;
        syscall_thread->isTask = 1;
    }
    do{
        if(syscall_thread->isReturn){
            syscall_thread->isReturn = 0;
            return syscall_thread->ret;
        }
    }while(1);
}

void *pthread_syscall(void *args){
    thread_syscall_t *syscall_thread = (thread_syscall_t *)args;
    while(1){
        if(syscall_thread->isTask){
            if(syscall_thread->type == 0){
                syscall_thread->ret = call_syscall(syscall_thread->args);
            }else if(syscall_thread->type == 1){
                syscall_thread->ret = call_log(syscall_thread->args);
            }else if(syscall_thread->type == 2){
                syscall_thread->ret = call_read_maps(syscall_thread->args);
            }
            syscall_thread->args = NULL;
            syscall_thread->isReturn = 1;
            syscall_thread->isTask = 0;
        }
    }
    return NULL;
}

//syscall线程创建

thread_syscall_t *pthread_syscall_create(){
    thread_syscall_t *syscall_thread = (thread_syscall_t *)malloc(sizeof(thread_syscall_t));
    syscall_thread->type = 0;
    syscall_thread->isTask = 0;
    syscall_thread->args = NULL;
    syscall_thread->ret = NULL;
    syscall_thread->isReturn = 0;
    pthread_mutex_init(&syscall_thread->mutex, NULL);
    pthread_t threadId;
    pthread_create(&threadId, NULL, &pthread_syscall, (void *)syscall_thread);
    syscall_thread->thread = threadId;
    return syscall_thread;
}

struct seccomp_data {
    int nr;
    __u32 arch;
    __u64 instruction_pointer;
    __u64 args[6];
};

struct sock_filter {
    __u16 code;
    __u8 jt;
    __u8 jf;
    __u32 k;
};

struct sock_fprog {
    unsigned short len;
    struct sock_filter * filter;
};

int install_filter(__u32 nr) {
    log("install_filter(%lu)",nr);
    struct sock_filter filter[] = {
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, nr, 0, 1),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
            .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
            .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        on_message("prctl(NO_NEW_PRIVS)");
        return 1;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        on_message("prctl(PR_SET_SECCOMP)");
        return 1;
    }
    return 0;
}
`, {
        malloc: malloc_ptr,
        prctl: prctl_ptr,
        fopen: fopen_ptr,
        fclose: fclose_ptr,
        fgets: fgets_ptr,
        strtok: strtok_ptr,
        strcpy: strcpy_ptr,
        strtoul: strtoul_ptr,
        __android_log_print: __android_log_print_ptr,
        pthread_create: pthread_create_ptr,
        pthread_join: pthread_join_ptr,
        pthread_mutex_init: pthread_mutex_init_ptr,
        pthread_mutex_lock: pthread_mutex_lock_ptr,
        pthread_mutex_unlock: pthread_mutex_unlock_ptr,
        syscall: syscall_ptr,
        solist_get_head: solist_get_head_ptr,
        on_message: new NativeCallback(messagePtr => {
            // const message = messagePtr.readUtf8String();
            console.log("messagePtr=", messagePtr, hexdump(messagePtr))
        }, 'void', ['pointer']),
        on_messageInt: new NativeCallback(messageInt => {
            // const message = messagePtr.readUtf8String();
            console.log("messageInt=", messageInt)
        }, 'void', ['int'])
    });
}

function init() {
    //初始化，需要在主线程初始化且需要一个比较早的时机，frida脚本运行在它自己创建的一个线程，所以需要通过hook安装seccomp规则
    syscall_thread_ptr = new NativeFunction(cm.pthread_syscall_create, "pointer", [])()
    findSoinfoByAddr = new NativeFunction(cm.findSoinfoByAddr, "pointer", ["pointer"])
    get_base = new NativeFunction(cm.get_base, "uint64", ["pointer"])
    get_size = new NativeFunction(cm.get_size, "size_t", ["pointer"])
    call_task = new NativeFunction(cm.call_task, "pointer", ["pointer", "pointer", "int"])
    install_filter = new NativeFunction(cm.install_filter, "int", ['uint32'])
    lock = new NativeFunction(cm.lock, "int", ["pointer"])
    unlock = new NativeFunction(cm.unlock, "int", ["pointer"])
    // console.log("init called")
    if (Process.arch == "arm") {
        // 异常处理
        Process.setExceptionHandler(function (details) {
            const current_off = details.context.pc - 4;
            // console.log(hex(ptr(current_off).readByteArray(4)))
            // https://armconverter.com/?code=svc%200
            // 判断是否是seccomp导致的异常 读取opcode 000000ef == svc 0
            if (details.message == "system error" && details.type == "system" && hex(ptr(current_off).readByteArray(4)) == "000000ef") {
                // 上锁避免多线程问题
                lock(syscall_thread_ptr)
                // 获取r7寄存器中的调用号
                const nr = details.context.r7.toString(10);
                // console.log("nr="+nr)
                let loginfo = "\n" + new Array(100).join("=")
                // loginfo += `\nSVC[${syscalls[nr][1]}|${nr}] ==> PC:${addrToString(current_off)} P${Process.id}-T${Process.getCurrentThreadId()}`
                loginfo += `\nSVC[${syscalls_name[nr]}]|${nr}] ==> PC:${addrToString(current_off)} Pid${Process.id}-Tid${Process.getCurrentThreadId()}`
                // 构造线程syscall调用参数
                const args = Memory.alloc(7 * 4)
                args.writePointer(details.context.r7)
                let args_reg_arr = {}
                for (let index = 0; index < 6; index++) {
                    eval(`args.add(4 * (index + 1)).writePointer(details.context.r${index})`)
                    eval(`args_reg_arr["arg${index}"] = details.context.r${index}`)
                }
                // 获取手动堆栈信息
                // console.log(JSON.stringify(details.context))
                // console.log("details.context.fp=",details.context.r11,"details.context.sp=",details.context.sp)
                loginfo += "\n" + stacktrace(ptr(current_off), details.context.r11, details.context.sp).map(addrToString).join('\n')
                // 打印传参
                loginfo += "\nargs = " + JSON.stringify(args_reg_arr)
                loginfo += "\n" + pretty_args_log(0, nr, args_reg_arr);
                // 调用线程syscall 赋值r0寄存器
                details.context.r0 = call_task(syscall_thread_ptr, args, 0)
                loginfo += "\nret = " + details.context.r0.toString()
                loginfo += "---" + pretty_args_log(0, nr, details.context.r0, 1);
                console.log(loginfo)
                // 打印信息
                call_thread_log(loginfo)
                // 解锁
                unlock(syscall_thread_ptr)
                return true;
            }
            return false;
        })
        // openat的调用号
        install_filter(322)
        install_filter(3)
        // install_filter(4) //会崩。
    } else if (Process.arch == "arm64") {
        // 异常处理
        Process.setExceptionHandler(function (details) {
            const current_off = details.context.pc - 4;
            // 判断是否是seccomp导致的异常 读取opcode 010000d4 == svc 0
            if (details.message == "system error" && details.type == "system" && hex(ptr(current_off).readByteArray(4)) == "010000d4") {
                // 上锁避免多线程问题
                lock(syscall_thread_ptr)
                // 获取x8寄存器中的调用号
                const nr = details.context.x8.toString(10);
                let loginfo = "\n" + new Array(100).join("=")
                loginfo += `\nSVC[${syscalls_name[nr]}|${nr}] ==> PC:${addrToString(current_off)} P${Process.id}-T${Process.getCurrentThreadId()}`
                // 构造线程syscall调用参数
                const args = Memory.alloc(7 * 8)
                args.writePointer(details.context.x8)
                let args_reg_arr = {}
                for (let index = 0; index < 6; index++) {
                    eval(`args.add(8 * (index + 1)).writePointer(details.context.x${index})`)
                    eval(`args_reg_arr["arg${index}"] = details.context.x${index}`)
                }
                // 获取手动堆栈信息
                loginfo += "\n" + stacktrace(ptr(current_off), details.context.fp, details.context.sp).map(addrToString).join('\n')
                // 打印传参
                loginfo += "\nargs = " + JSON.stringify(args_reg_arr)
                // console.log(hexdump(args_reg_arr["arg1"]))
                loginfo += "\n" + pretty_args_log(1, nr, args_reg_arr);
                // 调用线程syscall 赋值x0寄存器
                details.context.x0 = call_task(syscall_thread_ptr, args, 0)
                loginfo += "\nret = " + details.context.x0.toString()
                loginfo += "---" + pretty_args_log(1, nr, details.context.x0, 1);
                console.log(loginfo)
                // 打印信息
                call_thread_log(loginfo)
                // 解锁
                unlock(syscall_thread_ptr)
                return true;
            }
            return false;
        })
        // install_filter(56)
        install_filter(63)
        // install_filter(64)
    }
}

function pretty_args_log(isArm64, nr, args, isReturn) {
    var result = "";
    if (isArm64) {
        switch (nr) {
            case "56":
                // [56, "openat", 0x38, "int dfd", "const char *filename", "int flags", "umode_t mode"]
                if (isReturn) {
                    result += "[retval]=" + args
                } else {
                    result += "[filename]=" + args["arg1"].readCString() + "---[flags]=" + args["arg2"] + "---[mode]=" + args["arg3"]
                }
                break
            case "63":
                // [63, "read", 0x3f, "unsigned int fd", "char *buf", "size_t count", "-"]
                if (isReturn) {
                    result += "[retval]=" + args
                } else {
                    result += "[buf]=" + args["arg1"].readCString() + "---[count]=" + args["arg2"]
                }
                break
            case "64":
                // [64, "write", 0x40, "unsigned int fd", "const char *buf", "size_t count", "-"],
                if (isReturn) {
                    result += "[retval]=" + args
                } else {
                    result += "[buf]=" + args["arg1"].readCString() + "---[count]=" + args["arg2"]
                }
                break
            case "59":
                // [59, "pipe2", 0x3b, "int *fildes", "int flags", "-", "-"],
                if (isReturn) {
                    result += "[retval]=" + args
                } else {
                    result += "[flags]=" + args["arg1"]
                }
                break



            default:
                break
        }
    } else {
        // console.log("pretty_args_log nr="+nr)
        switch (nr) {
            case "322":
                // [322, "openat", 0x142, "int dfd", "const char *filename", "int flags", "umode_t mode"]
                if (isReturn) {
                    result += "[retval]=" + args
                } else {
                    result += "[filename]=" + args["arg1"].readCString() + "---[flags]=" + args["arg2"] + "---[mode]=" + args["arg3"]
                }
                break
            case "3":
                // [3, "read", 0x3, "unsigned int fd", "char *buf", "size_t count", "-"]
                if (isReturn) {
                    result += "[retval]=" + args
                } else {
                    result += "[buf]=" + args["arg1"].readCString() + "---[count]=" + args["arg2"]
                }
                break
            default:
                break
        }
    }
    return result;

}

Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter(args) {
        if (install_filter == null) {
            init()
        }
    }
})

const byteToHex = [];

for (let n = 0; n <= 0xff; ++n) {
    const hexOctet = n.toString(16).padStart(2, "0");
    byteToHex.push(hexOctet);
}

function hex(arrayBuffer) {
    const buff = new Uint8Array(arrayBuffer);
    const hexOctets = [];
    for (let i = 0; i < buff.length; ++i)
        hexOctets.push(byteToHex[buff[i]]);
    return hexOctets.join("");
}

function call_thread_log(str) {
    call_task(syscall_thread_ptr, Memory.allocUtf8String(str), 1)
}

function get_maps() {

}

function call_thread_read_maps_(addr) {
    if (maps.length == 0) {
        get_maps()
    }
    for (let index = 0; index < maps.length; index++) {
        const element = maps[index];
        if (parseInt(addr.toString()) >= element[0] && parseInt(addr.toString()) < element[1]) {
            return { start: element[0], end: element[1], name: element[2] }
        }
    }
}

function call_thread_read_maps(addr) {
    // console.log("maps="+maps)
    for (let index = 0; index < maps.length; index++) {
        const element = maps[index];
        if (parseInt(addr.toString()) >= element[0] && parseInt(addr.toString()) < element[1]) {
            return { start: element[0], end: element[1], name: element[2] }
        }
    }
    const map_info = call_task(syscall_thread_ptr, ptr(addr), 2).readUtf8String()
    // console.log("map_info="+map_info)
    const start = parseInt("0x" + map_info.split("-")[0])
    const end = parseInt("0x" + map_info.split("-")[1].split(" ")[0])
    // const name_arr = map_info.split("                              ")
    // const name = name_arr.length == 2 ? name_arr[2] : ""
    const name_arr = map_info.split("/")
    if (name_arr.length > 2) {
        var name = name_arr[name_arr.length - 1].replace("\n", "")
        // console.log(name)
    } else {
        var name = ""
    }
    // const name = name_arr.length > 2 ? name_arr[2] : ""
    // console.log("name_arr="+name_arr,"name="+name)
    maps.push([start, end, name])
    return { start, end, name }
}

function addrToString(addr) {
    const add_s = parseInt(addr.toString(10))
    // if(Process.arch=="arm"){
    //     // var so_name = DebugSymbol.fromAddress(ptr(addr));
    //     try{
    //         var so_name = Process.getModuleByAddress((addr))
    //         // console.log("so_name="+JSON.stringify(so_name))
    //         return `0x${add_s.toString(16)}[${so_name.name}:0x${(add_s - so_name.base).toString(16)}]`
    //     }catch(e){
    //         return `0x${addr.toString(16)}[unkownmem:]`
    //     }

    // }
    const addr_soinfo = findSoinfoByAddr(ptr(add_s));
    // const addr_soinfo = new NativeFunction(solist_get_head_ptr,"pointer",[])()
    // console.log("addr="+addr,"add_s="+add_s,"addr_soinfo="+addr_soinfo,new NativeFunction(solist_get_head_ptr,"pointer",[])())
    if (addr_soinfo != 0) {
        if (Process.arch == "arm") {
            return `0x${addr.toString(16)}[${get_soname(addr_soinfo).readUtf8String()}:0x${(addr - get_base(addr_soinfo)).toString(16)}]`
        } else if (Process.arch == "arm64") {
            return `0x${addr.toString(16)}[${get_soname(addr_soinfo).readUtf8String()}:0x${(addr - get_base(addr_soinfo)).toString(16)}]`
        }
    }
    if (add_s >= linker.base && add_s < linker.base + linker.size) {
        return `0x${add_s.toString(16)}[${linker.name}:0x${(add_s - linker.base).toString(16)}]`
    }
    const mem_region = call_thread_read_maps(add_s);
    // console.log(JSON.stringify(mem_region))
    if (mem_region.name != "") {
        return `0x${add_s.toString(16)}[${mem_region.name}:0x${(add_s - mem_region.start).toString(16)}]`
    }
    return `0x${addr.toString(16)}[unkownmem:]`
}

function stacktrace(pc, fp, sp) {
    let n = 0, stack_arr = [], fp_c = fp;
    stack_arr[n++] = pc;
    const mem_region = call_thread_read_maps(sp);
    while (n < MAX_STACK_TRACE_DEPTH) {
        if (parseInt(fp_c.toString()) < parseInt(sp.toString()) || fp_c < mem_region.start || fp_c > mem_region.end) {
            break
        }
        let next_fp = fp_c.readPointer()
        let lr = fp_c.add(8).readPointer()
        fp_c = next_fp
        stack_arr[n++] = lr
    }
    return stack_arr;
}

// frida -UF -l xyxseccomp.js -o out.log

// frida -U -f io.github.vvb2060.mahoshojo -l xyxseccomp.js --no-pause -o out.log
// frida -U -f com.xunlei.playfarm -l xyxseccomp.js --no-pause -o out.log
// frida -U -f com.xunlei.playfarm -l xyxseccomp.js --no-pause > out.log