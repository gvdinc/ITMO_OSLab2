#include <linux/types.h>
#include <linux/printk.h>


#ifndef KERNELMODULE_CPUSTATS_H
#define KERNELMODULE_CPUSTATS_H

struct core_times {
    int core_id;
    u64 user;
    u64 nice;
    u64 system;
    u64 idle;
    u64 iowait;
    u64 irq;
    u64 softirq;
};

struct cpu_times {
    size_t core_num;
    struct core_times cores[12];
};

struct cpu_times *get_cpustat(void);

#endif //KERNELMODULE_CPUSTATS_H
