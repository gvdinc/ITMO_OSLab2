#include <linux/cpumask.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/stat.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/time_namespace.h>
#include <linux/irqnr.h>
#include <linux/sched/cputime.h>
#include <linux/tick.h>

#include "cpustats.h"

#ifndef arch_irq_stat_cpu
#define arch_irq_stat_cpu(cpu) 0
#endif
#ifndef arch_irq_stat
#define arch_irq_stat() 0
#endif

static u64 find_idle_time(int cpu)
{
    u64 idle, idle_usecs = -1ULL;
    if (cpu_online(cpu))
        idle_usecs = get_cpu_idle_time_us(cpu, NULL);
    if (idle_usecs == -1ULL)
        /* !NO_HZ or cpu offline */
        idle = 0;
    else
        idle = idle_usecs;

    return idle;
}


static u64 find_iowait_time(int cpu)
{
    u64 iowait, iowait_usecs = -1ULL;
    if (cpu_online(cpu))
        iowait_usecs = get_cpu_iowait_time_us(cpu, NULL);
    if (iowait_usecs == -1ULL)
        /* !NO_HZ or cpu offline */
        iowait = 0;
    else
        iowait = iowait_usecs;

    return iowait;
}

// @depricated
static struct core_times *get_corestat(int core){
    if (core < 0 || (uint)core > num_present_cpus())
        return NULL;
    struct core_times *core_times_data = kmalloc(sizeof(struct core_times), GFP_KERNEL);
    core_times_data->core_id = core;
    core_times_data->user    = 424242;
    core_times_data->nice    = 42;
    core_times_data->system  = 14204;
    core_times_data->idle    = find_idle_time(core);
    core_times_data->iowait  = find_iowait_time(core);
    core_times_data->irq     = kstat_cpu_irqs_sum(core);
    core_times_data->softirq = kstat_cpu_softirqs_sum(core);
    return core_times_data;
}


struct cpu_times *get_cpustat(void){
    struct cpu_times *cpuTimes;
    struct core_times *coreTimes;
    size_t core_num = 0;
    for_each_possible_cpu(core_num){
        core_num++;
    }

    cpuTimes = kmalloc(sizeof(struct cpu_times) + sizeof(struct core_times) * core_num, GFP_KERNEL);
    if (cpuTimes == NULL)
        return NULL;
    cpuTimes->core_num = core_num;

    coreTimes = cpuTimes->cores;
    int core;
    for_each_possible_cpu(core){
        coreTimes->core_id = core;
        coreTimes->user    = 424242;
        coreTimes->nice    = 42;
        coreTimes->system  = 14204;
        coreTimes->idle    = find_idle_time(core);
        coreTimes->iowait  = find_iowait_time(core);
        coreTimes->irq     = kstat_cpu_irqs_sum(core);
        coreTimes->softirq = kstat_cpu_softirqs_sum(core);
        // Увеличение указателя на следующее ядро
        coreTimes++;
    }

    return cpuTimes;
}

//void gvd_cputest(int core){
//    pr_info("testing cpu statistics: ");
//    u64 idle = find_idle_time(core);
//    u64 iowait = find_iowait_time(core);
//    pr_info("Idle Time: %llu, ", idle);
//    pr_info("I/O Wait Time: %llu\n", iowait);
//};
