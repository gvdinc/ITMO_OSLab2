#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/printk.h>
#include <linux/seq_file.h>
#include <linux/cdev.h>
#include "stats/cpustats.h"

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// Структура для представления записи в /proc
static struct proc_dir_entry *gvds_entry;

// Определение IOCTL команд
#define CPU_LOAD_MAGIC 'b'
#define RD_CPU_LOAD _IOR(CPU_LOAD_MAGIC, 1, struct cpu_times)   // макрос чтения данных о загрузке default
#define UPDATE_STATS _IOR(CPU_LOAD_MAGIC, 2, int core_number)   // макрос для обновления статистики

// Глобальные переменные для управления устройством
static dev_t stats_dev = 0;
static struct cpu_times *cpu_data = NULL;
static atomic_t stats_busy;
static struct class *stats_dev_class;
static struct cdev stats_cdev;

// Метод отчистки выделенной памяти
static void free_cpu_data(void) {
    if (cpu_data != NULL) {
        kfree(cpu_data);
        cpu_data = NULL;
    }
}

// Функции управления файловым устройством
static int stats_open(struct inode *inode, struct file *file);

static int stats_release(struct inode *inode, struct file *file);

static ssize_t stats_read(struct file *filp, char __user *buf, size_t len, loff_t *off);

static ssize_t stats_write(struct file *filp, const char *buf, size_t len, loff_t *off);

static long stats_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

// Определение операций с файловым устройством
static struct file_operations fops = {
        .owner          = THIS_MODULE,
        .read           = stats_read,
        .write          = stats_write,
        .open           = stats_open,
        .unlocked_ioctl = stats_ioctl,
        .release        = stats_release,
};

// Функция открытия устройства
static int stats_open(struct inode *inode, struct file *file) {
    // Проверка, что устройство не занято
    if (atomic_cmpxchg(&stats_busy, 0, 1) == 1) {
        return -EBUSY;
    }
    free_cpu_data();
    return 0;
}

// Функция закрытия устройства
static int stats_release(struct inode *inode, struct file *file) {
    atomic_set(&stats_busy, 0);
    free_cpu_data();
    return 0;
}

// Функция чтения из устройства (пустая, так как не предполагается чтение)
static ssize_t stats_read(struct file *filp, char __user *buf, size_t len, loff_t *off) {
    return 0;
}

// И функция записи в устройство (пустая, так как не предполагается запись)
static ssize_t stats_write(struct file *filp, const char *buf, size_t len, loff_t *off) {
    return 0;
}

// Функция обработки IOCTL команд
static long stats_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
        case UPDATE_STATS:
            int core_number = num_present_cpus();
            if (copy_to_user((int *) arg, &core_number, sizeof(int))) {
                return -EINVAL;
            }

            rcu_read_lock();
            // Сбор информации о загрузке вычислителя
            cpu_data = get_cpustat();
            rcu_read_unlock();

            return 0;

        case RD_CPU_LOAD:
            if (cpu_data == NULL) {
                return -ENOENT;
            }

            size_t size = sizeof(struct cpu_times) + sizeof(struct core_times) * cpu_data->core_num;
            if (copy_to_user((struct cpu_times*) arg, cpu_data, size)) {
                return -EINVAL;
            }
            free_cpu_data();

            return 0;
    }
}


// Не реагируем на попытки изменения файла proc
int react_procfs(struct seq_file *m, void *v) {
    pr_warn("I do not react procfs!\n");
    return 0;
}

// Инициализация модуля
static int __init

gvdstat_init(void) {
    gvds_entry = proc_create_single("gvdstat", 644, NULL, react_procfs);
    if (gvds_entry == NULL) {
        proc_remove(gvds_entry);
        pr_err("Error: failed to init /proc/gvdstat\n");
        return -ENOMEM;
    }
    pr_info("/proc/gvdstat is created\n");
    return 0;
}

// Очистка ресурсов при выгрузке модуля
static void __exit gvdstat_clean(void) {
    proc_remove(gvds_entry);                 // Удаление записи из /proc
    pr_info("turning off, /proc/gvdstat is now removed\n");
}

// Регистрация функций инициализации и очистки при загрузке и выгрузке модуля соответственно
module_init(gvdstat_init);
module_exit(gvdstat_clean);

MODULE_LICENSE("GPL");                      // Лицензия модуля
MODULE_AUTHOR("grebenkin_vd");              // Автор модуля
MODULE_DESCRIPTION("simple Linux module."); // Описание модуля
MODULE_VERSION("0.01");                     // Версия модуля
