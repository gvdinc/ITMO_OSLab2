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

MODULE_LICENSE("GPL");                      // Лицензия модуля
MODULE_AUTHOR("grebenkin_vd");              // Автор модуля
MODULE_DESCRIPTION("simple Linux module."); // Описание модуля
MODULE_VERSION("0.01");                     // Версия модуля

// Определение IOCTL команд
#define CPU_LOAD_MAGIC 'b'
#define RD_CPU_LOAD _IOR(CPU_LOAD_MAGIC, 1, struct cpu_times)   // макрос чтения данных о загрузке default
#define UPDATE_STATS _IOR(CPU_LOAD_MAGIC, 2, int)   // макрос для обновления статистики

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

        default:
            return -EINVAL;
    }
}


// Инициализация модуля
static int __init stats_init(void) {
    // Регистрация устройства
    if ((alloc_chrdev_region(&stats_dev, 0, 1, "stats")) < 0) {
        pr_err("alloc_chrdev_region failed\n");
        return -1;
    }

    cdev_init(&stats_cdev, &fops);

    if ((cdev_add(&stats_cdev, stats_dev, 1)) < 0) {
        pr_err("cdev_add failed\n");
        class_destroy(stats_dev_class);
        return -1;
    }

    if (IS_ERR(stats_dev_class = class_create("stats_class"))) {
        pr_err("class_create failed\n");
        class_destroy(stats_dev_class);
        return -1;
    }

    if(IS_ERR(device_create(stats_dev_class, NULL, stats_dev, NULL, "stats"))){
        pr_err("device_create failed\n");
        class_destroy(stats_dev_class);
        unregister_chrdev_region(stats_dev, 1);
        return -1;
    }
    atomic_set(&stats_busy, 0);
    pr_info("custom stats module initialised\n");

    return 0;
}

// Очистка ресурсов при выгрузке модуля
static void __exit stats_clean(void) {
    device_destroy(stats_dev_class, stats_dev);
    class_destroy(stats_dev_class);
    cdev_del(&stats_cdev);
    unregister_chrdev_region(stats_dev, 1);
    free_cpu_data();
    pr_info("Cleaned up and turned off \n");
}

// Регистрация функций инициализации и очистки при загрузке и выгрузке модуля соответственно
module_init(stats_init);
module_exit(stats_clean);
