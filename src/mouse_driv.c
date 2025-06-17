/*
 * mouse_driv.c - Драйвер мыши с кольцевым буфером и расширенным sysfs
 * Разрабатывалось на Linux 6.11.0-19-generic
 * Создаёт устройство /dev/mouselog для эмуляции координат мыши с чтением/записью,
 * кольцевым буфером и настройкой через sysfs.
 *
 * ИНСТРУКЦИИ:
 * 1. Скомпилировать: make
 * 2. Загрузить: sudo insmod src/mouse_driv.ko
 * 3. Создать устройство: sudo mknod /dev/mouselog c <major_number> 0
 * 4. Установить права: sudo chmod 666 /dev/mouselog
 * 5. Тестировать: ./tests/test_write "test", ./tests/test_read
 * 6. Настройка sysfs:
 *    - echo 2 > /sys/mouselog/display_mode
 *    - cat /sys/mouselog/buffer_status
 *    - echo 2048 > /sys/mouselog/buffer_size
 *    - echo 1 > /sys/mouselog/clear_buffer
 *    - cat /sys/mouselog/event_count
 * 7. Удалить: sudo rmmod mouse_driv
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/kobject.h>
#include <linux/random.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
#error "This module requires Linux kernel version 5.0 or higher"
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("M. Talbushkin <m@mxtn.dev>");
MODULE_DESCRIPTION("Mouse driver with ring buffer and extended sysfs");
MODULE_VERSION("0.3");

#define DEVICE_NAME "mouselog"

static int buffer_size = 4096;
module_param(buffer_size, int, 0644);
MODULE_PARM_DESC(buffer_size, "Initial buffer size for mouse data");

static int display_mode = 2;
module_param(display_mode, int, 0644);
MODULE_PARM_DESC(display_mode, "Display mode (0=X, 1=Y, 2=X+Y)");

static int major_number;
static unsigned long event_count = 0;
static struct ring_buffer {
    char *data;
    size_t size;
    size_t head;
    size_t tail;
    struct mutex lock;
} buffer;

static struct kobject *mouse_kobj;

static int mouse_open(struct inode *, struct file *);
static int mouse_release(struct inode *, struct file *);
static ssize_t mouse_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t mouse_write(struct file *, const char __user *, size_t, loff_t *);

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = mouse_open,
    .release = mouse_release,
    .read = mouse_read,
    .write = mouse_write,
};

static void simulate_mouse_data(void);

static ssize_t display_mode_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", display_mode);
}

static ssize_t display_mode_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    int value;
    if (kstrtoint(buf, 10, &value) || value < 0 || value > 2)
        return -EINVAL;
    display_mode = value;
    return count;
}

static ssize_t buffer_status_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    size_t available;
    mutex_lock(&buffer.lock);
    available = (buffer.head >= buffer.tail) ? 
                (buffer.head - buffer.tail) : 
                (buffer.size - buffer.tail + buffer.head);
    mutex_unlock(&buffer.lock);
    return sprintf(buf, "Used: %zu, Free: %zu\n", available, buffer.size - available - 1);
}

static ssize_t buffer_size_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%zu\n", buffer.size);
}

static ssize_t buffer_size_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    size_t new_size;
    char *new_data;

    if (kstrtoul(buf, 10, &new_size) < 0 || new_size < 64 || new_size > 65536)
        return -EINVAL;

    new_data = kmalloc(new_size, GFP_KERNEL);
    if (!new_data)
        return -ENOMEM;

    mutex_lock(&buffer.lock);
    if (buffer.head != buffer.tail) {
        kfree(new_data);
        mutex_unlock(&buffer.lock);
        return -EBUSY;
    }

    kfree(buffer.data);
    buffer.data = new_data;
    buffer.size = new_size;
    buffer.head = 0;
    buffer.tail = 0;
    mutex_unlock(&buffer.lock);
    return count;
}

static ssize_t clear_buffer_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    int value;
    if (kstrtoint(buf, 10, &value) || value != 1)
        return -EINVAL;
    mutex_lock(&buffer.lock);
    buffer.head = 0;
    buffer.tail = 0;
    mutex_unlock(&buffer.lock);
    return count;
}

static ssize_t event_count_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%lu\n", event_count);
}

static struct kobj_attribute display_mode_attr = __ATTR(display_mode, 0644, display_mode_show, display_mode_store);
static struct kobj_attribute buffer_status_attr = __ATTR_RO(buffer_status);
static struct kobj_attribute buffer_size_attr = __ATTR(buffer_size, 0644, buffer_size_show, buffer_size_store);
static struct kobj_attribute clear_buffer_attr = __ATTR_WO(clear_buffer);
static struct kobj_attribute event_count_attr = __ATTR_RO(event_count);

static struct attribute *mouse_attrs[] = {
    &display_mode_attr.attr,
    &buffer_status_attr.attr,
    &buffer_size_attr.attr,
    &clear_buffer_attr.attr,
    &event_count_attr.attr,
    NULL,
};

static struct attribute_group attr_group = {
    .attrs = mouse_attrs,
};

static int init_ring_buffer(size_t size) {
    buffer.data = kmalloc(size, GFP_KERNEL);
    if (!buffer.data) {
        printk(KERN_ERR "mouse_driv: Failed to allocate buffer\n");
        return -ENOMEM;
    }
    buffer.size = size;
    buffer.head = 0;
    buffer.tail = 0;
    mutex_init(&buffer.lock);
    return 0;
}

static void free_ring_buffer(void) {
    if (buffer.data) {
        kfree(buffer.data);
        buffer.data = NULL;
    }
}

static ssize_t ring_buffer_write(const char __user *user_data, size_t count) {
    size_t space, to_write;
    mutex_lock(&buffer.lock);

    space = (buffer.head >= buffer.tail) ? 
            (buffer.size - (buffer.head - buffer.tail)) : 
            (buffer.tail - buffer.head - 1);
    to_write = min(count, space);

    if (to_write == 0) {
        mutex_unlock(&buffer.lock);
        return -ENOSPC;
    }

    if (buffer.head + to_write <= buffer.size) {
        if (copy_from_user(buffer.data + buffer.head, user_data, to_write)) {
            mutex_unlock(&buffer.lock);
            return -EFAULT;
        }
        buffer.head += to_write;
    } else {
        size_t first_part = buffer.size - buffer.head;
        if (copy_from_user(buffer.data + buffer.head, user_data, first_part)) {
            mutex_unlock(&buffer.lock);
            return -EFAULT;
        }
        if (copy_from_user(buffer.data, user_data + first_part, to_write - first_part)) {
            mutex_unlock(&buffer.lock);
            return -EFAULT;
        }
        buffer.head = to_write - first_part;
    }

    mutex_unlock(&buffer.lock);
    return to_write;
}

static ssize_t ring_buffer_read(char __user *user_data, size_t count, loff_t *offset) {
    size_t available, to_read;
    mutex_lock(&buffer.lock);

    available = (buffer.head >= buffer.tail) ? 
                (buffer.head - buffer.tail) : 
                (buffer.size - buffer.tail + buffer.head);
    to_read = min(count, available);

    if (to_read == 0) {
        mutex_unlock(&buffer.lock);
        return 0;
    }

    if (buffer.tail + to_read <= buffer.size) {
        if (copy_to_user(user_data, buffer.data + buffer.tail, to_read)) {
            mutex_unlock(&buffer.lock);
            return -EFAULT;
        }
        buffer.tail += to_read;
    } else {
        size_t first_part = buffer.size - buffer.tail;
        if (copy_to_user(user_data, buffer.data + buffer.tail, first_part)) {
            mutex_unlock(&buffer.lock);
            return -EFAULT;
        }
        if (copy_to_user(user_data + first_part, buffer.data, to_read - first_part)) {
            mutex_unlock(&buffer.lock);
            return -EFAULT;
        }
        buffer.tail = to_read - first_part;
    }

    mutex_unlock(&buffer.lock);
    *offset += to_read;
    return to_read;
}

static void simulate_mouse_data(void) {
    char event_str[100];
    int event_len;
    int x_value = get_random_long() % 10 - 5;
    int y_value = get_random_long() % 10 - 5;

    mutex_lock(&buffer.lock);
    switch (display_mode) {
        case 0:
            event_len = snprintf(event_str, sizeof(event_str), "MOUSE_X:%d\n", x_value);
            break;
        case 1:
            event_len = snprintf(event_str, sizeof(event_str), "MOUSE_Y:%d\n", y_value);
            break;
        case 2:
        default:
            event_len = snprintf(event_str, sizeof(event_str), "MOUSE_X:%d\nMOUSE_Y:%d\n", x_value, y_value);
            break;
    }

    size_t space = (buffer.head >= buffer.tail) ? 
                   (buffer.size - (buffer.head - buffer.tail)) : 
                   (buffer.tail - buffer.head - 1);
    if (event_len <= space) {
        if (buffer.head + event_len <= buffer.size) {
            memcpy(buffer.data + buffer.head, event_str, event_len);
            buffer.head += event_len;
        } else {
            size_t first_part = buffer.size - buffer.head;
            memcpy(buffer.data + buffer.head, event_str, first_part);
            memcpy(buffer.data, event_str + first_part, event_len - first_part);
            buffer.head = event_len - first_part;
        }
        event_count++;
    }
    mutex_unlock(&buffer.lock);
}

static int mouse_open(struct inode *inode, struct file *file) {
    simulate_mouse_data();
    return 0;
}

static int mouse_release(struct inode *inode, struct file *file) {
    return 0;
}

static ssize_t mouse_read(struct file *file, char __user *buf, size_t len, loff_t *offset) {
    return ring_buffer_read(buf, len, offset);
}

static ssize_t mouse_write(struct file *file, const char __user *buf, size_t len, loff_t *offset) {
    return ring_buffer_write(buf, len);
}

static int __init mouse_driv_init(void) {
    int ret;

    ret = init_ring_buffer(buffer_size);
    if (ret < 0)
        return ret;

    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        free_ring_buffer();
        printk(KERN_ERR "mouse_driv: Failed to register chrdev\n");
        return major_number;
    }

    mouse_kobj = kobject_create_and_add("mouselog", kernel_kobj);
    if (!mouse_kobj) {
        unregister_chrdev(major_number, DEVICE_NAME);
        free_ring_buffer();
        printk(KERN_ERR "mouse_driv: Failed to create kobject\n");
        return -ENOMEM;
    }

    if (sysfs_create_group(mouse_kobj, &attr_group)) {
        kobject_put(mouse_kobj);
        unregister_chrdev(major_number, DEVICE_NAME);
        free_ring_buffer();
        printk(KERN_ERR "mouse_driv: Failed to create sysfs group\n");
        return -ENOMEM;
    }

    printk(KERN_INFO "mouse_driv: Initialized with major number %d\n", major_number);
    printk(KERN_INFO "Create device: 'sudo mknod /dev/%s c %d 0'\n", DEVICE_NAME, major_number);
    printk(KERN_INFO "Set permissions: 'sudo chmod 666 /dev/%s'\n", DEVICE_NAME);
    return 0;
}

static void __exit mouse_driv_exit(void) {
    sysfs_remove_group(mouse_kobj, &attr_group);
    kobject_put(mouse_kobj);
    unregister_chrdev(major_number, DEVICE_NAME);
    free_ring_buffer();
    printk(KERN_INFO "mouse_driv: Unloaded\n");
}

module_init(mouse_driv_init);
module_exit(mouse_driv_exit);