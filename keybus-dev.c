/**
 * @file   keybusdev.c
 * @author Heikki Vesalainen
 * @date   2016-02-07
 * @version 1.0
 * @brief   A Linux Kernel Module to interact with keybus protocol using GPIO.
 */

// Insipired heavily by examples from Derek Molly (http://derekmolloy.ie)

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/gpio.h>
#include <linux/circ_buf.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <asm/bitops.h>
#include <linux/platform_data/bcm2708.h>

#include "keybus-protocol.h"

#define  DEVICE_NAME "keybus"
#define  CLASS_NAME  "keybus"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Heikki Vesalainen");
MODULE_DESCRIPTION("A character device to interact with the keybus protocol");
MODULE_VERSION("1.0");

// dev stuff
static int            major_number;
static struct class*  keybus_class  = NULL;
static struct device* keybus_device = NULL;

static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops = {
    .open = dev_open,
    .read = dev_read,
    .write = dev_write,
    .release = dev_release,
};

static DEFINE_MUTEX(keybus_mutex);

// gpio stuff
static bool active_low = 0;
module_param(active_low, bool, S_IRUGO);
MODULE_PARM_DESC(active_low, " Active low: Inverted = 1, Normal = 0");

static unsigned int gpio_clk = 24;
module_param(gpio_clk, uint, S_IRUGO);
MODULE_PARM_DESC(gpio_clk, " GPIO Clock number (default=24)");

static unsigned int gpio_data = 23;
module_param(gpio_data, uint, S_IRUGO);
MODULE_PARM_DESC(gpio_data, " GPIO Data number (default=23)");

// irq stuff
#define IRQ_HANDLER_INIT -2
#define IRQ_HANDLER_WAIT -1
#define IRQ_HANDLER_SYNC_MS 2

// circular buffer size, must be power of 2 [Documentation/circular-buffers.txt]
#define CIRCULAR_BUFFER_SIZE 128

// packet length is 12 (including length byte)
#define PACKET_MAX_LEN 12

static int irq_number;
static struct timespec ts_last;
static char keybus_status = 0;
static unsigned int crc_errors = 0;
static struct {
    char buffer[CIRCULAR_BUFFER_SIZE * PACKET_MAX_LEN];
    unsigned int head;
    unsigned int tail;
} in_packets;

static DECLARE_WAIT_QUEUE_HEAD(in_packets_wait_queue);

static unsigned int packet_count = 0;

static ssize_t ts_last_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%.2lu:%.2lu:%.2lu:%.9lu\n", (ts_last.tv_sec/3600)%24,
                   (ts_last.tv_sec/60) % 60, ts_last.tv_sec % 60, ts_last.tv_nsec );
}

static ssize_t packet_count_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%u\n", packet_count);
}

static ssize_t packet_buffer_count_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%u\n", CIRC_CNT(in_packets.head, in_packets.tail, CIRCULAR_BUFFER_SIZE));
}

static ssize_t keybus_status_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    int ret = parse_status_flags(keybus_status, buf);

    ret += sprintf(buf + ret, "\n");
    
    return ret;
}

/*
static ssize_t keybus_status_raw_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    int ret = parse_status_flags(keybus_status, buf);

    ret += sprintf(buf + ret, "\n");
    
    return ret;
}
*/

static ssize_t crc_errors_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%u\n", crc_errors);
}

static struct kobj_attribute ts_last_attr  = __ATTR_RO(ts_last);
static struct kobj_attribute packet_count_attr = __ATTR_RO(packet_count);
static struct kobj_attribute packet_buffer_count_attr = __ATTR_RO(packet_buffer_count);
static struct kobj_attribute keybus_status_attr  = __ATTR_RO(keybus_status);
//static struct kobj_attribute keybus_status_raw_attr  = __ATTR_RO(keybus_status_raw);
static struct kobj_attribute crc_errors_attr  = __ATTR_RO(crc_errors);


static struct attribute *keybus_attrs[] = {
    &ts_last_attr.attr,
    &packet_count_attr.attr,
    &packet_buffer_count_attr.attr,
    &keybus_status_attr.attr,
    //    &keybus_status_raw.attr.attr,
    &crc_errors_attr.attr,
    NULL,
};

static struct attribute_group attr_group = {
    .name = CLASS_NAME,
    .attrs = keybus_attrs,
};

static struct kobject *keybus_kobj;

static irqreturn_t clk_irq_handler(unsigned int irq, void *dev_id, struct pt_regs *regs);

static int __init keybus_init(void) {
    int result;
    unsigned long flags = GPIOF_DIR_IN | (active_low ? GPIOF_ACTIVE_LOW : 0);

    in_packets.head = 0;
    in_packets.tail = 0;

    result = gpio_request_one(gpio_clk, flags, "keybusdev_clk");
    if (result < 0) {
        printk(KERN_INFO "%s: invalid Clock GPIO %d: %d\n", DEVICE_NAME, gpio_clk, result);
        return result;
    }

    result = gpio_request_one(gpio_data, flags, "keybusdev_data");
    if (result < 0) {
        printk(KERN_INFO "%s: invalid Data GPIO %d: %d\n", DEVICE_NAME, gpio_data, result);
        return result;
    }

    flags = IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING; // TODO: does this follow active_low?
    irq_number = gpio_to_irq(gpio_clk);

    if (irq_number <= 0) {
        printk(KERN_ALERT "%s: failed to get number irq for clk %d\n", DEVICE_NAME, gpio_clk);
        // return -ENODEV;
        irq_number = 418;
    }

    result = request_irq(irq_number,
                         (irq_handler_t) clk_irq_handler,
                         flags, "keybusdev_clk_handler",
                         NULL);

    if (result < 0) {
        printk(KERN_ALERT "%s: failed to request irq for clk: %d\n", DEVICE_NAME, result);
        return result;
    }

    printk(KERN_INFO "%s: listening to irq %d\n", DEVICE_NAME, irq_number);

    // register attrs at /sys/keybus/
    keybus_kobj = kobject_create_and_add("keybus", kernel_kobj->parent);

    if (!keybus_kobj){
        printk(KERN_ALERT "%s: failed to create kobject mapping\n", DEVICE_NAME);
        return -ENOMEM;
    }

    result = sysfs_create_group(keybus_kobj, &attr_group);

    if (result) {
        printk(KERN_ALERT "%s: failed to create sysfs group\n", DEVICE_NAME);
        kobject_put(keybus_kobj);
        return result;
    }

    // dynamically allocate a major number for the device
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0){
        printk(KERN_ALERT "%s: failed to register a major number\n", DEVICE_NAME);
        return major_number;
    }

    // Register the device class
    keybus_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(keybus_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "%s: failed to register a device class\n", DEVICE_NAME);
        return PTR_ERR(keybus_class);
    }

    // Register the device driver as /dev/DEVICE_NAME
    keybus_device = device_create(keybus_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(keybus_device)) {
        class_destroy(keybus_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "%s: failed to create a device\n", DEVICE_NAME);
        return PTR_ERR(keybus_device);
    }

    printk(KERN_INFO "%s: device registered\n", DEVICE_NAME);

    return 0;
}

static void __exit keybus_exit(void){
    gpio_free(gpio_clk);
    gpio_free(gpio_data);
    free_irq(irq_number, NULL);
    kobject_put(keybus_kobj);
    device_destroy(keybus_class, MKDEV(major_number, 0));
    class_unregister(keybus_class);
    class_destroy(keybus_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    printk(KERN_INFO "%s: exit!\n", DEVICE_NAME);
}

#ifdef KEYBUSDEV_DEBUG
static void debug_print_packet(char* msg, char* packet) { // of length PACKET_MAX_LEN
  char buf[PACKET_MAX_LEN * 2 + 1];
  int i;
  char* bufptr = buf;

  for (i = 0; i < PACKET_MAX_LEN; i++) {
      bufptr += sprintf(bufptr, "%02X", packet[i]);
  }

  printk(KERN_INFO "%s: %s: %s\n", DEVICE_NAME, msg, buf);
}
#endif

static irqreturn_t clk_irq_handler(unsigned int irq, void *dev_id, struct pt_regs *regs) {
    static struct timespec ts_current, ts_diff;
    static int num_bits = IRQ_HANDLER_INIT;
    static int max_packet_bits = (PACKET_MAX_LEN - 1) * 8;
    static unsigned int byte_index = 0;
    static unsigned int previous_byte_index = PACKET_MAX_LEN; // just anything other than 0;

    int clk, data;
    unsigned int head, tail, index;

    if (num_bits == IRQ_HANDLER_INIT) {
        // just initialize ts_last and start waiting for a sync

        num_bits = IRQ_HANDLER_WAIT;

	getnstimeofday(&ts_last);
    } else {
	getnstimeofday(&ts_current);

	ts_diff = timespec_sub(ts_current, ts_last);

	ts_last = ts_current;

        clk = gpio_get_value(gpio_clk);

        head = in_packets.head;

	if (timespec_to_ns(&ts_diff) / 1000000 > IRQ_HANDLER_SYNC_MS) {
            // got sync
            if (num_bits >= 17 && in_packets.buffer[byte_index + 1] == 0x05) { // status
                keybus_status = in_packets.buffer[byte_index + 2] << 1 |
                    ((in_packets.buffer[byte_index + 3] & 0x80) >> 7);

                packet_count++;
            } else if (num_bits >= 8 && in_packets.buffer[byte_index + 1] != 0) { // sane packet
                // release the packet, unless it's a duplicate
                in_packets.buffer[byte_index] = (char) num_bits;

                if (memcmp(&in_packets.buffer[byte_index], &in_packets.buffer[previous_byte_index], PACKET_MAX_LEN) != 0) {
                    smp_store_release(&in_packets.head,
                                      (head + 1) & (CIRCULAR_BUFFER_SIZE - 1));

                    packet_count++;

                    previous_byte_index = byte_index;

                    wake_up_interruptible(&in_packets_wait_queue);
                }
            }

            tail = ACCESS_ONCE(in_packets.tail);

            if (CIRC_SPACE(head, tail, CIRCULAR_BUFFER_SIZE) >= 1) {
                // there is space, start next packet (at current head)

                num_bits = 0;

                byte_index = in_packets.head * PACKET_MAX_LEN;

                memset(&in_packets.buffer[byte_index], 0, PACKET_MAX_LEN);
            } else {
                // no space for packets, wait for next sync

                num_bits = IRQ_HANDLER_WAIT;
            }
	} else if (num_bits != IRQ_HANDLER_WAIT && clk == 0) {
            if (num_bits >= max_packet_bits) {
                // bad packet, too long, wait for next sync
                printk(KERN_ALERT "%s: Buffer overrun\n", DEVICE_NAME);

                num_bits = IRQ_HANDLER_WAIT;
            } else {
                // more data

                index = byte_index + 1 + (num_bits >> 3);

                data = gpio_get_value(gpio_data) == 0 ? 1 : 0;

                in_packets.buffer[index] =
                    in_packets.buffer[index] | (data << (7 - (num_bits & 0x7)));

                num_bits++;
            }

        } // else wait for sync
    }

    return IRQ_HANDLED;
}

/*
static void flush_in_packets(void) {
    while (1) {
        unsigned int head = smp_load_acquire(&in_packets.head);
        unsigned int tail = in_packets.tail;

        if (CIRC_CNT(head, tail, CIRCULAR_BUFFER_SIZE) > 1) {
            smp_store_release(&in_packets.tail,
                              (tail + 1) & (CIRCULAR_BUFFER_SIZE - 1));
        } else {
            break;
        }
    }
}
*/

static int read_in_packet(char* buffer) {
    unsigned int head = smp_load_acquire(&in_packets.head);
    unsigned int tail = in_packets.tail;
    unsigned int count = CIRC_CNT(head, tail, CIRCULAR_BUFFER_SIZE);

    if (count >= 1) {
        memcpy(buffer, &in_packets.buffer[tail * PACKET_MAX_LEN], PACKET_MAX_LEN);

        smp_store_release(&in_packets.tail,
                          (tail + 1) & (CIRCULAR_BUFFER_SIZE - 1));

        return buffer[0];
    } else {
        return 0;
    }
}

/**
 * Called when user opens our device.
 * @param inodep A pointer to an inode object (defined in linux/fs.h)
 * @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_open(struct inode *inodep, struct file *filep){
    if (!mutex_trylock(&keybus_mutex)) {
        printk(KERN_ALERT "%s: device in use by another process", DEVICE_NAME);
        return -EBUSY;
    } else {
        return 0;
    }
}

/**
 * Called when user tries to read from our device
 * @param filep A pointer to a file object (defined in linux/fs.h)
 * @param buffer The pointer to the buffer to which this function writes the data
 * @param len The length of the b
 * @param offset The offset if required
 */
static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
    char packet[PACKET_MAX_LEN];
    char *buf;
    int msglen, ret, crc_error;

    if (*offset != 0) return 0;

    packet[0] = 0;

    // TODO: filtering and formatting really belongs in userland, not here in the module

    while (packet[0] == 0 || !is_interesting_packet(&packet[1])) {
        ret = wait_event_interruptible(in_packets_wait_queue, read_in_packet(packet) > 0);
    
        if (ret) {
            // interrupted
            return ret;
        }
    }

    buf = kmalloc(len, GFP_KERNEL);

    if (!buf) {
        printk(KERN_ALERT "%s: Could not allocate %d bytes of memory", DEVICE_NAME, len);
        return -EFAULT;
    }

    msglen = packet_to_bits(&packet[1], buf, packet[0], packet[1] != 0x11);

    while (msglen < 110) {
      // align to 110 chars
      buf[msglen++] = ' ';
    }

    msglen += sprintf(&buf[msglen], "| ");

    msglen += parse_keybus(&packet[1], &buf[msglen], packet[0], &crc_error);

    if (crc_error > 0) {
      crc_errors++;
    }

    ret = copy_to_user(buffer, buf, msglen);

    buffer += ret;

    kfree(buf);

    if (ret == 0) {
        *offset = msglen;

        return msglen;
    } else {
        printk(KERN_ALERT "%s: Failed to send %d bytes to the user\n", DEVICE_NAME, msglen);
        return -EFAULT;
    }
}

/**
 * Called when user tries to write to our device
 * @param filep A pointer to a file object
 * @param buffer The buffer to that contains the string to write to the device
 * @param len The length of the array of data that is being passed in the const char buffer
 * @param offset The offset if required
 */
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
    return -EFAULT;
}

/**
 * Called when user closes our device.
 */
static int dev_release(struct inode *inodep, struct file *filep){
    mutex_unlock(&keybus_mutex);
    return 0;
}

module_init(keybus_init);
module_exit(keybus_exit);
