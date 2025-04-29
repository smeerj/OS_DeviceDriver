/**************************************************************
 * Class::  CSC-415-01 Fall 2024
 * Name::  Arjun Bhagat
 * Student ID::  917129686
 * GitHub-Name::  smeerj
 * Project:: Assignment 6 - Device Driver
 *
 * File:: cryptographer.c
 *
 * Description:: A driver that shifts the letters of a message for
 * encryption/decryption
 *
 **************************************************************/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/sched.h>

MODULE_AUTHOR("Arjun Bhagat");
MODULE_DESCRIPTION("A simple Caesar cipher: encryption and decryption");
MODULE_LICENSE("GPL");

#define MY_MAJOR 415
#define MY_MINOR 0
#define MESSAGE_SIZE 256
#define DEVICE_NAME "cryptographer"
#define CLASS_NAME "cryptographer_class"
#define REGION_NAME "cryptographer_device"

struct crypt_key
{
    char mssg[MESSAGE_SIZE];
    int shift;
};

static void caesar_cipher(char *mssg, int shift)
{
    char c;
    while ((c = *mssg))
    {
        if (c >= 'a' && c <= 'z')
        {
            *mssg = ((c - 'a' + shift) % 26 + 26) % 26 + 'a';
        }
        else if (c >= 'A' && c <= 'Z')
        {
            *mssg = ((c - 'A' + shift) % 26 + 26) % 26 + 'A';
        }
        mssg++;
    }
}

// Reads the message from the device to the user
static ssize_t device_read(struct file *file, char __user *buffer, size_t size, loff_t *offset)
{
    struct crypt_key *private_crypt_key = (struct crypt_key *)file->private_data;
    size_t length;

    if (!private_crypt_key)
    {
        printk(KERN_ERR "Private data is NULL\n");
        return -EFAULT;
    }

    length = strlen(private_crypt_key->mssg);
    if (copy_to_user(buffer, private_crypt_key->mssg, length + 1))
    {
        printk(KERN_ERR "Failed to copy data to user space\n");
        return -EFAULT;
    }

    printk(KERN_INFO "Message read by user: %s\n", private_crypt_key->mssg);
    *offset = 0;
    return length;
}

// Reads data from the user buffer into the device and encrypts/decrypts
static ssize_t device_write(struct file *file, const char __user *buffer, size_t size, loff_t *offset)
{
    struct crypt_key *private_crypt_key = (struct crypt_key *)file->private_data;

    if (!private_crypt_key)
    {
        printk(KERN_ERR "Private data is NULL\n");
        return -EFAULT;
    }

    if (size > MESSAGE_SIZE)
    {
        printk(KERN_ERR "Message size exceeds buffer limit\n");
        return -EINVAL;
    }

    // Copy mssg from user space
    if (copy_from_user(private_crypt_key->mssg, buffer, size))
    {
        printk(KERN_ERR "Failed to copy data from user space\n");
        return -EFAULT;
    }

    // Ensures null-termination of mssg and calls for encrpytion/decryption
    private_crypt_key->mssg[size] = '\0';
    caesar_cipher(private_crypt_key->mssg, private_crypt_key->shift);

    printk(KERN_INFO "Message written and encrypted: %s\n", private_crypt_key->mssg);
    return size;
}

static int device_open(struct inode *inode, struct file *file)
{
    struct crypt_key *private_crypt_key;

    // Allocate memory for private data
    private_crypt_key = vmalloc(sizeof(struct crypt_key));
    if (!private_crypt_key)
    {
        printk(KERN_ERR "Failed to allocate memory for private data\n");
        return -ENOMEM;
    }

    memset(private_crypt_key, 0, sizeof(struct crypt_key));
    // Set a default shift crypt_key
    private_crypt_key->shift = 5;

    file->private_data = private_crypt_key;
    printk(KERN_INFO "Device opened, memory allocated\n");

    return 0;
}

// Free the allocated memory
static int device_close(struct inode *inode, struct file *file)
{
    struct crypt_key *private_crypt_key = (struct crypt_key *)file->private_data;

    if (private_crypt_key)
    {
        vfree(private_crypt_key);
        printk(KERN_INFO "Memory freed, device closed\n");
    }
    else
    {
        printk(KERN_ERR "Private data already NULL\n");
    }

    return 0;
}

// Sets the shift value
static long device_ioctl(struct file *file, unsigned int command, unsigned long data)
{
    struct crypt_key *private_crypt_key = (struct crypt_key *)file->private_data;
    int user_shift;

    if (!private_crypt_key)
    {
        printk(KERN_ERR "Private data is NULL\n");
        return -EFAULT;
    }

    if (copy_from_user(&user_shift, (int __user *)data, sizeof(int)))
    {
        printk(KERN_ERR "Failed to copy shift value from user\n");
        return -EFAULT;
    }

    if (command == 3)
    {
        private_crypt_key->shift = user_shift % 26;
        printk(KERN_INFO "Set shift for encryption: %d\n", private_crypt_key->shift);
    }
    else if (command == 4)
    {
        private_crypt_key->shift = (-user_shift) % 26;
        printk(KERN_INFO "Set shift for decryption: %d\n", private_crypt_key->shift);
    }
    else
    {
        printk(KERN_ERR "Invalid command\n");
        return -EINVAL;
    }

    return 0;
}

struct file_operations device_fops = {
    .open = device_open,
    .release = device_close,
    .read = device_read,
    .write = device_write,
    .unlocked_ioctl = device_ioctl,
};

// Globals for initialization and clean up
static int major_number = -1;
static struct cdev device_file;
static int device_created = 0;
static struct class *device_class = NULL;

static int set_permissions(const struct device *dev, struct kobj_uevent_env *env)
{
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}

int init_module(void)
{
    if (alloc_chrdev_region(&major_number, 0, 1, REGION_NAME) < 0)
    {
        return -1;
    }

    if ((device_class = class_create(CLASS_NAME)) == NULL)
    {
        unregister_chrdev_region(major_number, 1);
        return -1;
    }

    device_class->dev_uevent = &set_permissions;

    if (device_create(device_class, NULL, major_number, NULL, DEVICE_NAME) == NULL)
    {
        class_destroy(device_class);
        unregister_chrdev_region(major_number, 1);
        return -1;
    }

    device_created = 1;

    cdev_init(&device_file, &device_fops);
    if (cdev_add(&device_file, major_number, 1) == -1)
    {
        device_destroy(device_class, major_number);
        class_destroy(device_class);
        unregister_chrdev_region(major_number, 1);
        return -1;
    }

    printk(KERN_INFO "Device successfully initialized\n");
    return 0;
}

void cleanup_module(void)
{
    device_destroy(device_class, major_number);
    cdev_del(&device_file);
    class_destroy(device_class);
    unregister_chrdev_region(major_number, 1);
    device_created = 0;
    device_class = NULL;
    printk(KERN_INFO "Device successfully removed\n");
}