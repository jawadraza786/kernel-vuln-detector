/*
 * Sample: Stack Buffer Overflow + Missing Input Validation
 * Demonstrates insufficient bounds checking on user-supplied data
 */

#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/fs.h>

#define BUF_SIZE 64

static ssize_t vuln_write(struct file *file, const char __user *buf,
                           size_t count, loff_t *ppos)
{
    char kbuf[BUF_SIZE];

    /* BUG: count is not validated against BUF_SIZE before copy */
    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;

    /* BUG: no null termination guaranteed */
    printk(KERN_INFO "Received: %s\n", kbuf);

    return count;
}

static int vuln_open(struct inode *inode, struct file *file)
{
    return 0;
}

static const struct file_operations vuln_fops = {
    .owner  = THIS_MODULE,
    .open   = vuln_open,
    .write  = vuln_write,
};
