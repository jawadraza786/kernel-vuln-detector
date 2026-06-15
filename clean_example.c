/*
 * Sample: Clean implementation
 * Demonstrates proper bounds checking, null validation, and memory hygiene
 */

#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>

#define BUF_SIZE 64

static ssize_t safe_write(struct file *file, const char __user *buf,
                           size_t count, loff_t *ppos)
{
    char kbuf[BUF_SIZE];
    size_t copy_len;

    /* Validate input length before copy */
    if (count == 0)
        return 0;

    copy_len = min(count, (size_t)(BUF_SIZE - 1));

    if (copy_from_user(kbuf, buf, copy_len))
        return -EFAULT;

    /* Ensure null termination */
    kbuf[copy_len] = '\0';

    printk(KERN_INFO "Received: %s\n", kbuf);

    return copy_len;
}

struct safe_ctx *safe_alloc(void)
{
    struct safe_ctx *ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return NULL;

    memset(ctx, 0, sizeof(*ctx));
    return ctx;
}

void safe_free(struct safe_ctx **ctx)
{
    if (!ctx || !*ctx)
        return;

    kfree(*ctx);
    *ctx = NULL;  /* Null the pointer after free to prevent UAF */
}
