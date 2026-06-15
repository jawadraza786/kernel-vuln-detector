/*
 * Sample: Use-After-Free vulnerability
 * Demonstrates improper memory management in a kernel driver context
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>

struct device_ctx {
    int id;
    char name[64];
    void (*callback)(void);
};

static struct device_ctx *ctx;

void device_release(struct device_ctx *dev)
{
    kfree(dev);
    /* BUG: dev is freed but the global pointer is not nulled */
}

void device_callback_trigger(void)
{
    /* BUG: ctx may have been freed — use-after-free */
    if (ctx->callback) {
        ctx->callback();
    }
}

int device_init(void)
{
    ctx = kmalloc(sizeof(struct device_ctx), GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;

    ctx->id = 1;
    ctx->callback = NULL;
    return 0;
}

void device_exit(void)
{
    device_release(ctx);
    /* ctx is dangling here */
    device_callback_trigger();  /* UAF: triggers on freed memory */
}
   



