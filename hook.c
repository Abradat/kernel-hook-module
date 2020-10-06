/*
 * Hooking kernel functions using ftrace framework
 *
 * Copyright (c) 2018 ilammy
 */

#define pr_fmt(fmt) "ftrace_hook: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

MODULE_DESCRIPTION("Kernel Module for ftrace hook for encryption/decryption using rot13");
MODULE_AUTHOR("Shayan Khorsandi, Sajjad Aboutalebi");
MODULE_LICENSE("GPL");
static char __user *file_to_hook="f1";
module_param(file_to_hook, charp, S_IRUGO);
/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0
#define ROT 13

int in_path = 0;
/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = kallsyms_lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct pt_regs *regs)
{
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long) hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long) hook->function;
#endif
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION_SAFE.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION_SAFE
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

char *to_write;
char *to_read;
void rot13_encrypt(const char __user *buf)
{
	
	int c, e;
	int counter = 0;
	to_write = buf;
	char tmp = *(buf + counter);
	while(1)
	{
		tmp = *(buf + counter);
		if(tmp == '\0')
			break;
		c = (int)(tmp);
		if(c >='A' && c <='Z')
        {
            if((e = c + ROT) <= 'Z')
                // putchar(e);
				// tmp = e;
				*(to_write + counter) = e;
            else
            {
                   e = c - ROT;
                // putchar(e);
				// tmp = e;
				*(to_write + counter) = e;
            }
        }
		else if(c >='a' && c <='z')
        {
            if((e= c + ROT) <= 'z')
                // putchar(e);
				// tmp = e;
				*(to_write + counter) = e;
            else
            {
                e = c - ROT;
                // putchar(e);
				// tmp = e;
				*(to_write + counter) = e;
            }
        }
        // else
        //     // putchar(c);
		// 	// tmp = e;
		// 	*(to_write + counter) = e;
		counter = counter + 1;
		
	}
}
int number = 0;
int open_flag_for_write=0;
int flag_for_read=0;

static asmlinkage long (*real_sys_read)(unsigned int fd, char __user *buf, size_t count);

static asmlinkage long fh_sys_read(unsigned int fd, char __user *buf, size_t count)
{
	long ret;

	// if((fd == 3 && flag_for_read == 1))
	// {
	// 	pr_info("Going to Decrypt: %s", buf);
	// 	rot13_decrypt(buf);
	// 	pr_info("Decryption is Done.");
	// 	// pr_info("Decrypted String is: %s", to_read);
	// 	flag_for_read = 0;
	// 	ret = real_sys_read(fd, to_read, count);
	// }
	// else
    	ret = real_sys_read(fd, buf, count);

	return ret;
}

static asmlinkage long (*real_sys_open)(const char __user *filename,
				int flags, umode_t mode);

static asmlinkage long fh_sys_open(const char __user *filename, int flags, umode_t mode)
{
    long ret;
	int comp_result;
	comp_result = strcmp(filename, file_to_hook);
    if(comp_result == 0)
    {
		if(mode == 0666)
		{
			open_flag_for_write = 1;
			flag_for_read = 0;
		}
		else
		{
			open_flag_for_write = 0;
			flag_for_read = 1;
		}
		pr_info("File %s has been opened", file_to_hook);
		// pr_info("Value for open flag set to : %d", open_flag_for_write);
    }
	else
	{
		open_flag_for_write = 0;
		flag_for_read = 0;
	}
    ret = real_sys_open(filename, flags, mode);
    return ret;
}

static asmlinkage long (*real_sys_write)(unsigned int fd, const char __user *buf,
			  size_t count);

static asmlinkage long fh_sys_write(unsigned int fd, const char __user *buf, size_t count)
{
	long ret;
	if(fd == 1 && flag_for_read == 1 && open_flag_for_write == 0) 
	{
		pr_info("Going to Decrypt %s", buf);
		rot13_encrypt(buf);
		flag_for_read = 0;
		// flag_for_read = 1;
		ret = real_sys_write(fd, buf, count);
	}
	else if(fd == 3 && flag_for_read == 0 && open_flag_for_write == 1)
	{
		pr_info("Going to Encrypt %s", buf);
		rot13_encrypt(buf);
		// pr_info("Encrypted string is: %s", to_write);
		open_flag_for_write = 0;
		// flag_for_read = 1;
		ret = real_sys_write(fd, buf, count);
	}
	else
		ret = real_sys_write(fd, buf, count);
	return ret;
}

#define HOOK(_name, _function, _original)                    \
        {                                                    \
            .name = (_name),                                 \
            .function = (_function),                         \
            .original = (_original),                         \
        }

static struct ftrace_hook demo_hooks[] = {
	HOOK("sys_read",  fh_sys_read,  &real_sys_read),
    HOOK("sys_open",  fh_sys_open,  &real_sys_open),
	HOOK("sys_write",  fh_sys_write,  &real_sys_write),

};

static int fh_init(void)
{
	int err;

	err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (err)
		return err;

	pr_info("module loaded\n");
	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));

	pr_info("module unloaded\n");
}
module_exit(fh_exit);