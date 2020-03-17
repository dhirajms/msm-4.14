// SPDX-License-Identifier: GPL-2.0-only

/* This header file is written only to introduce /proc/touchpanel which is
 * required by OxygenOS, to RW screen gestures nodes
 * Author = Panchajanya1999 <panchajanya@azure-dev.live>
 */

#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <asm/types.h>

// We are keeping 4kB of data
#define DATA_SIZE 4096

// Name of the directory under /proc
#define DIR_NAME "touchpanel"

struct proc_dir_entry *NVT_proc;
struct proc_dir_entry *NVT_proc_tmp;
int len;
char *msg = NULL;

static ssize_t ts_proc_write(struct file *filp, const char __user *buffer, size_t count, loff_t *pos)
{
	int i;
    char *data = PDE_DATA(file_inode(filp));

    if (count > DATA_SIZE) {
        return -EFAULT;
    }

    printk(KERN_INFO "Writing to proc");
    if (copy_from_user(data, buffer, count)) {
        return -EFAULT;
    }

    data[count-1] = '\0';

    *pos = (int) count;
    len = count-1;

    return count;
}

static ssize_t ts_proc_read(struct file *filp,char *buf, size_t count, loff_t *offp )
{
    int err;
    char *data = PDE_DATA(file_inode(filp));

    if ((int) (*offp) > len) {
        return 0;
    }

    printk(KERN_INFO "Reading the proc entry, len of the file is %d", len);
    if(!(data)) {
        printk(KERN_INFO "NULL DATA");
        return 0;
    }

    if (count == 0) {
        printk(KERN_INFO "Read of size zero, doing nothing.");
        return count;
    } else {
        printk(KERN_INFO "Read of size %d", (int) count);
    }

    count = len + 1; // +1 to read the \0
    err = copy_to_user(buf, data, count); // +1 for \0
    printk(KERN_INFO "Read data : %s", buf);
    *offp = count;

    if (err) {
        printk(KERN_INFO "Error in copying data.");
    } else {
        printk(KERN_INFO "Successfully copied data.");
    }

    return count;
}

/*
 * The file_operations structure. This is the glue layer which associates the
 * proc entry to the read and write operations.
 */
struct file_operations proc_fops = {
    .read = ts_proc_read,
    .write = ts_proc_write,
};

/* Function to create a new proc entry */

int create_new_proc_entry(void) {
	int i;
	char *DATA = "1";
	len = strlen(DATA);
	msg = kmalloc((size_t) DATA_SIZE, GFP_KERNEL);
	if (msg != NULL) {
        printk(KERN_INFO "Allocated memory for msg");
    } else {
        return -1;
    }

	strncpy(msg, DATA, len+1);
	msg[len+1] = '\0';

	// Create a proc directory
	NVT_proc = proc_mkdir(DIR_NAME, NULL);
	if (NVT_proc == NULL) {
		NVT_ERR("OOS: OOS_proc: Failed to create touchpanel entry!\n");
		return -ENOMEM;
	} else {
		NVT_LOG("OOS: OOS_proc: Created touchpanel entry!\n");
	}

	// Create a entry in /proc
	NVT_proc_tmp = proc_create_data("gesture_enable", 0666, NVT_proc, &proc_fops, msg);
	if (NVT_proc_tmp == NULL) {
		NVT_ERR("OOS: OOS_proc_tmp: Failed to create /proc/touchpanel/gesture_enable entry!\n");
		return -ENOMEM;
	} else {
		NVT_LOG("OOS: OOS_proc_tmp: Created /proc/touchpanel/gesture_enable entry!\n");
	}

	return -1;
}

/* The usual init function */

int proc_init(void) {
	if (create_new_proc_entry()) {
        return -1;
    }
    return 0;
}

/* The usual exit | cleanup function */
void proc_cleanup(void) {
	remove_proc_entry(DIR_NAME, NULL);
}
