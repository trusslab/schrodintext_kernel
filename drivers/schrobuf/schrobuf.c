/* 
 * SchrodinText - Strong Protection of Sensitive Textual Content of Mobile Applications
 * File: schrobuf.c
 * Description: Kernel module for Xen communication
 *
 * Copyright (c) 2016-2019 University of California - Irvine, Irvine, USA
 * All rights reserved.
 *
 * Authors: Ardalan Amiri Sani
 *	    Nicholas Wei
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    substantially similar to the "NO WARRANTY" disclaimer below
 *    ("Disclaimer") and any redistribution must be conditioned upon
 *    including a substantially similar Disclaimer requirement for further
 *    binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 */
 
 
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <xen/xen.h>
#include <asm/xen/hypercall.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <asm/cacheflush.h> /* clflush_cache_range() */
#include <asm/tlbflush.h> /* flush_tlb_all() */
#include <asm/pgtable.h> /* flush_tlb_all() */

#ifdef CONFIG_ARM64
#define IN_KERNEL	1
#endif /* CONFIG_ARM64 */

#define PRINTK0(fmt, args...) printk("%s: " fmt, __func__, ##args)
#define PRINTK_ERR(fmt, args...) printk("%s: Error: " fmt, __func__, ##args)

/* ioctl */
#define SCHROBUF_REGISTER	5
#define SCHROBUF_UNREGISTER	6
#define SCHROBUF_RESOLVE		7

struct schrobuf_register_ioctl {
	unsigned long buffers_mem;
	unsigned int num_buffers;
	unsigned int buffer_size;
	unsigned long encrypted_text;
	unsigned int text_len;
	unsigned int text_buf_size;
	unsigned long char_widths;
	unsigned int char_widths_size;
};

struct schrobuf_resolve_ioctl {
    unsigned long dst_addr;
    unsigned int text_pos;
	unsigned int px;			// pixel coordinate on x-axis
	unsigned int fb_bytespp;
    bool conditional_char;
	bool trust_addr;			// tell Xen to composite text at dst_addr, do not perform adjustment (set true for monospaced fonts, false otherwise)
	bool last_res; 				// last resolve for the current text_pos?
};

#define XENMEM_schrobuf_register		37
#define XENMEM_schrobuf_unregister	38
#define XENMEM_schrobuf_resolve		39

struct xen_schrobuf_register_data {
	uint64_t handle;
	uint64_t buffers_mem;
	uint32_t num_buffers;
	uint32_t buffer_size;
	uint64_t encrypted_text;
	uint32_t text_len;
	uint32_t text_buf_size;
	uint64_t char_widths;
	uint32_t char_widths_size;
};

struct xen_schrobuf_unregister_data {
	uint64_t handle;
};

struct xen_schrobuf_resolve_data {
	uint64_t handle;
	uint64_t dst_paddr;
	uint32_t text_pos;
	uint32_t px;
	uint32_t fb_bytespp;
	bool conditional_char;
	bool trust_addr;
	bool last_res;
};

#define OPENED		1
#define CLOSED		0
#define DEVICE_NAME "schrobuf"

static struct class *schrobuf_class = NULL;
static struct cdev schrobuf_cdev;
static struct cdev* schrobuf_cdev_test;

static unsigned int major;

static int schrobuf_open(struct inode *inode, struct file *file)
{
	// No special actions needed
	return 0;
}

static int schrobuf_release(struct inode *inode, struct file *file)
{
	// No special actions needed
	return 0;
}

static ssize_t schrobuf_read(struct file *file, char *buf,
			  size_t size, loff_t *off)
{
	// No special actions needed
	return 0;
}

#ifdef CONFIG_ARM64
/* modified from arch/arm64/mm/fault.c */
pte_t *schrobuf_get_pte(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;

	if (!mm)
		mm = &init_mm;

	pgd = pgd_offset(mm, addr);

	do {
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;

		if (pgd_none(*pgd) || pgd_bad(*pgd))
			break;

		pud = pud_offset(pgd, addr);
		if (pud_none(*pud) || pud_bad(*pud))
			break;

		pmd = pmd_offset(pud, addr);
		if (pmd_none(*pmd) || pmd_bad(*pmd))
			break;

		pte = pte_offset_map(pmd, addr);
		return pte;
	} while(0);

	return NULL;
}
#elif CONFIG_ARM
/* modified from arch/arm/mm/fault.c */
/*
 * This is useful to dump out the page tables associated with
 * 'addr' in mm 'mm'.
 */
pte_t *schrobuf_get_pte(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;

	if (!mm)
		mm = &init_mm;

	pgd = pgd_offset(mm, addr);

	do {
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;

		if (pgd_none(*pgd))
			break;

		pud = pud_offset(pgd, addr);
		if (PTRS_PER_PUD != 1)
			PRINTK0(", *pud=%08lx", (long unsigned int) pud_val(*pud));

		if (pud_none(*pud))
			break;

		pmd = pmd_offset(pud, addr);
		if (PTRS_PER_PMD != 1)
			PRINTK0(", *pmd=%08llx", (long long) pmd_val(*pmd));

		if (pmd_none(*pmd))
			break;

		/* We must not map this if we have highmem enabled */
		if (PageHighMem(pfn_to_page(pmd_val(*pmd) >> PAGE_SHIFT)))
			break;

		pte = pte_offset_map(pmd, addr);
		return pte;
	} while(0);

	return NULL;
}

#endif /* CONFIG_ARM64/CONFIG_ARM */

static long schrobuf_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret;
	
	switch (cmd)
	{
	case SCHROBUF_REGISTER:
	{
		struct schrobuf_register_ioctl data;
		struct xen_schrobuf_register_data hyp_data;
		void *k_cipher = NULL;
		uint8_t *k_mBuffersMem = NULL;
		int* k_char_widths = NULL;
		unsigned int c_last_index = 0;

		ret = copy_from_user(&data, (void *) arg, sizeof(data));

		// Copy encrypted_text and buffers_mem from userspace to kernel allocated buffer
		k_cipher = kmalloc(data.text_buf_size, GFP_KERNEL);
		if (k_cipher == NULL) {
			PRINTK0("Error: Could not allocate kernel buffer for cipher. Exiting (-1).\n");
			return -1;
		}
		if (copy_from_user(k_cipher, (void*) data.encrypted_text, data.text_buf_size) != 0) {
			PRINTK0("Error: Could not copy_from_user cipher. Returning -EFAULT.\n");
			kfree(k_cipher);
			return -EFAULT;
		}
		
		k_mBuffersMem = kmalloc(data.num_buffers * data.buffer_size, GFP_KERNEL);
		if (k_mBuffersMem == NULL) {
			kfree(k_cipher);
			PRINTK0("Error: Could not allocate kernel mBuffersMem. Exiting (-1).\n");
			return -1;
		}
		if (copy_from_user(k_mBuffersMem, (uint8_t *) data.buffers_mem, data.num_buffers * data.buffer_size) != 0) {
			PRINTK0("Could not copy_from_user data.buffers_mem. Returning -EFAULT.\n");
			kfree(k_cipher);
			kfree(k_mBuffersMem);
			return -EFAULT;
		}

		if (data.char_widths_size && data.char_widths) {
			k_char_widths = kmalloc(data.char_widths_size * sizeof(int), GFP_KERNEL);
			if (k_char_widths == NULL) {
				kfree(k_cipher);
				kfree(k_mBuffersMem);
				PRINTK0("Error: Could not allocate kernel char_widths. Exiting (-1).\n");
				return -1;
			}
			if (copy_from_user(k_char_widths, (int*) data.char_widths, data.char_widths_size * sizeof(int)) != 0) {
				PRINTK0("Could not copy_from_user data.char_widths. Returning -EFAULT.\n");
				kfree(k_cipher);
				kfree(k_mBuffersMem);
				kfree(k_char_widths);
				return -EFAULT;
			}
		}		 

		// Replace data.buffers_mem with our new kernel allocated buffer to send to Xen; num_buffers/buffer_size don't change
		hyp_data.buffers_mem = (uint64_t) k_mBuffersMem;
		hyp_data.num_buffers = (uint32_t) data.num_buffers;
		hyp_data.buffer_size = (uint32_t) data.buffer_size;
		hyp_data.encrypted_text = (uint64_t) k_cipher;
		hyp_data.text_len = (uint32_t) data.text_len;
		hyp_data.text_buf_size = (uint32_t) data.text_buf_size;
		hyp_data.char_widths = k_char_widths ? (uint64_t) k_char_widths : 0;
		hyp_data.char_widths_size = (uint32_t) data.char_widths_size;
		
		file->private_data = (void *) &file->private_data;
		hyp_data.handle = (uint64_t) file->private_data;

		// Perform hypercall
		ret = HYPERVISOR_memory_op(XENMEM_schrobuf_register, &hyp_data);
		
		// Can free cipher here regardless of hypercall return value
		kfree(k_cipher);
		if (ret) {
			file->private_data = NULL;
			return ret;
		}		
		return 0;
	}

	case SCHROBUF_UNREGISTER:
	{
		struct xen_schrobuf_unregister_data hyp_data;
		if (!file->private_data) {
			PRINTK_ERR("Error: schrobuf is NULL\n");
			return -EINVAL;
		}
		hyp_data.handle = (uint64_t) file->private_data;

		ret = HYPERVISOR_memory_op(XENMEM_schrobuf_unregister, &hyp_data);

		return ret;
	}

	case SCHROBUF_RESOLVE:
	{
		struct schrobuf_resolve_ioctl data;
		struct xen_schrobuf_resolve_data hyp_data;
		unsigned long dst_paddr;
		pte_t *dst_pte;

		if (!file->private_data) {
			PRINTK_ERR("Error: schrobuf is NULL\n");
			return -EINVAL;
		}

		ret = copy_from_user(&data, (void *) arg, sizeof(data));

		dst_pte = schrobuf_get_pte(current->mm, data.dst_addr);
		if (!dst_pte) {
			PRINTK_ERR("Error: invalid address\n");
			return -EINVAL;
		}

		dst_paddr = (pte_pfn(*dst_pte) << PAGE_SHIFT) + (data.dst_addr & ~PAGE_MASK);

		hyp_data.handle = (uint64_t) file->private_data;
		hyp_data.dst_paddr = (uint64_t) dst_paddr;
		hyp_data.text_pos = (uint32_t) data.text_pos;
		hyp_data.px = (uint32_t) data.px;
		hyp_data.fb_bytespp = (uint32_t) data.fb_bytespp;
		hyp_data.conditional_char = data.conditional_char;
		hyp_data.trust_addr = data.trust_addr;
		hyp_data.last_res = data.last_res;		

		ret = HYPERVISOR_memory_op(XENMEM_schrobuf_resolve, &hyp_data);

		return ret;
	}
	
	default:
		PRINTK0("Invalid ioctl num used.\n");
		return -EINVAL;
			
	}

	return 0;
}

static struct file_operations schrobuf_fops = {
	.owner = THIS_MODULE,
	.read = schrobuf_read,
	.open = schrobuf_open,
	.release = schrobuf_release,
	.unlocked_ioctl = schrobuf_ioctl
};

#ifdef ACCESS_CHECK
static bool is_schrobuf_address(unsigned long addr, struct mm_struct *mm)
{
	struct protected_page *ppage = NULL, *p_tmp;

	list_for_each_entry_safe(ppage, p_tmp, &g_ppages, list) {

		if (ppage->orig_addr == (addr & PAGE_MASK)) {	
			return true;
		}
	}

	return false;
}

int __schrobuf_access_check(struct mm_struct *mm, unsigned long addr, unsigned int fsr,
                        struct pt_regs *regs, struct vm_area_struct *vma, int is_user_addr)
{
	bool is_schrobuf_addr;
	
	is_schrobuf_addr = is_schrobuf_address(addr, mm);

	if (is_user_addr == 0 || is_user_addr == 1) {
		if (is_schrobuf_addr) {
			PRINTK0("Error: found unexpected schrobuf addr = %#lx, is_user_addr = %d\n",
								(unsigned long) addr, is_user_addr);
			dump_stack();
		}

		return -EFAULT;
	}

	if (is_schrobuf_addr) {
		return -EFAULT;
	}

	return 0;
}


extern int (*schrobuf_access_check) (struct mm_struct *mm, unsigned long addr, unsigned int fsr,
                        struct pt_regs *regs, struct vm_area_struct *vma, int is_user_addr);
#endif /* ACCESS_CHECK */

#ifdef IN_KERNEL
int init_schrobuf(void)
#else /* IN_KERNEL */
static int __init init_schrobuf(void)
#endif /* IN_KERNEL */
{
	int err = 0;
	dev_t dev = 0;
	dev_t devno;
	struct device *device = NULL;

	err = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
	if (err < 0) {
		PRINTK_ERR("Error: Failed to allocated device number: %d\n", err);
		return err;
	}
	major = MAJOR(dev);
	
	/* Create device */
	schrobuf_class = class_create(THIS_MODULE, DEVICE_NAME);
	if (IS_ERR(schrobuf_class)) {
		err = PTR_ERR(schrobuf_class);
		PRINTK0("Failed to create class: %d\n", err);
		goto failed;
	}

	cdev_init(&schrobuf_cdev, &schrobuf_fops);
	schrobuf_cdev.owner = THIS_MODULE;

	/* We only need one device, so hard code minor number */
	devno = MKDEV(major, 0);
	err = cdev_add(&schrobuf_cdev, devno, 1);
	if (err)
	{
		PRINTK_ERR("Error: Unable to add character device: %d\n", err);
		class_destroy(schrobuf_class);
		goto failed;
	}

	device = device_create(schrobuf_class, NULL, devno, NULL, DEVICE_NAME);
	if (IS_ERR(device)) {
		err = PTR_ERR(device);
		PRINTK_ERR("Error: Unable to create device: %d\n", err);
		class_destroy(schrobuf_class);
		cdev_del(&schrobuf_cdev);
		goto failed;
	}

	printk("SchrodinText - /dev/schrobuf device create: %d\n", major);

#ifdef ACCESS_CHECK
	schrobuf_access_check = __schrobuf_access_check;
#endif /* ACCESS_CHECK */

	return 0;

failed:
	unregister_chrdev_region(MKDEV(major, 0), 1);
	return err;
}

#ifdef IN_KERNEL
static void cleanup_schrobuf(void)
#else /* IN_KERNEL */
static void __exit cleanup_schrobuf(void)
#endif /* IN_KERNEL */
{
	cdev_del(&schrobuf_cdev);
	device_destroy(schrobuf_class, MKDEV(major, 0));
	class_destroy(schrobuf_class);
	unregister_chrdev_region(MKDEV(major, 0), 1);
}

#ifdef IN_KERNEL
module_init(init_schrobuf);
module_exit(cleanup_schrobuf);
MODULE_LICENSE("GPLv2");
MODULE_AUTHOR("Ardalan Amiri Sani");
MODULE_AUTHOR("Nicholas Wei");
MODULE_DESCRIPTION("SchrodinText kernel module");
MODULE_VERSION("1.0");
#endif /* !IN_KERNEL */


