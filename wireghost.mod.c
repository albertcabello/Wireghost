#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xd2901226, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x84f43e8d, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x754d539c, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0x2124474, __VMLINUX_SYMBOL_STR(ip_send_check) },
	{ 0xe4a30d0e, __VMLINUX_SYMBOL_STR(nf_register_hook) },
	{ 0x55dee550, __VMLINUX_SYMBOL_STR(seq_read) },
	{ 0x27cb7ea0, __VMLINUX_SYMBOL_STR(proc_remove) },
	{ 0xb97a8d7, __VMLINUX_SYMBOL_STR(param_ops_charp) },
	{ 0x2e2b40d2, __VMLINUX_SYMBOL_STR(strncat) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x9166fada, __VMLINUX_SYMBOL_STR(strncpy) },
	{ 0x1e6d26a8, __VMLINUX_SYMBOL_STR(strstr) },
	{ 0x61651be, __VMLINUX_SYMBOL_STR(strcat) },
	{ 0xe16bca7a, __VMLINUX_SYMBOL_STR(pskb_expand_head) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0x910e0dc, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0x55da9811, __VMLINUX_SYMBOL_STR(proc_create_data) },
	{ 0xcf8262b6, __VMLINUX_SYMBOL_STR(nf_unregister_hook) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x69acdf38, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0xe113bbbc, __VMLINUX_SYMBOL_STR(csum_partial) },
	{ 0xe8914f18, __VMLINUX_SYMBOL_STR(skb_put) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "E2ED9E4F0C03EA78F7E3B1D");
