/*
 * Created 190414 lynnl
 */

#include <kern/locks.h>
#include <kern/lock_group.h>

#include <libkern/libkern.h>
#include <libkern/OSMalloc.h>

#include <mach/kmod.h>
#include <mach/mach_types.h>

#include "kauth.h"
#include "kextlog.h"
#include "log_kctl.h"
#include "log_sysctl.h"
#include "utils.h"

#pragma mark -
#pragma mark Local variables

OSMallocTag bsd_kext_log_malloc_tag = NULL;
lck_grp_t * bsd_kext_log_lck_grp = NULL;
lck_mtx_t * bsd_kext_log_hash_mutex = NULL;

#pragma mark -
#pragma mark Local function prototypes

kern_return_t bsd_kext_log_init(void);
void bsd_kext_log_fini(void);
kern_return_t bsd_kext_log_start(kmod_info_t *, void *);
kern_return_t bsd_kext_log_stop(kmod_info_t *, void *);

#pragma mark -
#pragma mark Kext init/fini routines

kern_return_t
bsd_kext_log_init(void)
{
    kern_return_t ret = KERN_SUCCESS;

    bsd_kext_log_malloc_tag = OSMalloc_Tagalloc(BUNDLEID_S, OSMT_DEFAULT);
    if (bsd_kext_log_malloc_tag == NULL) {
        goto out_fail;
    }

    bsd_kext_log_hash_mutex = lck_mtx_alloc_init(bsd_kext_log_malloc_tag, LCK_ATTR_NULL);
    if (bsd_kext_log_hash_mutex == NULL) {
        goto out_fail;
    }

    bsd_kext_log_lck_grp = lck_grp_alloc_init(BUNDLEID_S, LCK_ATTR_NULL);
    if (bsd_kext_log_hash_mutex == NULL) {
        goto out_fail;
    }

    if (ret != KERN_SUCCESS) {
        bsd_kext_log_fini();
        goto out_fail;
    }

out_exit:
    return ret;

out_fail:
    ret = KERN_FAILURE;
    goto out_exit;
}

void
bsd_kext_log_fini(void)
{
    if (bsd_kext_log_malloc_tag != NULL) {
        OSMalloc_Tagfree(bsd_kext_log_malloc_tag);
        bsd_kext_log_malloc_tag = NULL;
        goto out_exit;
    }

    if (bsd_kext_log_lck_grp != NULL) {
        lck_grp_free(bsd_kext_log_lck_grp);
        bsd_kext_log_lck_grp = NULL;
        goto out_exit;
    }

    if (bsd_kext_log_hash_mutex != NULL) {
        lck_mtx_free(bsd_kext_log_hash_mutex, bsd_kext_log_lck_grp);
        bsd_kext_log_hash_mutex = NULL;
        goto out_exit;
    }

out_exit:
    return;
}

#pragma mark -
#pragma mark Kext start/stop routines

kern_return_t
bsd_kext_log_start(kmod_info_t *ki, void *d)
{
    kern_return_t ret;

    UNUSED(ki, d);

    ret = bsd_kext_log_init();
    if (ret != KERN_SUCCESS) {
        goto out_fail;
    }

    log_sysctl_register();

    ret = kauth_register();
    if (ret != KERN_SUCCESS) {
        goto out_fail;
    }

    ret = log_kctl_register();
    if (ret != KERN_SUCCESS) {
        kauth_deregister();
        goto out_fail;
    }

    if (ret == KERN_SUCCESS) {
        goto out_exit;
    }

out_exit:
    return ret;

out_fail:
    bsd_kext_log_fini();
    ret = KERN_FAILURE;
    goto out_exit;
}

kern_return_t
bsd_kext_log_stop(kmod_info_t *ki, void *d)
{
    kern_return_t ret;

    UNUSED(ki, d);

    ret = log_kctl_deregister();
    if (ret == KERN_SUCCESS) {
        kauth_deregister();
        log_sysctl_deregister();
        util_massert();
        bsd_kext_log_fini();
    } else {
        bsd_kext_log_fini();
        goto out_fail;
    }

out_exit:
    return ret;

out_fail:
    ret = KERN_FAILURE;
    goto out_exit;
}

KMOD_EXPLICIT_DECL(BUNDLEID_S, KEXTBUILD_S, bsd_kext_log_start, bsd_kext_log_stop)

/* If you intended to write a kext library  NULLify _realmain and _antimain */
__private_extern__ kmod_start_func_t *_realmain = bsd_kext_log_start;
__private_extern__ kmod_stop_func_t *_antimain = bsd_kext_log_stop;

__private_extern__ int _kext_apple_cc = __APPLE_CC__;

