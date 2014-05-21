#ifndef __LIBCT_BACKEND_OPENVZ_H__
#define __LIBCT_BACKEND_OPENVZ_H__

#include <sys/ioctl.h>
#include "types.h"

#define VZCTLDEV		"/dev/vzctl"

#define VE_CREATE		 1	/* Create VE, VE_ENTER added automatically */
#define VE_EXCLUSIVE		 2	/* Fail if exists */
#define VE_ENTER		 4	/* Enter existing VE */
#define VE_TEST			 8	/* Test if VE exists */
#define VE_LOCK			16	/* Do not allow entering created VE */
#define VE_SKIPLOCK		32	/* Allow entering embrion VE */

typedef unsigned int envid_t;
#define VZ_ENVID_SUPER		0

struct vzctl_old_env_create {
	envid_t			veid;
	unsigned int		flags;
	u32			addr;
};
struct vzctl_mark_env_to_down {
	envid_t			veid;
};

#define VE_USE_MAJOR		010	/* Test MAJOR supplied in rule */
#define VE_USE_MINOR		030	/* Test MINOR supplied in rule */
#define VE_USE_MASK		030	/* Testing mask, VE_USE_MAJOR | VE_USE_MINOR */

struct vzctl_setdevperms {
	envid_t			veid;
	unsigned int		type;
	unsigned int		dev;
	unsigned int		mask;
};

#define VE_NETDEV_ADD		1
#define VE_NETDEV_DEL		2

struct vzctl_ve_netdev {
	envid_t			veid;
	int			op;
	char			dev_name;
};

#define VE_CONFIGURE_OS_RELEASE		2
#define VE_CONFIGURE_CREATE_PROC_LINK	4
#define VE_CONFIGURE_OPEN_TTY		5
#define VE_CONFIGURE_MOUNT_OPTIONS	7

struct vzctl_ve_configure {
	unsigned int		veid;
	unsigned int		key;
	unsigned int		val;
	unsigned int		size;
	char			data[0];
};

struct vzctl_ve_meminfo {
	envid_t			veid;
	unsigned long		val;
};

struct vzctl_env_create_cid {
	envid_t			veid;
	unsigned int		flags;
	u32			class_id;
};

struct vzctl_env_create {
	envid_t			veid;
	unsigned int		flags;
	u32			class_id;
};

struct env_create_param {
	u64			iptables_mask;
};

#define VZCTL_ENV_CREATE_DATA_MINLEN	sizeof(struct env_create_param)

struct env_create_param2 {
	u64			iptables_mask;
	u64			feature_mask;
	u32			total_vcpus;	/* 0 - don't care, same as in host */
};

struct env_create_param3 {
	u64			iptables_mask;
	u64			feature_mask;
	u32			total_vcpus;
	u32			pad;
	u64			known_features;
};

#define VE_FEATURE_SYSFS	(1ull << 0)
#define VE_FEATURE_NFS		(1ull << 1)
#define VE_FEATURE_DEF_PERMS	(1ull << 2)
#define VE_FEATURE_SIT          (1ull << 3)
#define VE_FEATURE_IPIP         (1ull << 4)
#define VE_FEATURE_PPP		(1ull << 5)
#define VE_FEATURE_IPGRE	(1ull << 6)
#define VE_FEATURE_BRIDGE	(1ull << 7)
#define VE_FEATURE_NFSD		(1ull << 8)

#define VE_FEATURES_OLD		(VE_FEATURE_SYSFS)
#define VE_FEATURES_DEF		(VE_FEATURE_SYSFS | VE_FEATURE_DEF_PERMS)

typedef struct env_create_param3 env_create_param_t;
#define VZCTL_ENV_CREATE_DATA_MAXLEN	sizeof(env_create_param_t)

struct vzctl_env_create_data {
	envid_t			veid;
	unsigned int		flags;
	u32			class_id;
	env_create_param_t	*data;
	int			datalen;
};

struct vz_load_avg {
	int			val_int;
	int			val_frac;
};

struct vz_cpu_stat {
	unsigned long		user_jif;
	unsigned long		nice_jif;
	unsigned long		system_jif;
	unsigned long		uptime_jif;
	u64			idle_clk;
	u64			strv_clk;
	u64			uptime_clk;
	struct vz_load_avg	avenrun[3];	/* loadavg data */
};

struct vzctl_cpustatctl {
	envid_t			veid;
	struct vz_cpu_stat	*cpustat;
};

#define VZCTLTYPE '.'
#define VZCTL_OLD_ENV_CREATE		_IOW(VZCTLTYPE,  0,	struct vzctl_old_env_create)
#define VZCTL_MARK_ENV_TO_DOWN		_IOW(VZCTLTYPE,  1,	struct vzctl_mark_env_to_down)
#define VZCTL_SETDEVPERMS		_IOW(VZCTLTYPE,  2,	struct vzctl_setdevperms)
#define VZCTL_ENV_CREATE_CID		_IOW(VZCTLTYPE,  4,	struct vzctl_env_create_cid)
#define VZCTL_ENV_CREATE		_IOW(VZCTLTYPE,  5,	struct vzctl_env_create)
#define VZCTL_GET_CPU_STAT		_IOW(VZCTLTYPE,  6,	struct vzctl_cpustatctl)
#define VZCTL_ENV_CREATE_DATA		_IOW(VZCTLTYPE, 10,	struct vzctl_env_create_data)
#define VZCTL_VE_NETDEV			_IOW(VZCTLTYPE, 11,	struct vzctl_ve_netdev)
#define VZCTL_VE_MEMINFO		_IOW(VZCTLTYPE, 13,	struct vzctl_ve_meminfo)
#define VZCTL_VE_CONFIGURE		_IOW(VZCTLTYPE, 15,	struct vzctl_ve_configure)

/*
 * NOTE: No compat things here!
 */

#endif /* __LIBCT_BACKEND_OPENVZ_H__ */
