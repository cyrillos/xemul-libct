#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <sys/ioctl.h>

#include "compiler.h"

#include "uapi/libct.h"

#include "xmalloc.h"
#include "session.h"
#include "cgroups.h"
#include "security.h"
#include "libct.h"
#include "list.h"
#include "util.h"
#include "net.h"
#include "ct.h"
#include "fs.h"

#include "vz.h"

typedef struct {
	struct container	ct;

	int			vzfd;
	envid_t			veid;
} vz_container_t;

typedef struct {
	struct libct_session	s;
	int			server_sk;
} vz_session_t;

static vz_session_t *s2vz(libct_session_t s)
{
	return container_of(s, vz_session_t, s);
}

static vz_container_t *cth2vz(ct_handler_t h)
{
	struct container *ct = container_of(h, struct container, h);
	return container_of(ct, vz_container_t, ct);
}

static enum ct_state vz_ct_get_state(ct_handler_t h)
{
	return cth2vz(h)->ct.state;
}

static void vz_ct_destroy(ct_handler_t h)
{
	vz_container_t *vz = cth2vz(h);
	struct container *ct = &vz->ct;

	if (vz->vzfd >= 0)
		close(vz->vzfd);

	cgroups_free(ct);
	fs_free(ct);
	net_release(ct);
	xfree(ct->name);
	xfree(ct->hostname);
	xfree(ct->domainname);
	xfree(ct->cgroup_sub);
	xfree(vz);
}

static const struct container_ops vz_ct_ops = {
	.spawn_cb		= NULL,
	.spawn_execve		= NULL,
	.enter_cb		= NULL,
	.enter_execve		= NULL,
	.kill			= NULL,
	.wait			= NULL,
	.get_state		= vz_ct_get_state,
	.set_nsmask		= NULL,
	.add_controller		= NULL,
	.config_controller	= NULL,
	.fs_set_root		= local_fs_set_root,
	.fs_set_private		= local_fs_set_private,
	.fs_add_mount		= local_add_mount,
	.fs_del_mount		= local_del_mount,
	.set_option		= NULL,
	.destroy		= vz_ct_destroy,
	.detach			= NULL,
	.net_add		= local_net_add,
	.net_del		= local_net_del,
	.uname			= NULL,
	.set_caps		= NULL,
};

static ct_handler_t vz_ct_create(libct_session_t s, char *name)
{
	struct vzctl_env_create env_create = { };
	vz_container_t *vz;
	int ret, retry = 3;

	vz = xmalloc(sizeof(*vz));
	if (!vz || ct_init(&vz->ct, name))
		goto err;

	vz->vzfd = -1;

	/*
	 * OpenVZ doesn't support symbolic names, but all VEs
	 * are identified by than named numeric VE id. Thus the
	 * name here must be a VE (container) number.
	 */
	vz->veid = (envid_t)atol(name);
	if (vz->veid == VZ_ENVID_SUPER) {
		pr_err("Bad VE name %s\n", name);
		goto err;
	}

	/*
	 * All communications come through special VZ
	 * module device.
	 */
	vz->vzfd = open(VZCTLDEV, O_RDWR);
	if (vz->vzfd < 0) {
		pr_perror("Can't open %s", VZCTLDEV);
		goto err;
	}

	/*
	 * While device might be there but still we need to
	 * make sure there is real VZ support on OS level.
	 */
	while (retry--) {
		ret = ioctl(vz->vzfd, VZCTL_ENV_CREATE, &env_create);
		if (ret < 0) {
			if (errno == EBUSY) {
				sleep(1);
				continue;
			}
		}
		break;
	}

	if (ret < 0) {
		pr_perror("The kernel looks like don't supporting VZ "
			  "(or VZ module is not loaded)");
		goto err;
	}

	vz->ct.h.ops = &vz_ct_ops;
	return &vz->ct.h;

err:
	if (vz)
		vz_ct_destroy(&vz->ct.h);
	return NULL;
}

static ct_handler_t vz_ct_open(libct_session_t s, char *name)
{
	/* FIXME */
	return NULL;
}

static void vz_close(libct_session_t s)
{
	vz_session_t *vz_ses = s2vz(s);

	if (vz_ses->server_sk >= 0)
		close(vz_ses->server_sk);

	xfree(vz_ses);
}

static const struct backend_ops vz_session_ops = {
	.type		= BACKEND_VZ,
	.create_ct	= vz_ct_create,
	.open_ct	= vz_ct_open,
	.close		= vz_close,
};

libct_session_t libct_session_open_vz(void)
{
	vz_session_t *vz_ses;

	/*
	 * VZ session is close to "local" ones
	 * and we need some features which are
	 * initialized here for own needs.
	 */
	if (libct_init_local())
		return NULL;

	vz_ses = xzalloc(sizeof(*vz_ses));
	if (vz_ses) {
		INIT_LIST_HEAD(&vz_ses->s.s_cts);
		vz_ses->s.ops = &vz_session_ops;
		vz_ses->server_sk = -1;
		return &vz_ses->s;
	}

	return NULL;
}
