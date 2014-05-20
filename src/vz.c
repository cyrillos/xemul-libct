#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <sys/ioctl.h>

#include "compiler.h"

#include "uapi/libct.h"

#include "xmalloc.h"
#include "session.h"
#include "libct.h"

#include "vz.h"

typedef struct {
	struct container	ct;

	int			vzfd;
	envid_t			veid;
} vz_container_t;

static vz_container_t *cth2vz(ct_handler_t h)
{
	struct container *ct = container_of(h, struct container, h);
	return container_of(ct, vz_container_t, ct);
}

static void vz_ct_destroy(ct_handler_t h)
{
	vz_container_t *vz = cth2vz(h);

	if (vz->vzfd >= 0)
		close(vz->vzfd);
	xfree(vz->ct.name);
	xfree(vz);
}

static const struct container_ops vz_ct_ops = {
	.spawn_cb		= NULL,
	.spawn_execve		= NULL,
	.enter_cb		= NULL,
	.enter_execve		= NULL,
	.kill			= NULL,
	.wait			= NULL,
	.get_state		= NULL,
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
	.net_add		= NULL,
	.net_del		= NULL,
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

	vz->veid = 0;
	vz->vzfd = -1;

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
	return NULL;
}

static void vz_ct_close(libct_session_t s)
{
}

static const struct backend_ops vz_session_ops = {
	.type		= BACKEND_VZ,
	.create_ct	= vz_ct_create,
	.open_ct	= vz_ct_open,
	.close		= vz_ct_close,
};
