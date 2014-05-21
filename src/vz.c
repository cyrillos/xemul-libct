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

static int vz_ioctl_env_create(vz_container_t *vzct, envid_t veid, int flags)
{
	unsigned int retry = 3;
	int ret = -EINVAL;

	struct vzctl_env_create env_create = {
		.veid	= veid,
		.flags	= flags,
	};

	for (retry = 0; retry < 3; retry++) {
		ret = ioctl(vzct->vzfd, VZCTL_ENV_CREATE, &env_create);
		if (ret < 0) {
			if (errno == EBUSY) {
				sleep(1);
				continue;
			}
		}
		break;
	}

	return ret;
}

static enum ct_state vz_ct_get_state(ct_handler_t h)
{
	vz_container_t *vzct = cth2vz(h);
	struct container *ct = cth2ct(h);
	enum ct_state real_state;

	/*
	 * When VE is running it must report so, don't
	 * rely on internal container 'state' we're tracking
	 * in container::state.
	 *
	 * FIXME Figure out if VE states might be differen
	 * from ones we're presening (checkpointing, migrating).
	 */
	real_state = vz_ioctl_env_create(vzct, vzct->veid, VE_TEST) == 0 ? CT_RUNNING : CT_STOPPED;
	if (real_state != ct->state) {
		/*
		 * Someone is playing with container outside
		 * of us, we can't guarantee data consistency.
		 */
		pr_err_once("Container %u state mismatch %u %u\n",
			    vzct->veid, real_state, ct->state);
		return -EINVAL;
	}

	return real_state;
}

static void vz_ct_destroy(ct_handler_t h)
{
	vz_container_t *vzct = cth2vz(h);
	struct container *ct = &vzct->ct;

	/*
	 * Try to stop it if it's running first.
	 */
	if (vz_ct_get_state(h) == CT_RUNNING) {
		char *argv[] = {"halt", NULL};
		char *env[] = { NULL};

		vzct->ct.h.ops->enter_execve(h, argv[0], argv, env);
	}

	if (vzct->vzfd >= 0)
		close(vzct->vzfd);

	cgroups_free(ct);
	fs_free(ct);
	net_release(ct);
	xfree(ct->name);
	xfree(ct->hostname);
	xfree(ct->domainname);
	xfree(ct->cgroup_sub);
	xfree(vzct);
}

static const struct container_ops vz_ct_ops = {
	.spawn_cb		= NULL,
	.spawn_execve		= NULL,
	.enter_cb		= NULL,
	.enter_execve		= NULL,
	.kill			= local_ct_kill,
	.wait			= NULL,
	.get_state		= vz_ct_get_state,
	.set_nsmask		= local_set_nsmask,
	.add_controller		= local_add_controller,
	.config_controller	= local_config_controller,
	.fs_set_root		= local_fs_set_root,
	.fs_set_private		= local_fs_set_private,
	.fs_add_mount		= local_add_mount,
	.fs_del_mount		= local_del_mount,
	.set_option		= local_set_option,
	.destroy		= vz_ct_destroy,
	.detach			= vz_ct_destroy,
	.net_add		= local_net_add,
	.net_del		= local_net_del,
	.uname			= local_uname,
	.set_caps		= local_set_caps,
};

static ct_handler_t vz_ct_create(libct_session_t s, char *name)
{
	vz_container_t *vzct;

	vzct = xmalloc(sizeof(*vzct));
	if (!vzct || ct_init(&vzct->ct, name))
		goto err;

	vzct->vzfd = -1;

	/*
	 * OpenVZ doesn't support symbolic names, but all VEs
	 * are identified by than named numeric VE id. Thus the
	 * name here must be a VE (container) number.
	 */
	vzct->veid = (envid_t)atol(name);
	if (vzct->veid == VZ_ENVID_SUPER) {
		pr_err("Bad VE name %s\n", name);
		goto err;
	}

	/*
	 * All communications come through special VZ
	 * module device.
	 */
	vzct->vzfd = open(VZCTLDEV, O_RDWR);
	if (vzct->vzfd < 0) {
		pr_perror("Can't open %s", VZCTLDEV);
		goto err;
	}

	/*
	 * While device might be there but still we need to
	 * make sure there is real VZ support on OS level.
	 */
	if (vz_ioctl_env_create(vzct, 0, 0) < 0) {
		pr_perror("The kernel looks like don't supporting VZ "
			  "(or VZ module is not loaded)");
		goto err;
	}

	vzct->ct.h.ops = &vz_ct_ops;
	return &vzct->ct.h;

err:
	if (vzct)
		vz_ct_destroy(&vzct->ct.h);
	return NULL;
}

static ct_handler_t vz_ct_open(libct_session_t s, char *name)
{
	/* FIXME */
	return NULL;
}

static void vz_close(libct_session_t s)
{
	vz_session_t *vzs = s2vz(s);

	if (vzs->server_sk >= 0)
		close(vzs->server_sk);

	xfree(vzs);
}

static const struct backend_ops vz_session_ops = {
	.type		= BACKEND_VZ,
	.create_ct	= vz_ct_create,
	.open_ct	= vz_ct_open,
	.close		= vz_close,
};

libct_session_t libct_session_open_vz(void)
{
	vz_session_t *vzs;

	/*
	 * VZ session is close to "local" ones
	 * and we need some features which are
	 * initialized here for own needs.
	 */
	if (libct_init_local())
		return NULL;

	vzs = xzalloc(sizeof(*vzs));
	if (vzs) {
		INIT_LIST_HEAD(&vzs->s.s_cts);
		vzs->s.ops = &vz_session_ops;
		vzs->server_sk = -1;
		return &vzs->s;
	}

	return NULL;
}
