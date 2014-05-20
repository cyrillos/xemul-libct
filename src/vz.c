#include <stdio.h>

#include "compiler.h"

#include "uapi/libct.h"

#include "xmalloc.h"
#include "session.h"
#include "libct.h"

#include "vz.h"


typedef struct {
	struct container	ct;
	void			*private;
} vz_container_t;

static vz_container_t *cth2vz(ct_handler_t h)
{
	struct container *ct = container_of(h, struct container, h);
	return container_of(ct, vz_container_t, ct);
}

static void vz_ct_destroy(ct_handler_t h)
{
	vz_container_t *vz = cth2vz(h);

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
	.fs_set_root		= NULL,
	.fs_set_private		= NULL,
	.fs_add_mount		= NULL,
	.fs_del_mount		= NULL,
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
	vz_container_t *vz;

	vz = xmalloc(sizeof(*vz));
	if (vz && ct_init(&vz->ct, name)) {
		vz->ct.h.ops = &vz_ct_ops;
		return &vz->ct.h;
	}

	xfree(vz);
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
