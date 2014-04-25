#include <stdio.h>

#include "compiler.h"

#include "uapi/libct.h"

#include "session.h"
#include "libct.h"

#include "backend-openvz.h"


typedef struct {
	struct libct_session	s;
} vz_session_t;

static ct_handler_t vz_ct_create(libct_session_t s, char *name)
{
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

