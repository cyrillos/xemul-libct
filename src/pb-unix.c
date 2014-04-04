#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include "uapi/libct.h"
#include "session.h"
#include "compiler.h"
#include "list.h"
#include "xmalloc.h"
#include "ct.h"
#include "net.h"
#include "protobuf/rpc.pb-c.h"

#define MAX_MSG_ONSTACK	512

struct pbunix_session {
	int sk;
	struct libct_session s;
};

static inline struct pbunix_session *s2us(libct_session_t s)
{
	return container_of(s, struct pbunix_session, s);
}

static RpcResponce *pbunix_req(struct pbunix_session *us, RpcRequest *req)
{
	int len, ret;
	unsigned char *data, dbuf[MAX_MSG_ONSTACK];
	RpcResponce *resp = NULL;

	len = rpc_request__get_packed_size(req);
	if (len > MAX_MSG_ONSTACK) {
		data = xmalloc(len);
		if (!data)
			goto out_nd;
	} else
		data = dbuf;

	ret = rpc_request__pack(req, data);
	if (ret != len)
		goto out;

	ret = send(us->sk, data, len, 0);
	if (ret != len)
		goto out;

	len = recv(us->sk, dbuf, MAX_MSG_ONSTACK, 0);
	if (len < 0)
		goto out;

	resp = rpc_responce__unpack(NULL, len, dbuf);
	if (!resp->success) {
		rpc_responce__free_unpacked(resp, NULL);
		resp = NULL;
	}
out:
	if (data != dbuf)
		xfree(data);
out_nd:
	return resp;
}

struct container_proxy {
	struct ct_handler h;
	unsigned long rid;
	struct pbunix_session *ses;
};

static inline struct container_proxy *ch2c(ct_handler_t h)
{
	return container_of(h, struct container_proxy, h);
}

static int pbunix_req_ct(ct_handler_t h, RpcRequest *req, RpcResponce **respp)
{
	RpcResponce *resp;

	resp = pbunix_req(ch2c(h)->ses, req);
	if (!resp)
		return -1;
	if (!respp)
		rpc_responce__free_unpacked(resp, NULL);
	else
		*respp = resp;
	return 0;
}

static inline void pack_ct_req(RpcRequest *req, int t, ct_handler_t h)
{
	struct container_proxy *cp;

	cp = ch2c(h);
	req->req = t;
	req->has_ct_rid = true;
	req->ct_rid = cp->rid;
}

static void send_destroy_req(ct_handler_t h)
{
	RpcRequest req = RPC_REQUEST__INIT;

	pack_ct_req(&req, REQ_TYPE__CT_DESTROY, h);
	pbunix_req_ct(h, &req, NULL);
	/* FIXME what if it fails? */
	xfree(ch2c(h));
}

static enum ct_state send_get_state_req(ct_handler_t h)
{
	RpcRequest req = RPC_REQUEST__INIT;
	RpcResponce *resp;
	enum ct_state st = CT_ERROR;

	pack_ct_req(&req, REQ_TYPE__CT_GET_STATE, h);
	if (!pbunix_req_ct(h, &req, &resp)) {
		st = resp->state->state;
		rpc_responce__free_unpacked(resp, NULL);
	}

	return st;
}

static int send_execve_req(ct_handler_t h, int type, char *path, char **argv, char **env)
{
	RpcRequest req = RPC_REQUEST__INIT;
	ExecvReq er = EXECV_REQ__INIT;

	pack_ct_req(&req, type, h);
	req.execv = &er;

	er.path = path;
	for (er.n_args = 0; argv[er.n_args]; er.n_args++)
		;
	er.args = argv;

	if (env) {
		for (er.n_env = 0; env[er.n_env]; er.n_env++)
			;
		er.env = env;
	}

	return pbunix_req_ct(h, &req, NULL);
}

static int send_spawn_req(ct_handler_t h, char *path, char **argv, char **env)
{
	return send_execve_req(h, REQ_TYPE__CT_SPAWN, path, argv, env);
}

static int send_enter_req(ct_handler_t h, char *path, char **argv, char **env)
{
	return send_execve_req(h, REQ_TYPE__CT_ENTER, path, argv, env);
}

static int send_kill_req(ct_handler_t h)
{
	RpcRequest req = RPC_REQUEST__INIT;
	pack_ct_req(&req, REQ_TYPE__CT_KILL, h);
	return pbunix_req_ct(h, &req, NULL);
}

static int send_wait_req(ct_handler_t h)
{
	RpcRequest req = RPC_REQUEST__INIT;
	pack_ct_req(&req, REQ_TYPE__CT_WAIT, h);
	return pbunix_req_ct(h, &req, NULL);
}

static int send_nsmask_req(ct_handler_t h, unsigned long nsmask)
{
	RpcRequest req = RPC_REQUEST__INIT;
	NsmaskReq nm = NSMASK_REQ__INIT;

	pack_ct_req(&req, REQ_TYPE__CT_SETNSMASK, h);
	req.nsmask = &nm;
	nm.mask = nsmask;
	return pbunix_req_ct(h, &req, NULL);
}

static int send_addcntl_req(ct_handler_t h, enum ct_controller ctype)
{
	RpcRequest req = RPC_REQUEST__INIT;
	AddcntlReq ac = ADDCNTL_REQ__INIT;

	pack_ct_req(&req, REQ_TYPE__CT_ADD_CNTL, h);
	req.addcntl = &ac;
	ac.ctype = ctype;
	return pbunix_req_ct(h, &req, NULL);
}

static int send_cfgcntl_req(ct_handler_t h, enum ct_controller ctype,
		char *param, char *value)
{
	RpcRequest req = RPC_REQUEST__INIT;
	CfgcntlReq cr = CFGCNTL_REQ__INIT;

	pack_ct_req(&req, REQ_TYPE__CT_CFG_CNTL, h);
	req.cfgcntl = &cr;
	cr.ctype = ctype;
	cr.param = param;
	cr.value = value;
	return pbunix_req_ct(h, &req, NULL);
}

static int send_setroot_req(ct_handler_t h, char *root)
{
	RpcRequest req = RPC_REQUEST__INIT;
	SetrootReq sr = SETROOT_REQ__INIT;

	pack_ct_req(&req, REQ_TYPE__FS_SETROOT, h);
	req.setroot = &sr;
	sr.root = root;
	return pbunix_req_ct(h, &req, NULL);
}

static int send_setpriv_req(ct_handler_t h, enum ct_fs_type type, void *arg)
{
	RpcRequest req = RPC_REQUEST__INIT;
	SetprivReq sp = SETPRIV_REQ__INIT;
	const struct ct_fs_ops *ops;

	pack_ct_req(&req, REQ_TYPE__FS_SETPRIVATE, h);
	req.setpriv = &sp;

	ops = fstype_get_ops(type);
	if (!ops)
		return -1;

	sp.type = type;
	ops->pb_pack(arg, &sp);
	return pbunix_req_ct(h, &req, NULL);
}

static int send_set_option_req(ct_handler_t h, int opt, va_list parms)
{
	RpcRequest req = RPC_REQUEST__INIT;
	SetoptionReq so = SETOPTION_REQ__INIT;

	pack_ct_req(&req, REQ_TYPE__CT_SET_OPTION, h);
	req.setopt = &so;
	so.opt = opt;

	switch (opt) {
	default:
		return -1;
	case LIBCT_OPT_AUTO_PROC_MOUNT:
		break;
	}

	return pbunix_req_ct(h, &req, NULL);
}

static int send_netadd_req(ct_handler_t h, enum ct_net_type ntype, void *arg)
{
	RpcRequest req = RPC_REQUEST__INIT;
	NetaddReq na = NETADD_REQ__INIT;
	const struct ct_net_ops *nops;

	pack_ct_req(&req, REQ_TYPE__CT_NET_ADD, h);
	req.netadd = &na;
	na.type = ntype;

	if (ntype != CT_NET_NONE) {
		nops = net_get_ops(ntype);
		if (!nops)
			return -1;

		nops->pb_pack(arg, &na);
	}

	return pbunix_req_ct(h, &req, NULL);
}

static int send_add_mount_req(ct_handler_t h, char *src, char *dst, int flags)
{
	RpcRequest req = RPC_REQUEST__INIT;
	AddmountReq am = ADDMOUNT_REQ__INIT;

	pack_ct_req(&req, REQ_TYPE__FS_ADD_MOUNT, h);
	req.addmnt = &am;
	am.src = src;
	am.dst = dst;
	am.flags = flags;

	return pbunix_req_ct(h, &req, NULL);
}

static const struct container_ops pbunix_ct_ops = {
	.get_state = send_get_state_req,
	.spawn_execve = send_spawn_req,
	.enter_execve = send_enter_req,
	.destroy = send_destroy_req,
	.kill = send_kill_req,
	.wait = send_wait_req,
	.set_nsmask = send_nsmask_req,
	.add_controller = send_addcntl_req,
	.config_controller = send_cfgcntl_req,
	.fs_set_root = send_setroot_req,
	.fs_set_private = send_setpriv_req,
	.fs_add_mount = send_add_mount_req,
	.set_option = send_set_option_req,
	.net_add = send_netadd_req,
};

static ct_handler_t send_create_req(libct_session_t s, char *name)
{
	struct pbunix_session *us;
	struct container_proxy *cp;
	RpcRequest req = RPC_REQUEST__INIT;
	CreateReq cr = CREATE_REQ__INIT;
	RpcResponce *resp;

	us = s2us(s);

	cp = xmalloc(sizeof(*cp));
	if (!cp)
		return NULL;

	req.req = REQ_TYPE__CT_CREATE;
	req.create = &cr;
	cr.name = name;

	resp = pbunix_req(us, &req);
	if (!resp) {
		xfree(cp);
		return NULL;
	}

	cp->h.ops = &pbunix_ct_ops;
	cp->rid = resp->create->rid;
	cp->ses = us;

	rpc_responce__free_unpacked(resp, NULL);

	return &cp->h;
}

static void close_pbunix_session(libct_session_t s)
{
	struct pbunix_session *us;

	us = s2us(s);
	close(us->sk);
	xfree(us);
}

static const struct backend_ops pbunix_session_ops = {
	.create_ct = send_create_req,
	.close = close_pbunix_session,
};

libct_session_t libct_session_open_pbunix(char *sk_path)
{
	struct pbunix_session *us;
	struct sockaddr_un addr;
	socklen_t alen;

	us = xmalloc(sizeof(*us));
	if (us == NULL)
		return NULL;

	us->sk = socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if (us->sk == -1)
		goto err;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, sk_path, sizeof(addr.sun_path));
	alen = strlen(addr.sun_path) + sizeof(addr.sun_family);

	if (connect(us->sk, (struct sockaddr *)&addr, alen))
		goto err;

	us->s.ops = &pbunix_session_ops;
	return &us->s;

err:
	xfree(us);
	return NULL;
}
