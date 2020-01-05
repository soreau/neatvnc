/*
 * Copyright (c) 2020 Andri Yngvason
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */


#include <stdlib.h>
#include <unistd.h>
#include <uv.h>

#include "type-macros.h"
#include "rcbuf.h"
#include "stream.h"


struct stream_write_req {
	uv_write_t req;
	struct rcbuf* payload;
	void (*on_done)(void*);
	void* userdata;
};

int stream__init(struct stream* self, enum stream_type type)
{
	switch (type) {
	case STREAM_TCP:
		return uv_tcp_init(uv_default_loop(), &self->tcp);
	case STREAM_PIPE:
		return uv_pipe_init(uv_default_loop(), &self->pipe, 0);
	default:
		return -1;
	}
}

struct stream* stream_new(enum stream_type type)
{
	struct stream* self = calloc(1, sizeof(*self));
	if (!self)
		return NULL;

	if (stream__init(self, type) < 0)
		goto failure;

	return self;

failure:
	free(self);
	return NULL;
}

void stream__on_close(uv_handle_t* uv_handle)
{
	struct stream* self = container_of(uv_handle, struct stream, handle);
	free(self);
}

void stream_close(struct stream* self)
{
	if (--self->ref > 0)
		return;

#ifdef HAVE_TLS
	if (self->tcp & STREAM_TLS)
		stream_tls_destroy(&self->tls);
#endif

	uv_read_stop(&self->stream);
	uv_close(&self->handle, stream__on_close);
}

void stream__on_write_done(uv_write_t* uv_req, int status)
{
	struct stream_write_req* req = (struct stream_write_req*)uv_req;

	if (req->on_done)
		req->on_done(req->userdata);

	rcbuf_unref(req->payload);
	free(req);
}

int stream__write_plain(struct stream* self, struct rcbuf* payload,
                        void (*on_done)(void*), void* userdata)
{
	struct stream_write_req* req = calloc(1, sizeof(*req));
	if (!req)
		return -1;

	rcbuf_ref(payload);

	req->payload = payload;
	req->on_done = on_done;
	req->userdata = req->userdata;

	int rc = uv_write(&req->req, &self->stream, &payload->uv, 1,
	                  stream__on_write_done);
	if (rc < 0) {
		rcbuf_unref(payload);
		free(req);
	}

	return rc;
}

int stream__write_tls(struct stream* self, struct rcbuf* payload,
                 void (*on_done)(void*), void* userdata)
{
	return -1;
}

int stream_write(struct stream* self, struct rcbuf* payload,
                 void (*on_done)(void*), void* userdata)
{
	return (self->type & STREAM_TLS)
	     ? stream__write_tls(self, payload, on_done, userdata)
	     : stream__write_plain(self, payload, on_done, userdata);
}
