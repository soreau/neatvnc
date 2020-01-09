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
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/uio.h>
#include <uv.h>

#include "type-macros.h"
#include "rcbuf.h"
#include "stream.h"
#include "sys/queue.h"

void stream__on_event(uv_poll_t* uv_poll, int status, int events);

void stream__poll_r(struct stream* self)
{
	uv_poll_start(&self->uv_poll, UV_READABLE | UV_DISCONNECT,
	              stream__on_event);
}

void stream__poll_rw(struct stream* self)
{
	uv_poll_start(&self->uv_poll, UV_READABLE | UV_DISCONNECT | UV_WRITABLE,
	              stream__on_event);
}

void stream_req__finish(struct stream_req* req, enum stream_req_status status)
{
	if (req->on_done)
		req->on_done(req->userdata, status);

	rcbuf_unref(req->payload);
	free(req);
}

void stream__remote_closed(struct stream* self)
{
	uv_poll_stop(&self->uv_poll);
	close(self->fd);
	self->fd = -1;

	if (self->on_event)
		self->on_event(self, STREAM_EVENT_CLOSE);
}

int stream__flush(struct stream* self)
{
	static struct iovec iov[IOV_MAX];
	size_t n_msgs = 0;
	ssize_t bytes_sent;

	struct stream_req* req;
	TAILQ_FOREACH(req, &self->send_queue, link) {
		iov[n_msgs].iov_base = req->payload->payload;
		iov[n_msgs].iov_len = req->payload->size;

		if (++n_msgs >= IOV_MAX)
			break;
	}

	if (n_msgs < 0)
		return 0;

	printf("Flush\n");

	bytes_sent = writev(self->fd, iov, n_msgs);
	if (bytes_sent < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			stream__poll_rw(self);
			errno = EAGAIN;
		} else if (errno == EPIPE) {
			stream__remote_closed(self);
			errno = EPIPE;
		}

		return bytes_sent;
	}

	printf("Flushed %lu\n", bytes_sent);

	ssize_t bytes_left = bytes_sent;

	struct stream_req* tmp;
	TAILQ_FOREACH_SAFE(req, &self->send_queue, link, tmp) {
		bytes_left -= req->payload->size;

		if (bytes_left >= 0) {
			TAILQ_REMOVE(&self->send_queue, req, link);
			stream_req__finish(req, STREAM_REQ_DONE);
		} else {
			char* p = req->payload->payload;
			size_t s = req->payload->size;
			memmove(p, p + s - bytes_left, -bytes_left);
		}

		if (bytes_left <= 0)
			break;
	}

	if (bytes_left == 0)
		stream__poll_r(self);

	assert(bytes_left <= 0);

	return bytes_sent;
}

void stream__on_readable(struct stream* self)
{
	printf("Got event\n");
	if (self->on_event)
		self->on_event(self, STREAM_EVENT_READ);
}

void stream__on_event(uv_poll_t* uv_poll, int status, int events)
{
	struct stream* self = container_of(uv_poll, struct stream, uv_poll);

	if (events & UV_WRITABLE)
		stream__flush(self);

	if (events & UV_READABLE)
		stream__on_readable(self);

	if (events & UV_DISCONNECT)
		stream__remote_closed(self);
}

struct stream* stream_new(enum stream_flags flags, int fd,
                          stream_event_fn on_event, void* userdata)
{
	struct stream* self = calloc(1, sizeof(*self));
	if (!self)
		return NULL;

	self->ref = 1;
	self->flags |= flags;
	self->fd = fd;
	self->on_event = on_event;
	self->userdata = userdata;

	TAILQ_INIT(&self->send_queue);

	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

	if (uv_poll_init(uv_default_loop(), &self->uv_poll, fd) < 0)
		goto failure;

	stream__poll_r(self);

	return self;

failure:
	free(self);
	return NULL;
}

void stream_ref(struct stream* self)
{
	++self->ref;
}

void stream_unref(struct stream* self)
{
	assert(self->ref > 0);

	if (--self->ref != 0)
		return;

#ifdef ENABLE_TLS
	if (self->flags & STREAM_TLS)
		SSL_free(self->ssl);
#endif

	while (!TAILQ_EMPTY(&self->send_queue)) {
		struct stream_req* req = TAILQ_FIRST(&self->send_queue);
		TAILQ_REMOVE(&self->send_queue, req, link);
		stream_req__finish(req, STREAM_REQ_FAILED);
	}

	uv_poll_stop(&self->uv_poll);
	if (self->fd >= 0)
		close(self->fd);
	free(self);
}

int stream__write_plain(struct stream* self, struct rcbuf* payload,
                        stream_req_fn on_done, void* userdata)
{

	struct stream_req* req = calloc(1, sizeof(*req));
	if (!req)
		return -1;

	req->payload = payload;
	req->on_done = on_done;
	req->userdata = userdata;

	TAILQ_INSERT_TAIL(&self->send_queue, req, link);

	return stream__flush(self);
}

int stream__write_tls(struct stream* self, struct rcbuf* payload,
                      stream_req_fn on_done, void* userdata)
{
	// TODO
	return -1;
}

ssize_t stream__read_plain(struct stream* self, void* dst, size_t size)
{
	return read(self->fd, dst, size);
}

ssize_t stream__read_tls(struct stream* self, void* dst, size_t size)
{
#ifdef ENABLE_TLS
	return SSL_read(self->ssl, dst, size);
#endif
}

ssize_t stream_read(struct stream* self, void* dst, size_t size)
{
	printf("Stream read %lu\n", size);

	if (self->fd < 0) {
		errno = EPIPE;
		return -1;
	}

	return (self->flags & STREAM_TLS)
	     ? stream__read_tls(self, dst, size)
	     : stream__read_plain(self, dst, size);
}

int stream_write(struct stream* self, struct rcbuf* payload,
                 stream_req_fn on_done, void* userdata)
{
	printf("Stream write %lu\n", payload->size);
	if (self->fd < 0) {
		errno = EPIPE;
		return -1;
	}

	return (self->flags & STREAM_TLS)
	     ? stream__write_tls(self, payload, on_done, userdata)
	     : stream__write_plain(self, payload, on_done, userdata);
}
