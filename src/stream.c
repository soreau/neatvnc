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

#include <openssl/ssl.h>
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

static void stream__on_event(uv_poll_t* uv_poll, int status, int events);
static int stream__try_tls_accept(struct stream* self);

static inline void stream__poll_r(struct stream* self)
{
	uv_poll_start(&self->uv_poll, UV_READABLE | UV_DISCONNECT,
	              stream__on_event);
}

static inline void stream__poll_w(struct stream* self)
{
	uv_poll_start(&self->uv_poll, UV_WRITABLE | UV_DISCONNECT,
	              stream__on_event);
}

static inline void stream__poll_rw(struct stream* self)
{
	uv_poll_start(&self->uv_poll, UV_READABLE | UV_DISCONNECT | UV_WRITABLE,
	              stream__on_event);
}

static void stream_req__finish(struct stream_req* req, enum stream_req_status status)
{
	if (req->on_done)
		req->on_done(req->userdata, status);

	rcbuf_unref(req->payload);
	free(req);
}

static void stream__remote_closed(struct stream* self)
{
	uv_poll_stop(&self->uv_poll);
	close(self->fd);
	self->fd = -1;

	if (self->on_event)
		self->on_event(self, STREAM_EVENT_CLOSE);
}

static int stream__flush(struct stream* self)
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

static int stream__tls_flush(struct stream* self)
{
	while (!TAILQ_EMPTY(&self->send_queue)) {
		struct stream_req* req = TAILQ_FIRST(&self->send_queue);

		size_t n_bytes = 0;
		int rc = SSL_write_ex(self->ssl, req->payload->payload,
		                      req->payload->size, &n_bytes);
		if (rc == 0) {
			int err = SSL_get_error(self->ssl, rc);
			if (err == SSL_ERROR_WANT_WRITE)
				stream__poll_rw(self);
			else if (err != SSL_ERROR_WANT_READ) {
				// TODO: Do more to close the socket
				errno = EPIPE;
				return -1;
			}

			break;
		}

		// TODO: Enable and handle partial writes

		TAILQ_REMOVE(&self->send_queue, req, link);
		stream_req__finish(req, STREAM_REQ_DONE);
	}

	if (TAILQ_EMPTY(&self->send_queue))
		stream__poll_r(self);

	return 1;
}

static void stream__on_readable(struct stream* self)
{
	switch (self->state) {
	case STREAM_STATE_NORMAL:
	case STREAM_STATE_TLS_READY:
		if (self->on_event)
			self->on_event(self, STREAM_EVENT_READ);
		break;
	case STREAM_STATE_TLS_HANDSHAKE:
		stream__try_tls_accept(self);
		break;
	}
}

static void stream__on_writable(struct stream* self)
{
	switch (self->state) {
	case STREAM_STATE_NORMAL:
		stream__flush(self);
		break;
	case STREAM_STATE_TLS_HANDSHAKE:
		stream__try_tls_accept(self);
		break;
	case STREAM_STATE_TLS_READY:
		stream__tls_flush(self);
		break;
	}
}

static void stream__on_event(uv_poll_t* uv_poll, int status, int events)
{
	struct stream* self = container_of(uv_poll, struct stream, uv_poll);

	if (events & UV_WRITABLE)
		stream__on_writable(self);

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
	if (self->ssl)
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

int stream_write(struct stream* self, struct rcbuf* payload,
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

ssize_t stream__read_plain(struct stream* self, void* dst, size_t size)
{
	return read(self->fd, dst, size);
}

ssize_t stream__read_tls(struct stream* self, void* dst, size_t size)
{
#ifdef ENABLE_TLS
	return SSL_read(self->ssl, dst, size);
#else
	return -1;
#endif
}

ssize_t stream_read(struct stream* self, void* dst, size_t size)
{
	if (self->fd < 0) {
		errno = EPIPE;
		return -1;
	}

	switch (self->state) {
	case STREAM_STATE_NORMAL: return stream__read_plain(self, dst, size);
	case STREAM_STATE_TLS_READY: return stream__read_tls(self, dst, size);
	default: break;
	}

	errno = EAGAIN;
	return -1;
}

static int stream__try_tls_accept(struct stream* self)
{
	int rc = SSL_accept(self->ssl);
	if (rc == 0)
		return -1;

	if (rc == 1) {
		self->state = STREAM_STATE_TLS_READY;
		stream__poll_r(self);
		return 0;
	}

	assert(rc < 0);

	int err = SSL_get_error(self->ssl, rc);
	if (err == SSL_ERROR_WANT_READ)
		stream__poll_r(self);
	else if (err == SSL_ERROR_WANT_WRITE)
		stream__poll_w(self);
	else
		return -1;

	self->state = STREAM_STATE_TLS_HANDSHAKE;
	return 0;
}

int stream_upgrade_to_tls(struct stream* self, void* context)
{
	self->ssl = SSL_new(context);
	if (!self->ssl)
		return -1;

	SSL_set_fd(self->ssl, self->fd);

	return stream__try_tls_accept(self);
}
