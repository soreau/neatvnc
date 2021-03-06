/*
 * Copyright (c) 2019 Andri Yngvason
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

#include "rfb-proto.h"
#include "util.h"
#include "zrle.h"
#include "tight.h"
#include "raw-encoding.h"
#include "vec.h"
#include "type-macros.h"
#include "fb.h"
#include "neatvnc.h"
#include "common.h"
#include "pixels.h"
#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>
#include <sys/param.h>
#include <assert.h>
#include <uv.h>
#include <libdrm/drm_fourcc.h>
#include <pixman.h>
#include <pthread.h>

#ifndef DRM_FORMAT_INVALID
#define DRM_FORMAT_INVALID 0
#endif

#ifndef DRM_FORMAT_MOD_LINEAR
#define DRM_FORMAT_MOD_LINEAR DRM_FORMAT_MOD_NONE
#endif

#define DEFAULT_NAME "Neat VNC"
#define READ_BUFFER_SIZE 4096

#define EXPORT __attribute__((visibility("default")))

struct fb_update_work {
	uv_work_t work;
	struct nvnc_client* client;
	struct pixman_region16 region;
	struct rfb_pixel_format server_fmt;
	struct vec frame;
	struct nvnc_fb* fb;
};

int schedule_client_update_fb(struct nvnc_client* client);

static const char* fourcc_to_string(uint32_t fourcc)
{
	static char buffer[5];

	buffer[0] = (fourcc >> 0) & 0xff;
	buffer[1] = (fourcc >> 8) & 0xff;
	buffer[2] = (fourcc >> 16) & 0xff;
	buffer[3] = (fourcc >> 24) & 0xff;
	buffer[4] = '\0';

	return buffer;
}

static void allocate_read_buffer(uv_handle_t* handle, size_t suggested_size,
                                 uv_buf_t* buf)
{
	(void)suggested_size;

	buf->base = malloc(READ_BUFFER_SIZE);
	buf->len = buf->base ? READ_BUFFER_SIZE : 0;
}

static void cleanup_client(uv_handle_t* handle)
{
	struct nvnc_client* client = container_of(
	        (uv_tcp_t*)handle, struct nvnc_client, stream_handle);

	nvnc_client_fn fn = client->cleanup_fn;
	if (fn)
		fn(client);

	deflateEnd(&client->z_stream);

	LIST_REMOVE(client, link);
	pixman_region_fini(&client->damage);
	free(client);
}

static inline void client_close(struct nvnc_client* client)
{
	uv_close((uv_handle_t*)&client->stream_handle, cleanup_client);
}

static inline void client_unref(struct nvnc_client* client)
{
	if (--client->ref == 0)
		client_close(client);
}

static inline void client_ref(struct nvnc_client* client)
{
	++client->ref;
}

static void close_after_write(uv_write_t* req, int status)
{
	struct nvnc_client* client = container_of(
	        (uv_tcp_t*)req->handle, struct nvnc_client, stream_handle);

	client_unref(client);
}

static int handle_unsupported_version(struct nvnc_client* client)
{
	char buffer[256];

	client->state = VNC_CLIENT_STATE_ERROR;

	struct rfb_error_reason* reason = (struct rfb_error_reason*)(buffer + 1);

	static const char reason_string[] = "Unsupported version\n";

	buffer[0] = 0; /* Number of security types is 0 on error */
	reason->length = htonl(strlen(reason_string));
	(void)strcmp(reason->message, reason_string);

	vnc__write((uv_stream_t*)&client->stream_handle, buffer,
	           1 + sizeof(*reason) + strlen(reason_string),
	           close_after_write);

	return 0;
}

static int on_version_message(struct nvnc_client* client)
{
	if (client->buffer_len - client->buffer_index < 12)
		return 0;

	char version_string[13];
	memcpy(version_string, client->msg_buffer + client->buffer_index, 12);
	version_string[12] = '\0';

	if (strcmp(RFB_VERSION_MESSAGE, version_string) != 0)
		return handle_unsupported_version(client);

	/* clang-format off */
	const static struct rfb_security_types_msg security = {
		.n = 1,
		.types = {
			RFB_SECURITY_TYPE_NONE,
		},
	};
	/* clang-format on */

	vnc__write((uv_stream_t*)&client->stream_handle, &security,
	           sizeof(security), NULL);

	client->state = VNC_CLIENT_STATE_WAITING_FOR_SECURITY;
	return 12;
}

static int handle_invalid_security_type(struct nvnc_client* client)
{
	char buffer[256];

	client->state = VNC_CLIENT_STATE_ERROR;

	uint8_t* result = (uint8_t*)buffer;

	struct rfb_error_reason* reason =
	        (struct rfb_error_reason*)(buffer + sizeof(*result));

	static const char reason_string[] = "Unsupported security type\n";

	*result = htonl(RFB_SECURITY_HANDSHAKE_FAILED);
	reason->length = htonl(strlen(reason_string));
	(void)strcmp(reason->message, reason_string);

	vnc__write((uv_stream_t*)&client->stream_handle, buffer,
	           sizeof(*result) + sizeof(*reason) + strlen(reason_string),
	           close_after_write);

	return 0;
}

static int on_security_message(struct nvnc_client* client)
{
	if (client->buffer_len - client->buffer_index < 1)
		return 0;

	uint8_t type = client->msg_buffer[client->buffer_index];

	if (type != RFB_SECURITY_TYPE_NONE)
		return handle_invalid_security_type(client);

	enum rfb_security_handshake_result result =
	        htonl(RFB_SECURITY_HANDSHAKE_OK);

	vnc__write((uv_stream_t*)&client->stream_handle, &result,
	           sizeof(result), NULL);

	client->state = VNC_CLIENT_STATE_WAITING_FOR_INIT;
	return sizeof(type);
}

static void disconnect_all_other_clients(struct nvnc_client* client)
{
	struct nvnc_client* node;
	LIST_FOREACH (node, &client->server->clients, link)
		if (node != client)
			client_unref(client);
}

static void send_server_init_message(struct nvnc_client* client)
{
	struct nvnc* server = client->server;
	struct vnc_display* display = &server->display;

	size_t name_len = strlen(display->name);
	size_t size = sizeof(struct rfb_server_init_msg) + name_len;

	struct rfb_server_init_msg* msg = calloc(1, size);
	if (!msg) {
		client_unref(client);
		return;
	}

	msg->width = htons(display->width),
	msg->height = htons(display->height), msg->name_length = htonl(name_len),
	memcpy(msg->name_string, display->name, name_len);

	int rc = rfb_pixfmt_from_fourcc(&msg->pixel_format, display->pixfmt);
	if (rc < 0) {
		client_unref(client);
		return;
	}

	msg->pixel_format.red_max = htons(msg->pixel_format.red_max);
	msg->pixel_format.green_max = htons(msg->pixel_format.green_max);
	msg->pixel_format.blue_max = htons(msg->pixel_format.blue_max);

	vnc__write((uv_stream_t*)&client->stream_handle, msg, size, NULL);

	free(msg);
}

static int on_init_message(struct nvnc_client* client)
{
	if (client->buffer_len - client->buffer_index < 1)
		return 0;

	uint8_t shared_flag = client->msg_buffer[client->buffer_index];
	if (!shared_flag)
		disconnect_all_other_clients(client);

	send_server_init_message(client);

	nvnc_client_fn fn = client->server->new_client_fn;
	if (fn)
		fn(client);

	client->state = VNC_CLIENT_STATE_READY;
	return sizeof(shared_flag);
}

static int on_client_set_pixel_format(struct nvnc_client* client)
{
	if (client->buffer_len - client->buffer_index <
	    4 + sizeof(struct rfb_pixel_format))
		return 0;

	struct rfb_pixel_format* fmt =
	        (struct rfb_pixel_format*)(client->msg_buffer +
	                                   client->buffer_index + 4);

	if (!fmt->true_colour_flag) {
		/* We don't really know what to do with color maps right now */
		client_unref(client);
		return 0;
	}

	fmt->red_max = ntohs(fmt->red_max);
	fmt->green_max = ntohs(fmt->green_max);
	fmt->blue_max = ntohs(fmt->blue_max);

	memcpy(&client->pixfmt, fmt, sizeof(client->pixfmt));

	client->fourcc = rfb_pixfmt_to_fourcc(fmt);

	return 4 + sizeof(struct rfb_pixel_format);
}

static int on_client_set_encodings(struct nvnc_client* client)
{
	struct rfb_client_set_encodings_msg* msg =
	        (struct rfb_client_set_encodings_msg*)(client->msg_buffer +
	                                               client->buffer_index);

	size_t n_encodings = MIN(MAX_ENCODINGS, ntohs(msg->n_encodings));
	size_t n = 0;

	if (client->buffer_len - client->buffer_index <
	    sizeof(*msg) + n_encodings * 4)
		return 0;

	for (size_t i = 0; i < n_encodings; ++i) {
		enum rfb_encodings encoding = htonl(msg->encodings[i]);

		switch (encoding) {
		case RFB_ENCODING_RAW:
		case RFB_ENCODING_COPYRECT:
		case RFB_ENCODING_RRE:
		case RFB_ENCODING_HEXTILE:
		case RFB_ENCODING_TIGHT:
		case RFB_ENCODING_TRLE:
		case RFB_ENCODING_ZRLE:
		case RFB_ENCODING_CURSOR:
		case RFB_ENCODING_DESKTOPSIZE:
			client->encodings[n++] = encoding;
		}
	}

	client->n_encodings = n;

	return sizeof(*msg) + 4 * n_encodings;
}

static void process_fb_update_requests(struct nvnc_client* client)
{
	if (!client->server->frame)
		return;

	if (uv_is_closing((uv_handle_t*)&client->stream_handle))
		return;

	if (!pixman_region_not_empty(&client->damage))
		return;

	if (client->is_updating || client->n_pending_requests == 0)
		return;

	client->is_updating = true;

	schedule_client_update_fb(client);
}

static int on_client_fb_update_request(struct nvnc_client* client)
{
	struct nvnc* server = client->server;

	struct rfb_client_fb_update_req_msg* msg =
	        (struct rfb_client_fb_update_req_msg*)(client->msg_buffer +
	                                               client->buffer_index);

	if (client->buffer_len - client->buffer_index < sizeof(*msg))
		return 0;

	int incremental = msg->incremental;
	int x = ntohs(msg->x);
	int y = ntohs(msg->y);
	int width = ntohs(msg->width);
	int height = ntohs(msg->height);

	client->n_pending_requests++;

	/* Note: The region sent from the client is ignored for incremental
	 * updates. This avoids superfluous complexity.
	 */
	if (!incremental)
		pixman_region_union_rect(&client->damage, &client->damage, x, y,
		                         width, height);

	nvnc_fb_req_fn fn = server->fb_req_fn;
	if (fn)
		fn(client, incremental, x, y, width, height);

	process_fb_update_requests(client);

	return sizeof(*msg);
}

static int on_client_key_event(struct nvnc_client* client)
{
	struct nvnc* server = client->server;

	struct rfb_client_key_event_msg* msg =
	        (struct rfb_client_key_event_msg*)(client->msg_buffer +
	                                           client->buffer_index);

	if (client->buffer_len - client->buffer_index < sizeof(*msg))
		return 0;

	int down_flag = msg->down_flag;
	uint32_t keysym = ntohl(msg->key);

	nvnc_key_fn fn = server->key_fn;
	if (fn)
		fn(client, keysym, !!down_flag);

	return sizeof(*msg);
}

static int on_client_pointer_event(struct nvnc_client* client)
{
	struct nvnc* server = client->server;

	struct rfb_client_pointer_event_msg* msg =
	        (struct rfb_client_pointer_event_msg*)(client->msg_buffer +
	                                               client->buffer_index);

	if (client->buffer_len - client->buffer_index < sizeof(*msg))
		return 0;

	int button_mask = msg->button_mask;
	uint16_t x = ntohs(msg->x);
	uint16_t y = ntohs(msg->y);

	nvnc_pointer_fn fn = server->pointer_fn;
	if (fn)
		fn(client, x, y, button_mask);

	return sizeof(*msg);
}

static int on_client_cut_text(struct nvnc_client* client)
{
	struct rfb_client_cut_text_msg* msg =
	        (struct rfb_client_cut_text_msg*)(client->msg_buffer +
	                                          client->buffer_index);

	if (client->buffer_len - client->buffer_index < sizeof(*msg))
		return 0;

	uint32_t length = ntohl(msg->length);

	// TODO

	return sizeof(*msg) + length;
}

static int on_client_message(struct nvnc_client* client)
{
	if (client->buffer_len - client->buffer_index < 1)
		return 0;

	enum rfb_client_to_server_msg_type type =
	        client->msg_buffer[client->buffer_index];

	switch (type) {
	case RFB_CLIENT_TO_SERVER_SET_PIXEL_FORMAT:
		return on_client_set_pixel_format(client);
	case RFB_CLIENT_TO_SERVER_SET_ENCODINGS:
		return on_client_set_encodings(client);
	case RFB_CLIENT_TO_SERVER_FRAMEBUFFER_UPDATE_REQUEST:
		return on_client_fb_update_request(client);
	case RFB_CLIENT_TO_SERVER_KEY_EVENT:
		return on_client_key_event(client);
	case RFB_CLIENT_TO_SERVER_POINTER_EVENT:
		return on_client_pointer_event(client);
	case RFB_CLIENT_TO_SERVER_CLIENT_CUT_TEXT:
		return on_client_cut_text(client);
	}

	client_unref(client);
	return 0;
}

static int try_read_client_message(struct nvnc_client* client)
{
	switch (client->state) {
	case VNC_CLIENT_STATE_ERROR:
		client_unref(client);
		return 0;
	case VNC_CLIENT_STATE_WAITING_FOR_VERSION:
		return on_version_message(client);
	case VNC_CLIENT_STATE_WAITING_FOR_SECURITY:
		return on_security_message(client);
	case VNC_CLIENT_STATE_WAITING_FOR_INIT:
		return on_init_message(client);
	case VNC_CLIENT_STATE_READY:
		return on_client_message(client);
	}

	abort();
	return 0;
}

static void on_client_read(uv_stream_t* stream, ssize_t n_read,
                           const uv_buf_t* buf)
{
	struct nvnc_client* client = container_of(
	        (uv_tcp_t*)stream, struct nvnc_client, stream_handle);

	if (n_read == 0)
		goto done;

	if (n_read < 0) {
		uv_read_stop(stream);
		client_unref(client);
		goto done;
	}

	assert(client->buffer_index == 0);

	if ((size_t)n_read > MSG_BUFFER_SIZE - client->buffer_len) {
		/* Can't handle this. Let's just give up */
		client->state = VNC_CLIENT_STATE_ERROR;
		uv_read_stop(stream);
		client_unref(client);
		goto done;
	}

	memcpy(client->msg_buffer + client->buffer_len, buf->base, n_read);
	client->buffer_len += n_read;

	while (1) {
		int rc = try_read_client_message(client);
		if (rc == 0)
			break;

		client->buffer_index += rc;
	}

	assert(client->buffer_index <= client->buffer_len);

	memmove(client->msg_buffer, client->msg_buffer + client->buffer_index,
	        client->buffer_index);
	client->buffer_len -= client->buffer_index;
	client->buffer_index = 0;

done:
	free(buf->base);
}

static void on_connection(uv_stream_t* server_stream, int status)
{
	struct nvnc* server =
	        container_of((uv_tcp_t*)server_stream, struct nvnc, tcp_handle);

	struct nvnc_client* client = calloc(1, sizeof(*client));
	if (!client)
		return;

	client->ref = 1;
	client->server = server;

	int rc = deflateInit2(&client->z_stream,
	                      /* compression level: */ 1,
	                      /*            method: */ Z_DEFLATED,
	                      /*       window bits: */ 15,
	                      /*         mem level: */ 9,
	                      /*          strategy: */ Z_DEFAULT_STRATEGY);

	if (rc != Z_OK) {
		free(client);
		return;
	}

	pixman_region_init(&client->damage);

	uv_tcp_init(uv_default_loop(), &client->stream_handle);

	uv_accept((uv_stream_t*)&server->tcp_handle,
	          (uv_stream_t*)&client->stream_handle);

	uv_read_start((uv_stream_t*)&client->stream_handle,
	              allocate_read_buffer, on_client_read);

	vnc__write((uv_stream_t*)&client->stream_handle, RFB_VERSION_MESSAGE,
	           strlen(RFB_VERSION_MESSAGE), NULL);

	LIST_INSERT_HEAD(&server->clients, client, link);

	client->state = VNC_CLIENT_STATE_WAITING_FOR_VERSION;
}

int vnc_server_init(struct nvnc* self, const char* address, int port)
{
	LIST_INIT(&self->clients);

	uv_tcp_init(uv_default_loop(), &self->tcp_handle);

	struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(address);
	addr.sin_port = htons(port);

	if (uv_tcp_bind(&self->tcp_handle, (const struct sockaddr*)&addr, 0) < 0)
		goto failure;

	if (uv_listen((uv_stream_t*)&self->tcp_handle, 16, on_connection) < 0)
		goto failure;

	return 0;

failure:
	uv_unref((uv_handle_t*)&self->tcp_handle);
	return -1;
}

EXPORT
struct nvnc* nvnc_open(const char* address, uint16_t port)
{
	struct nvnc* self = calloc(1, sizeof(*self));
	if (!self)
		return NULL;

	strcpy(self->display.name, DEFAULT_NAME);

	LIST_INIT(&self->clients);

	uv_tcp_init(uv_default_loop(), &self->tcp_handle);

	struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(address);
	addr.sin_port = htons(port);

	if (uv_tcp_bind(&self->tcp_handle, (const struct sockaddr*)&addr, 0) < 0)
		goto failure;

	if (uv_listen((uv_stream_t*)&self->tcp_handle, 16, on_connection) < 0)
		goto failure;

	return self;
failure:
	uv_unref((uv_handle_t*)&self->tcp_handle);
	return NULL;
}

EXPORT
void nvnc_close(struct nvnc* self)
{
	struct nvnc_client* client;

	if (self->frame)
		nvnc_fb_unref(self->frame);

	LIST_FOREACH (client, &self->clients, link)
		client_unref(client);

	uv_unref((uv_handle_t*)&self->tcp_handle);
	free(self);
}

static void on_write_frame_done(uv_write_t* req, int status)
{
	struct vnc_write_request* rq = (struct vnc_write_request*)req;
	struct nvnc_client* client = rq->userdata;
	client->is_updating = false;
	free(rq->buffer.base);
}

enum rfb_encodings choose_frame_encoding(struct nvnc_client* client)
{
	for (size_t i = 0; i < client->n_encodings; ++i)
		switch (client->encodings[i]) {
		case RFB_ENCODING_RAW:
#ifdef ENABLE_TIGHT
		case RFB_ENCODING_TIGHT:
#endif
		case RFB_ENCODING_ZRLE:
			return client->encodings[i];
		default:
			break;
		}

	return -1;
}

void do_client_update_fb(uv_work_t* work)
{
	struct fb_update_work* update = (void*)work;
	struct nvnc_client* client = update->client;
	const struct nvnc_fb* fb = update->fb;

	enum rfb_encodings encoding = choose_frame_encoding(client);
	if (encoding == -1) {
		uv_read_stop((uv_stream_t*)&client->stream_handle);
		client_unref(client);
		return;
	}

	if (client->fourcc == DRM_FORMAT_INVALID) {
		rfb_pixfmt_from_fourcc(&client->pixfmt, fb->fourcc_format);
		client->fourcc = fb->fourcc_format;
	}

	switch (encoding) {
	case RFB_ENCODING_RAW:
		raw_encode_frame(&update->frame, &client->pixfmt, fb,
		                 &update->server_fmt, &update->region);
		break;
#ifdef ENABLE_TIGHT
	case RFB_ENCODING_TIGHT:
		tight_encode_frame(&update->frame, client, fb, &update->region);
		break;
#endif
	case RFB_ENCODING_ZRLE:
		zrle_encode_frame(&client->z_stream, &update->frame,
		                  &client->pixfmt, fb, &update->server_fmt,
		                  &update->region);
		break;
	default:
		break;
	}
}

void on_client_update_fb_done(uv_work_t* work, int status)
{
	(void)status;

	struct fb_update_work* update = (void*)work;
	struct nvnc_client* client = update->client;
	struct nvnc* server = client->server;
	struct vec* frame = &update->frame;

	if (!uv_is_closing((uv_handle_t*)&client->stream_handle))
		vnc__write2((uv_stream_t*)&client->stream_handle, frame->data,
		            frame->len, on_write_frame_done, client);
	else
		client->is_updating = false;

	client->n_pending_requests--;
	process_fb_update_requests(client);
	nvnc_fb_unref(update->fb);
	client_unref(client);

	pixman_region_fini(&update->region);
	free(update);
}

int schedule_client_update_fb(struct nvnc_client* client)
{
	struct nvnc_fb* fb = client->server->frame;
	assert(fb);

	struct fb_update_work* work = calloc(1, sizeof(*work));
	if (!work)
		return -1;

	if (rfb_pixfmt_from_fourcc(&work->server_fmt, fb->fourcc_format) < 0)
		goto pixfmt_failure;

	work->client = client;
	work->fb = fb;

	/* The client's damage is exchanged for an empty one */
	work->region = client->damage;
	pixman_region_init(&client->damage);

	int rc = vec_init(&work->frame, fb->width * fb->height * 3 / 2);
	if (rc < 0)
		goto vec_failure;

	client_ref(client);
	nvnc_fb_ref(fb);

	rc = uv_queue_work(uv_default_loop(), &work->work, do_client_update_fb,
	                   on_client_update_fb_done);
	if (rc < 0)
		goto queue_failure;

	return 0;

queue_failure:
	nvnc_fb_unref(fb);
	client_unref(client);
	vec_destroy(&work->frame);
vec_failure:
pixfmt_failure:
	free(work);
	return -1;
}

EXPORT
int nvnc_feed_frame(struct nvnc* self, struct nvnc_fb* fb,
                    const struct pixman_region16* damage)
{
	struct nvnc_client* client;

	if (self->frame)
		nvnc_fb_unref(self->frame);

	self->frame = fb;
	nvnc_fb_ref(self->frame);

	LIST_FOREACH (client, &self->clients, link) {
		if (uv_is_closing((uv_handle_t*)&client->stream_handle))
			continue;

		pixman_region_union(&client->damage, &client->damage,
		                    (struct pixman_region16*)damage);
		pixman_region_intersect_rect(&client->damage, &client->damage,
		                             0, 0, fb->width, fb->height);

		process_fb_update_requests(client);
	}

	return 0;
}

EXPORT
void nvnc_set_userdata(void* self, void* userdata)
{
	struct nvnc_common* common = self;
	common->userdata = userdata;
}

EXPORT
void* nvnc_get_userdata(const void* self)
{
	const struct nvnc_common* common = self;
	return common->userdata;
}

EXPORT
void nvnc_set_key_fn(struct nvnc* self, nvnc_key_fn fn)
{
	self->key_fn = fn;
}

EXPORT
void nvnc_set_pointer_fn(struct nvnc* self, nvnc_pointer_fn fn)
{
	self->pointer_fn = fn;
}

EXPORT
void nvnc_set_fb_req_fn(struct nvnc* self, nvnc_fb_req_fn fn)
{
	self->fb_req_fn = fn;
}

EXPORT
void nvnc_set_new_client_fn(struct nvnc* self, nvnc_client_fn fn)
{
	self->new_client_fn = fn;
}

EXPORT
void nvnc_set_client_cleanup_fn(struct nvnc_client* self, nvnc_client_fn fn)
{
	self->cleanup_fn = fn;
}

EXPORT
void nvnc_set_dimensions(struct nvnc* self, uint16_t width, uint16_t height,
                         uint32_t fourcc_format)
{
	self->display.width = width;
	self->display.height = height;
	self->display.pixfmt = fourcc_format;
}

EXPORT
struct nvnc* nvnc_get_server(const struct nvnc_client* client)
{
	return client->server;
}

EXPORT
void nvnc_set_name(struct nvnc* self, const char* name)
{
	strncpy(self->display.name, name, sizeof(self->display.name));
	self->display.name[sizeof(self->display.name) - 1] = '\0';
}
