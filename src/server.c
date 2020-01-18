/*
 * Copyright (c) 2019 - 2020 Andri Yngvason
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
#include "stream.h"
#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>
#include <assert.h>
#include <uv.h>
#include <libdrm/drm_fourcc.h>
#include <pixman.h>
#include <pthread.h>

#ifdef ENABLE_TLS
#include <gnutls/gnutls.h>
#endif

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

static void client_close(struct nvnc_client* client)
{
	stream_destroy(client->net_stream);

	nvnc_client_fn fn = client->cleanup_fn;
	if (fn)
		fn(client);

	deflateEnd(&client->z_stream);

	LIST_REMOVE(client, link);
	pixman_region_fini(&client->damage);
	free(client);
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

static void close_after_write(void* userdata, enum stream_req_status status)
{
	struct nvnc_client* client = userdata;
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

	struct rcbuf* payload =
		rcbuf_from_mem(buffer,
		               1 + sizeof(*reason) + strlen(reason_string));
	stream_write(client->net_stream, payload, close_after_write, client);

	return 0;
}

static int on_version_message(struct nvnc_client* client)
{
	struct nvnc* server = client->server;

	if (client->buffer_len - client->buffer_index < 12)
		return 0;

	char version_string[13];
	memcpy(version_string, client->msg_buffer + client->buffer_index, 12);
	version_string[12] = '\0';

	if (strcmp(RFB_VERSION_MESSAGE, version_string) != 0)
		return handle_unsupported_version(client);

	struct rfb_security_types_msg security = { 0 };
	security.n = 1;
	security.types[0] = RFB_SECURITY_TYPE_NONE;

#ifdef ENABLE_TLS
	if (server->auth_fn)
		security.types[0] = RFB_SECURITY_TYPE_VENCRYPT;
#endif

	struct rcbuf* payload = rcbuf_from_mem(&security, sizeof(security));
	stream_write(client->net_stream, payload, NULL, NULL);

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

	struct rcbuf* payload =
		rcbuf_from_mem(buffer, sizeof(*result) + sizeof(*reason) +
			               strlen(reason_string));
	stream_write(client->net_stream, payload, close_after_write, client);

	return 0;
}

static int security_handshake_ok(struct nvnc_client* client)
{
	uint32_t result = htonl(RFB_SECURITY_HANDSHAKE_OK);
	struct rcbuf* payload = rcbuf_from_mem(&result, sizeof(result));
	return stream_write(client->net_stream, payload, NULL, NULL);
}

static int vencrypt_send_version(struct nvnc_client* client)
{
	struct rfb_vencrypt_version_msg msg = {
		.major = 0,
		.minor = 2,
	};

	struct rcbuf* payload = rcbuf_from_mem(&msg, sizeof(msg));
	return stream_write(client->net_stream, payload, NULL, NULL);
}

static int send_byte(struct nvnc_client* client, uint8_t value)
{
	struct rcbuf* payload = rcbuf_from_mem(&value, sizeof(value));
	return stream_write(client->net_stream, payload, NULL, NULL);
}

static int on_vencrypt_version_message(struct nvnc_client* client)
{
	struct rfb_vencrypt_version_msg* msg =
		(struct rfb_vencrypt_version_msg*)&client->msg_buffer[client->buffer_index];

	if (client->buffer_len - client->buffer_index < sizeof(*msg))
		return 0;

	if (msg->major != 0 || msg->minor != 2) {
		// TODO: Say unsupported vencrypt type in message
		handle_invalid_security_type(client);
		return sizeof(*msg);
	}

	send_byte(client, 0);

	struct rfb_vencrypt_subtypes_msg result = { .n = 1, };
	result.types[0] = htonl(RFB_VENCRYPT_X509_PLAIN);

	struct rcbuf* payload = rcbuf_from_mem(&result, sizeof(result));
	stream_write(client->net_stream, payload, NULL, NULL);

	client->state = VNC_CLIENT_STATE_WAITING_FOR_VENCRYPT_SUBTYPE;

	send_byte(client, 1);

	return sizeof(*msg);
}

static int on_vencrypt_subtype_message(struct nvnc_client* client)
{
	uint32_t* msg = (uint32_t*)&client->msg_buffer[client->buffer_index];

	if (client->buffer_len - client->buffer_index < sizeof(*msg))
		return 0;

	enum rfb_vencrypt_subtype subtype = ntohl(*msg);

	if (subtype != RFB_VENCRYPT_X509_PLAIN) {
		client_unref(client);
		return 0;
	}

	if (stream_upgrade_to_tls(client->net_stream, client->server->tls_creds) < 0) {
		client_unref(client);
		return 0;
	}

	client->state = VNC_CLIENT_STATE_WAITING_FOR_VENCRYPT_PLAIN_AUTH;

	// TODO: For tls send one byte containing only 1
	return sizeof(*msg);
}

static int on_vencrypt_plain_auth_message(struct nvnc_client* client)
{
	struct nvnc* server = client->server;

	struct rfb_vencrypt_plain_auth_msg* msg =
	        (void*)(client->msg_buffer + client->buffer_index);

	if (client->buffer_len - client->buffer_index < sizeof(*msg))
		return 0;

	uint32_t ulen = ntohl(msg->username_len);
	uint32_t plen = ntohl(msg->password_len);

	if (client->buffer_len - client->buffer_index < sizeof(*msg) + ulen + plen)
		return 0;

	char username[256];
	char password[256];

	memcpy(username, msg->text, MIN(ulen, sizeof(username) - 1));
	memcpy(password, msg->text + ulen, MIN(plen, sizeof(password) - 1));

	username[MIN(ulen, sizeof(username) - 1)] = '\0';
	password[MIN(plen, sizeof(password) - 1)] = '\0';

	if (server->auth_fn(username, password, server->auth_ud))
		security_handshake_ok(client);
	else
		handle_invalid_security_type(client); // TODO say wrong auth

	client->state = VNC_CLIENT_STATE_WAITING_FOR_INIT;

	return sizeof(*msg) + ulen + plen;
}

static int on_security_message(struct nvnc_client* client)
{
	if (client->buffer_len - client->buffer_index < 1)
		return 0;

	uint8_t type = client->msg_buffer[client->buffer_index];

	switch (type) {
	case RFB_SECURITY_TYPE_NONE:
		security_handshake_ok(client);
		client->state = VNC_CLIENT_STATE_WAITING_FOR_INIT;
		break;
	case RFB_SECURITY_TYPE_VENCRYPT:
		vencrypt_send_version(client);
		client->state = VNC_CLIENT_STATE_WAITING_FOR_VENCRYPT_VERSION;
		break;
	default:
		handle_invalid_security_type(client);
		break;
	}

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

	struct rcbuf* payload = rcbuf_new(msg, size);
	stream_write(client->net_stream, payload, NULL, NULL);
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

	int n_encodings = MIN(MAX_ENCODINGS, ntohs(msg->n_encodings));
	int n = 0;

	if (client->buffer_len - client->buffer_index <
	    sizeof(*msg) + n_encodings * 4)
		return 0;

	for (int i = 0; i < n_encodings; ++i) {
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

	if (client->net_stream->fd < 0)
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
	case VNC_CLIENT_STATE_WAITING_FOR_VENCRYPT_VERSION:
		return on_vencrypt_version_message(client);
	case VNC_CLIENT_STATE_WAITING_FOR_VENCRYPT_SUBTYPE:
		return on_vencrypt_subtype_message(client);
	case VNC_CLIENT_STATE_WAITING_FOR_VENCRYPT_PLAIN_AUTH:
		return on_vencrypt_plain_auth_message(client);
	case VNC_CLIENT_STATE_READY:
		return on_client_message(client);
	}

	abort();
	return 0;
}

static void on_client_event(struct stream* stream, enum stream_event event)
{
	struct nvnc_client* client = stream->userdata;

	if (event == STREAM_EVENT_REMOTE_CLOSED) {
		stream_close(stream);
		client_unref(client);
		return;
	}

#define BUF_SIZE 16384
	char* buf = malloc(BUF_SIZE);
	ssize_t n_read = stream_read(stream, buf, BUF_SIZE);
#undef BUF_SIZE

	if (n_read == 0)
		goto done;

	if (n_read < 0) {
		if (errno != EAGAIN) {
			stream_close(stream);
			client_unref(client);
		}

		goto done;
	}

	assert(client->buffer_index == 0);

	if ((size_t)n_read > MSG_BUFFER_SIZE - client->buffer_len) {
		/* Can't handle this. Let's just give up */
		client->state = VNC_CLIENT_STATE_ERROR;
		client_unref(client);
		goto done;
	}

	memcpy(client->msg_buffer + client->buffer_len, buf, n_read);
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
	free(buf);
}

static void on_connection(uv_poll_t* poll_handle, int status, int events)
{
	struct nvnc* server =
	        container_of(poll_handle, struct nvnc, poll_handle);

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

	int fd = accept(server->fd, NULL, 0);
	assert(fd >= 0); //TODO

	client->net_stream = stream_new(fd, on_client_event, client);
	assert(client->net_stream); // TODO

	struct rcbuf* payload = rcbuf_from_string(RFB_VERSION_MESSAGE);
	assert(payload); //TODO
	stream_write(client->net_stream, payload, NULL, NULL);

	LIST_INSERT_HEAD(&server->clients, client, link);

	client->state = VNC_CLIENT_STATE_WAITING_FOR_VERSION;
}

EXPORT
struct nvnc* nvnc_open(const char* address, uint16_t port)
{
	struct nvnc* self = calloc(1, sizeof(*self));
	if (!self)
		return NULL;

	strcpy(self->display.name, DEFAULT_NAME);

	LIST_INIT(&self->clients);

	self->fd = socket(AF_INET, SOCK_STREAM, 0);
	if (self->fd < 0)
		return NULL;

	int one = 1;
	if (setsockopt(self->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int)) < 0)
		goto failure;

	struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(address);
	addr.sin_port = htons(port);

	if (bind(self->fd, (const struct sockaddr*)&addr, sizeof(addr)) < 0)
		goto failure;

	if (listen(self->fd, 16) < 0)
		goto failure;

	uv_poll_init(uv_default_loop(), &self->poll_handle, self->fd);
	uv_poll_start(&self->poll_handle, UV_READABLE, on_connection);

	return self;

failure:
	close(self->fd);
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

	uv_poll_stop(&self->poll_handle);
	close(self->fd);

#ifdef ENABLE_TLS
	gnutls_certificate_free_credentials(self->tls_creds);

	// TODO: Do something with this that doesn't ruin things for others
	gnutls_global_deinit();
#endif

	free(self);
}

static void on_write_frame_done(void* userdata, enum stream_req_status status)
{
	struct nvnc_client* client = userdata;
	client->is_updating = false;
	client_unref(client);
}

enum rfb_encodings choose_frame_encoding(struct nvnc_client* client)
{
	for (int i = 0; i < client->n_encodings; ++i)
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
	assert(encoding != -1);

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
	struct vec* frame = &update->frame;

	if (client->net_stream->state != STREAM_STATE_CLOSED) {
		struct rcbuf* payload = rcbuf_new(frame->data, frame->len);
		stream_write(client->net_stream, payload, on_write_frame_done,
		             client);
	} else {
		client->is_updating = false;
		vec_destroy(frame);
	}

	client->n_pending_requests--;
	process_fb_update_requests(client);
	nvnc_fb_unref(update->fb);

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
		if (client->net_stream->state == STREAM_STATE_CLOSED)
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

EXPORT
bool nvnc_has_auth(void)
{
#ifdef ENABLE_TLS
	return true;
#else
	return false;
#endif
}

EXPORT
int nvnc_enable_auth(struct nvnc* self, const char* privkey_path,
                     const char* cert_path, nvnc_auth_fn auth_fn,
                     void* userdata)
{
#ifdef ENABLE_TLS
	if (self->tls_creds)
		return -1;

	// TODO: There may be a better place for this
	gnutls_global_init();

	gnutls_certificate_allocate_credentials(&self->tls_creds);
	gnutls_certificate_set_x509_key_file(
		self->tls_creds, cert_path, privkey_path, GNUTLS_X509_FMT_PEM);

	self->auth_fn = auth_fn;
	self->auth_ud = userdata;

	return 0;
#endif
	return -1;
}
