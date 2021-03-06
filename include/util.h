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

#pragma once

#include <uv.h>
#include <unistd.h>

struct rfb_pixel_format;

struct vnc_write_request {
	uv_write_t request;
	uv_write_cb on_done;
	uv_buf_t buffer;
	void* userdata;
};

int vnc__write(uv_stream_t* stream, const void* payload, size_t size,
               uv_write_cb on_done);

int vnc__write2(uv_stream_t* stream, const void* payload, size_t size,
                uv_write_cb on_done, void* userdata);

int rfb_pixfmt_from_fourcc(struct rfb_pixel_format* dst, uint32_t src);
