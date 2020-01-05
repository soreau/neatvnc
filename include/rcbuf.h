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

#pragma once

#include <stdlib.h>
#include <uv.h>

struct rcbuf {
	uv_buf_t uv;
	int ref;
};

static inline struct rcbuf* rcbuf_new(void* payload, size_t size)
{
	struct rcbuf* self = calloc(1, sizeof(*self));
	if (!self)
		return NULL;

	self->ref = 0;
	self->uv.base = payload;
	self->uv.len = size;

	return self;
}

static inline void rcbuf_ref(struct rcbuf* self)
{
	self->ref++;
}

static inline void rcbuf_unref(struct rcbuf* self)
{
	if (--self->ref > 0)
		return;

	free(self->uv.base);
	free(self);
}
