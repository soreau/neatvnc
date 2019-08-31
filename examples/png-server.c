#include "neatvnc.h"

#include <stdio.h>
#include <uv.h>
#include <assert.h>
#include <pixman.h>

int read_png_file(struct nvnc_fb* fb, const char *filename);

void on_fb_req(struct nvnc *nvnc, bool incremental, uint16_t x, uint16_t y,
	       uint16_t width, uint16_t height)
{
	if (incremental)
		return;

	struct nvnc_fb *fb = nvnc_get_userdata(nvnc);
	assert(fb);

	struct pixman_region16 region;
	pixman_region_init_rect(&region, 0, 0, fb->width, fb->height);
	nvnc_update_fb(nvnc, fb, &region);
	pixman_region_fini(&region);
}

int main(int argc, char *argv[])
{
	const char *file = argv[1];

	if (!file) {
		printf("Missing argument\n");
		return 1;
	}

	struct nvnc_fb fb;
	if (read_png_file(&fb, file) < 0) {
		printf("Failed to read png file\n");
		return 1;
	}

	struct nvnc *server = nvnc_open("127.0.0.1", 5900);

	nvnc_set_dimensions(server, fb.width, fb.height, fb.fourcc_format);
	nvnc_set_name(server, file);
	nvnc_set_fb_req_fn(server, on_fb_req);
	nvnc_set_userdata(server, &fb);

	uv_run(uv_default_loop(), UV_RUN_DEFAULT);

	nvnc_close(server);
}