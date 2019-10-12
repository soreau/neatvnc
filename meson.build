project(
	'neatvnc',
	'c',
	version: '0.0.0',
	license: 'ISC',
	default_options: [
		'c_std=gnu11',
	],
)

add_project_arguments([
	'-D_GNU_SOURCE',
	'-fvisibility=hidden',
], language: 'c')

cc = meson.get_compiler('c')

libm = cc.find_library('m', required: false)

pixman = dependency('pixman-1')
libuv = dependency('libuv')

inc = include_directories('include', 'contrib/miniz')

sources = [
	'src/server.c',
	'src/util.c',
	'src/vec.c',
	'src/zrle.c',
	'src/raw-encoding.c',
	'src/pixels.c',
	'src/damage.c',
	'src/fb.c',
	'contrib/miniz/miniz.c',
]

dependencies = [
	libm,
	pixman,
	libuv,
]

shared_library(
	'neatvnc',
	sources,
	dependencies: dependencies,
	include_directories: inc,
	install: true,
)

install_headers('include/neatvnc.h')