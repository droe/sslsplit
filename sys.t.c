/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "sys.h"

#include "defaults.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>

#include <check.h>

#define TARGETDIR "extra/pki/targets"
static char template[] = "/tmp/sslsplit.test.XXXXXX";
static char *basedir;
static char *file, *lfile, *dir, *ldir, *notexist;

static void
sys_isdir_setup(void)
{
	basedir = strdup(template);
	if (!mkdtemp(basedir)) {
		perror("mkdtemp");
		exit(EXIT_FAILURE);
	}
	if (asprintf(&file, "%s/file", basedir) == -1) {
		perror("asprintf");
		exit(EXIT_FAILURE);
	}
	if (asprintf(&lfile, "%s/lfile", basedir) == -1) {
		perror("asprintf");
		exit(EXIT_FAILURE);
	}
	if (asprintf(&dir, "%s/dir", basedir) == -1) {
		perror("asprintf");
		exit(EXIT_FAILURE);
	}
	if (asprintf(&ldir, "%s/ldir", basedir) == -1) {
		perror("asprintf");
		exit(EXIT_FAILURE);
	}
	if (asprintf(&notexist, "%s/DOES_NOT_EXIST", basedir) == -1) {
		perror("asprintf");
		exit(EXIT_FAILURE);
	}
	close(open(file, O_CREAT|O_WRONLY|O_APPEND, DFLT_FILEMODE));
	if (symlink(file, lfile) == -1) {
		perror("symlink");
		exit(EXIT_FAILURE);
	}
	if (mkdir(dir, 0700) == -1) {
		perror("mkdir");
		exit(EXIT_FAILURE);
	}
	if (symlink(dir, ldir) == -1) {
		perror("symlink");
		exit(EXIT_FAILURE);
	}
}

static void
sys_isdir_teardown(void)
{
	unlink(lfile);
	unlink(file);
	unlink(ldir);
	rmdir(dir);
	rmdir(basedir);
	free(lfile);
	free(file);
	free(ldir);
	free(dir);
	free(notexist);
}

START_TEST(sys_isdir_01)
{
	fail_unless(sys_isdir(dir), "Directory !isdir");
}
END_TEST

START_TEST(sys_isdir_02)
{
	fail_unless(sys_isdir(ldir), "Symlink dir !isdir");
}
END_TEST

START_TEST(sys_isdir_03)
{
	fail_unless(!sys_isdir(notexist), "Not-exist isdir");
}
END_TEST

START_TEST(sys_isdir_04)
{
	fail_unless(!sys_isdir(file), "File isdir");
}
END_TEST

START_TEST(sys_isdir_05)
{
	fail_unless(!sys_isdir(lfile), "Symlink file isdir");
}
END_TEST

static void
sys_mkpath_setup(void)
{
	basedir = strdup(template);
	if (!mkdtemp(basedir)) {
		perror("mkdtemp");
		exit(EXIT_FAILURE);
	}
}

static void
sys_mkpath_teardown(void)
{
	char *cmd;
	int rv;

	rv = asprintf(&cmd, "rm -r '%s'", basedir);
	if ((rv != -1) && cmd) {
		rv = system(cmd);
		if (rv == -1) {
			perror("system");
			exit(EXIT_FAILURE);
		}
	}
}

START_TEST(sys_mkpath_01)
{
	char *dir;
	int rv;

	rv = asprintf(&dir, "%s/a/bb/ccc/dddd/eeeee/ffffff/ggggggg/hhhhhhhh",
	              basedir);
	fail_unless((rv != -1) && !!dir, "asprintf failed");
	fail_unless(!sys_isdir(dir), "dir already sys_isdir()");
	fail_unless(!sys_mkpath(dir, DFLT_DIRMODE), "sys_mkpath failed");
	fail_unless(sys_isdir(dir), "dir not sys_isdir()");
	free(dir);
}
END_TEST

START_TEST(sys_realdir_01)
{
	char *rd;

	rd = sys_realdir("./extra/../sys.t.c");
	fail_unless(!!rd, "sys_realdir failed");
	fail_unless(!!strstr(rd, "/sys.t.c"), "filename not found");
	fail_unless(!strstr(rd, "/extra/"), "extra in path");
	fail_unless(!strstr(rd, "/../"), "dot-dot in path");
	free(rd);
}
END_TEST

START_TEST(sys_realdir_02)
{
	char *rd;

	rd = sys_realdir("/foo/bar/baz");
	fail_unless(!rd, "sys_realdir did not fail");
	fail_unless(errno == ENOENT, "errno not ENOENT");
}
END_TEST

START_TEST(sys_realdir_03)
{
	char *rd;

	rd = sys_realdir("foobarbaz");
	fail_unless(!!rd, "sys_realdir failed");
	fail_unless(!!strstr(rd, "/foobarbaz"), "filename not found or dir");
	free(rd);
}
END_TEST

START_TEST(sys_realdir_04)
{
	char *rd;

	rd = sys_realdir("");
	fail_unless(!rd, "sys_realdir did not fail");
}
END_TEST

int
sys_dir_eachfile_cb(UNUSED const char *fn, void *arg)
{
	*((int*)arg) += 1;
	/* fprintf(stderr, "%s\n", fn); */
	return 0;
}

START_TEST(sys_dir_eachfile_01)
{
	int flag = 0;
	int rv;

	rv = sys_dir_eachfile(TARGETDIR, sys_dir_eachfile_cb, &flag);

	fail_unless(rv == 0, "Did not return success");
	fail_unless(flag == 2, "Iterated wrong number of files");
}
END_TEST

START_TEST(sys_get_cpu_cores_01)
{
	fail_unless(sys_get_cpu_cores() >= 1, "Number of CPU cores < 1");
}
END_TEST

void *
thrmain(void *arg)
{
	*((int*)arg) = 1;
	return (void*) 2;
}

START_TEST(pthread_create_01)
{
	pthread_t tid;
	int x = 0;
	void *rv;
	fail_unless(!pthread_create(&tid, NULL, thrmain, &x),
	            "Cannot create thread");
	fail_unless(!pthread_join(tid, &rv), "Cannot join thread");
	fail_unless(x == 1, "Thread failed to update x");
	fail_unless(rv == (void*) 2, "Thread return value mismatch");
}
END_TEST

START_TEST(sys_user_str_01)
{
	char *name = sys_user_str(0);
	fail_unless(!strcmp(name, TEST_ZEROUSR), "User 0 name mismatch");
}
END_TEST

START_TEST(sys_group_str_01)
{
	char *name = sys_group_str(0);
	fail_unless(!strcmp(name, TEST_ZEROGRP), "Group 0 name mismatch");
}
END_TEST

START_TEST(sys_ip46str_sanitize_01)
{
	char *clean;

	clean = sys_ip46str_sanitize("2a01:7c8:aab0:1fb::1");
	fail_unless(!!clean, "Sanitized string is NULL");
	fail_unless(!strcmp(clean, "2a01_7c8_aab0_1fb__1"),
	            "Unexpected result");
	free(clean);
}
END_TEST

START_TEST(sys_ip46str_sanitize_02)
{
	char *clean;

	clean = sys_ip46str_sanitize("127.0.0.1");
	fail_unless(!!clean, "Sanitized string is NULL");
	fail_unless(!strcmp(clean, "127.0.0.1"),
	            "Unexpected result");
	free(clean);
}
END_TEST

START_TEST(sys_ip46str_sanitize_03)
{
	char *clean;

	clean = sys_ip46str_sanitize("fe80::5626:96ff:e4a7:f583%en0");
	fail_unless(!!clean, "Sanitized string is NULL");
	fail_unless(!strcmp(clean, "fe80__5626_96ff_e4a7_f583_en0"),
	            "Unexpected result");
	free(clean);
}
END_TEST


Suite *
sys_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("sys");

	tc = tcase_create("sys_isdir");
	tcase_add_unchecked_fixture(tc, sys_isdir_setup, sys_isdir_teardown);
	tcase_add_test(tc, sys_isdir_01);
	tcase_add_test(tc, sys_isdir_02);
	tcase_add_test(tc, sys_isdir_03);
	tcase_add_test(tc, sys_isdir_04);
	tcase_add_test(tc, sys_isdir_05);
	suite_add_tcase(s, tc);

	tc = tcase_create("sys_mkpath");
	tcase_add_unchecked_fixture(tc, sys_mkpath_setup, sys_mkpath_teardown);
	tcase_add_test(tc, sys_mkpath_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("sys_realdir");
	tcase_add_test(tc, sys_realdir_01);
	tcase_add_test(tc, sys_realdir_02);
	tcase_add_test(tc, sys_realdir_03);
	tcase_add_test(tc, sys_realdir_04);
	suite_add_tcase(s, tc);

	tc = tcase_create("sys_dir_eachfile");
	tcase_add_test(tc, sys_dir_eachfile_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("sys_get_cpu_cores");
	tcase_add_test(tc, sys_get_cpu_cores_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("pthread_create");
	tcase_add_test(tc, pthread_create_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("sys_user_str");
	tcase_add_test(tc, sys_user_str_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("sys_group_str");
	tcase_add_test(tc, sys_group_str_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("sys_ip46str_sanitize");
	tcase_add_test(tc, sys_ip46str_sanitize_01);
	tcase_add_test(tc, sys_ip46str_sanitize_02);
	tcase_add_test(tc, sys_ip46str_sanitize_03);
	suite_add_tcase(s, tc);

	return s;
}

/* vim: set noet ft=c: */
