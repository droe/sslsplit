/*
 * SSLsplit - transparent and scalable SSL/TLS interception
 * Copyright (c) 2009-2014, Daniel Roethlisberger <daniel@roe.ch>
 * All rights reserved.
 * http://www.roe.ch/SSLsplit
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "sys.h"

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
static char template[] = "/tmp/" BNAME ".test.XXXXXX";
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
	asprintf(&file, "%s/file", basedir);
	asprintf(&lfile, "%s/lfile", basedir);
	asprintf(&dir, "%s/dir", basedir);
	asprintf(&ldir, "%s/ldir", basedir);
	asprintf(&notexist, "%s/DOES_NOT_EXIST", basedir);
	if (!file || !lfile || !dir || !ldir || !notexist) {
		perror("asprintf");
		exit(EXIT_FAILURE);
	}
	close(open(file, O_CREAT|O_WRONLY|O_APPEND, 0600));
	symlink(file, lfile);
	mkdir(dir, 0700);
	symlink(dir, ldir);
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

	asprintf(&cmd, "rm -r '%s'", basedir);
	if (cmd) {
		system(cmd);
	}
}

START_TEST(sys_mkpath_01)
{
	char *dir;

	asprintf(&dir, "%s/a/bb/ccc/dddd/eeeee/ffffff/ggggggg/hhhhhhhh",
	         basedir);
	fail_unless(!!dir, "asprintf failed");
	fail_unless(!sys_isdir(dir), "dir already sys_isdir()");
	fail_unless(!sys_mkpath(dir, 0755), "sys_mkpath failed");
	fail_unless(sys_isdir(dir), "dir not sys_isdir()");
	free(dir);
}
END_TEST

void
sys_dir_eachfile_cb(UNUSED const char *fn, void *arg)
{
	*((int*)arg) += 1;
	/* fprintf(stderr, "%s\n", fn); */
}

START_TEST(sys_dir_eachfile_01)
{
	int flag = 0;

	sys_dir_eachfile(TARGETDIR, sys_dir_eachfile_cb, &flag);

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

	return s;
}

/* vim: set noet ft=c: */
