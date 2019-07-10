/**
 * collectd - src/match_ipaddress.c
 * Copyright (C) 2019 Takuro Ashie <ashie@clear-code.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *   Takuro Ashie <ashie at clear-code.com>
 **/

#include "collectd.h"
#include "filter_chain.h"
#include "utils/avltree/avltree.h"
#include "utils/common/common.h"
#include <arpa/inet.h>

#define log_debug(...) DEBUG("match_ipaddress: " __VA_ARGS__)
#define log_info(...) INFO("match_ipaddress: " __VA_ARGS__)
#define log_warn(...) WARN("match_ipaddress: " __VA_ARGS__)
#define log_err(...) ERROR("match_ipaddress: " __VA_ARGS__)

struct match_ipaddress_s {
  time_t mtime;
  char *file_path;
  bool invert;
  c_avl_tree_t *addresses;
  pthread_rwlock_t addresses_lock;
};
typedef struct match_ipaddress_s match_ipaddress_t;

static void free_addresses(c_avl_tree_t *addresses) /* {{{ */
{
  int status;

  if (addresses == NULL)
    return;

  while (true) {
    char *key = NULL;
    char *value = NULL;

    status = c_avl_pick(addresses, (void *)&key, (void *)&value);
    if (status != 0)
      break;

    sfree(key);
    // key == value
  }

  c_avl_destroy(addresses);
} /* }}} void free_addresses */

static int read_file(match_ipaddress_t *m) /* {{{ */
{
  FILE *fh;
  char buffer[64];
  struct flock fl = {0};
  c_avl_tree_t *tree;
  int status;

  fh = fopen(m->file_path, "r");
  if (fh == NULL)
    return -1;

  fl.l_type = F_RDLCK;
  fl.l_whence = SEEK_SET;

  status = fcntl(fileno(fh), F_SETLK, &fl);
  if (status != 0) {
    fclose(fh);
    return -1;
  }

  tree = c_avl_create((int (*)(const void *, const void *))strcmp);
  if (tree == NULL) {
    fclose(fh);
    return -1;
  }

  while (fgets(buffer, sizeof(buffer), fh) != NULL) /* {{{ */
  {
    size_t len;
    char *ipaddress, *ipaddress_copy;
    struct in_addr addr4;
    struct in6_addr addr6;

    buffer[sizeof(buffer) - 1] = '\0';
    len = strlen(buffer);

    /* Remove trailing newline characters. */
    while ((len > 0) &&
           ((buffer[len - 1] == '\n') || (buffer[len - 1] == '\r'))) {
      len--;
      buffer[len] = 0;
    }

    /* Seek first non-space character */
    ipaddress = buffer;
    while ((*ipaddress != 0) && isspace((int)*ipaddress))
      ipaddress++;

    /* Skip empty lines and comments */
    if ((ipaddress[0] == 0) || (ipaddress[0] == '#'))
      continue;

    if (inet_pton(AF_INET, ipaddress, &addr4) <= 0 &&
	inet_pton(AF_INET6, ipaddress, &addr6) <= 0) {
      log_err("Invalid IP address: file = %s, address = %s",
	      m->file_path, ipaddress);
      continue;
    }

    ipaddress_copy = sstrdup(ipaddress);

    status = c_avl_insert(tree, ipaddress_copy, ipaddress_copy);
    if (status != 0) {
      sfree(ipaddress_copy);
      continue;
    }

    log_debug("ipaddress: %s", ipaddress);
  } /* }}} while (fgets) */

  fclose(fh);

  pthread_rwlock_wrlock(&m->addresses_lock);
  free_addresses(m->addresses);
  m->addresses = tree;
  pthread_rwlock_unlock(&m->addresses_lock);

  return 0;
} /* }}} int read_file */

static int check_file(match_ipaddress_t *m) /* {{{ */
{
  struct stat statbuf = {0};
  int status;

  status = stat(m->file_path, &statbuf);
  if (status != 0)
    return -1;

  if (m->mtime >= statbuf.st_mtime)
    return 0;

  status = read_file(m);
  if (status == 0)
    m->mtime = statbuf.st_mtime;

  return status;
} /* }}} int check_file */

static int match_ipaddress_create(const oconfig_item_t *ci, void **user_data) /* {{{ */
{
  match_ipaddress_t *m;
  int status = 0;

  m = calloc(1, sizeof(*m));
  if (m == NULL) {
    log_err("calloc failed.");
    return -ENOMEM;
  }

  m->file_path = NULL;
  m->addresses = NULL;
  m->invert = false;
  status = pthread_rwlock_init(&m->addresses_lock, NULL);
  if (status != 0) {
    log_err("Failed to initialize rwlock, err %u", status);
    return status;
  }

  status = 0;
  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;

    if (strcasecmp("FilePath", child->key) == 0)
      status = cf_util_get_string(child, &m->file_path);
    else if (strcasecmp("Invert", child->key) == 0)
      status = cf_util_get_boolean(child, &m->invert);
    else {
      log_err("The `%s' configuration option is not understood and "
              "will be ignored.",
              child->key);
      status = 0;
    }

    if (status != 0)
      break;
  }

  return status;
}

static void match_ipaddress_free(match_ipaddress_t *m) /* {{{ */
{
  free_addresses(m->addresses);
  sfree(m->file_path);
  sfree(m);
} /* }}} void match_ipaddress_free */

static int match_ipaddress_destroy(void **user_data) /* {{{ */
{
  if ((user_data != NULL) && (*user_data != NULL))
    match_ipaddress_free(*user_data);
  return 0;
} /* }}} int match_ipaddress_destroy */

static int match_ipaddress_match(const data_set_t *ds, const value_list_t *vl, /* {{{ */
				 notification_meta_t __attribute__((unused)) * *meta,
				 void **user_data) {
  match_ipaddress_t *m;
  int match_value = FC_MATCH_MATCHES;
  int nomatch_value = FC_MATCH_NO_MATCH;
  char *ipaddress = NULL;
  int status;

  if ((user_data == NULL) || (*user_data == NULL))
    return -1;

  m = *user_data;

  if (m->invert) {
    match_value = FC_MATCH_NO_MATCH;
    nomatch_value = FC_MATCH_MATCHES;
  }

  if (vl->meta == NULL)
    return nomatch_value;

  status = meta_data_get_string(vl->meta, "network:ip_address", &ipaddress);
  if (status == (-ENOENT)) /* key is not present */
    return nomatch_value;

  check_file(m);

  pthread_rwlock_rdlock(&m->addresses_lock);
  if (m->addresses)
    status = c_avl_get(m->addresses, ipaddress, NULL);
  else
    status = -1;
  pthread_rwlock_unlock(&m->addresses_lock);

  if (status == 0)
    return match_value;
  else
    return nomatch_value;
} /* }}} int match_ipaddress_match */

void module_register(void) {
  match_proc_t mproc = {0};

  mproc.create = match_ipaddress_create;
  mproc.destroy = match_ipaddress_destroy;
  mproc.match = match_ipaddress_match;
  fc_register_match("ipaddress", mproc);
} /* module_register */
