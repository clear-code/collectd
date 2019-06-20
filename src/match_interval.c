/**
 * collectd - src/match_interval.c
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
#include "daemon/utils_avltree.h"
#include "daemon/common.h"

#define log_debug(...) DEBUG("match_interval: " __VA_ARGS__)
#define log_info(...) INFO("match_interval: " __VA_ARGS__)
#define log_warn(...) WARN("match_interval: " __VA_ARGS__)
#define log_err(...) ERROR("match_interval: " __VA_ARGS__)

/*
 * private data types
 */
struct mi_match_s;
typedef struct mi_match_s mi_match_t;
enum update_type_e {
  UPDATE_TIMESTAMP_ALWAYS,
  UPDATE_TIMESTAMP_MATCH,
  UPDATE_TIMESTAMP_UNMATCH
};
typedef enum update_type_e update_type_t;
struct mi_match_s {
  cdtime_t min;
  cdtime_t max;
  cdtime_t expire;
  int invert;
  update_type_t update_type;

  cdtime_t next_expire_time;
  c_avl_tree_t *timestamps;
  pthread_rwlock_t lock;
};

/*
 * internal helper functions
 */
static void mi_free_match(mi_match_t *m) /* {{{ */
{
  char *key = NULL;
  cdtime_t *value = NULL;
  for (; c_avl_pick(m->timestamps, (void *)&key, (void *)&value) == 0;) {
    sfree(key);
    sfree(value);
  }
  c_avl_destroy(m->timestamps);
  sfree(m);
} /* }}} void mi_free_match */

static int mi_config_add_time(cdtime_t *ret_value, /* {{{ */
                              oconfig_item_t *ci) {

  if ((ci->values_num != 1) || (ci->values[0].type != OCONFIG_TYPE_NUMBER)) {
    ERROR("`interval' match: `%s' needs exactly one numeric argument.",
          ci->key);
    return -1;
  }

  *ret_value = TIME_T_TO_CDTIME_T(ci->values[0].value.number);

  return 0;
} /* }}} int mi_config_add_gauge */

static int mi_config_add_boolean(int *ret_value, /* {{{ */
                                 oconfig_item_t *ci) {

  if ((ci->values_num != 1) || (ci->values[0].type != OCONFIG_TYPE_BOOLEAN)) {
    ERROR("`interval' match: `%s' needs exactly one boolean argument.",
          ci->key);
    return -1;
  }

  if (ci->values[0].value.boolean)
    *ret_value = 1;
  else
    *ret_value = 0;

  return 0;
} /* }}} int mi_config_add_boolean */

static int mi_config_set_update_type(mi_match_t *m, /* {{{ */
                                     oconfig_item_t *ci) {
  char *value;

  if ((ci->values_num != 1) || (ci->values[0].type != OCONFIG_TYPE_STRING)) {
    log_err("'%s' needs exactly one string argument.", ci->key);
    return -1;
  }

  value = ci->values[0].value.string;

  if (value && !strcasecmp(value, "always")) {
    m->update_type = UPDATE_TIMESTAMP_ALWAYS;
  } else if (value && !strcasecmp(value, "match")) {
    m->update_type = UPDATE_TIMESTAMP_MATCH;
  } else if (value && !strcasecmp(value, "unmatch")) {
    m->update_type = UPDATE_TIMESTAMP_UNMATCH;
  } else {
    log_err("Unknown value '%s' for '%s'", value, ci->key);
  }

  return 0;
} /* }}} int mi_config_add_gauge */

static void check_expire(mi_match_t *m) {
  cdtime_t now = cdtime();
  cdtime_t expire_check_duration;
  time_t one_day_in_sec = 60 * 60 * 24;
  cdtime_t one_day = TIME_T_TO_CDTIME_T(one_day_in_sec);
  c_avl_iterator_t *itr;
  char **keys = NULL;
  uint64_t i, keys_len = 0, keys_array_size = 0, step = 100;

  pthread_rwlock_rdlock(&m->lock);

  if (m->expire <= 0) {
    pthread_rwlock_unlock(&m->lock);
    return;
  }

  if (now < m->next_expire_time) {
    pthread_rwlock_unlock(&m->lock);
    return;
  }

  pthread_rwlock_unlock(&m->lock);
  pthread_rwlock_wrlock(&m->lock);

  keys_array_size = step;
  keys = realloc(keys, keys_array_size * sizeof(char *));
  itr = c_avl_get_iterator(m->timestamps);
  if (itr) {
    char *key = NULL;
    cdtime_t *value = NULL;
    while (c_avl_iterator_next(itr, (void *)&key, (void *)&value) == 0) {
      if (!value || *value + m->expire >= now) {
        keys_len++;
        if (keys_len > keys_array_size) {
          keys_array_size += step;
          keys = realloc(keys, keys_array_size * sizeof(char *));
        }
        keys[keys_len - 1] = key;
      }
    }
    c_avl_iterator_destroy(itr);
  }

  for (i = 0; i < keys_len; i++) {
    char *key = NULL;
    cdtime_t *value = NULL;
    log_debug("Expire: %s", keys[i]);
    c_avl_remove(m->timestamps, keys[i], (void *)&key, (void *)&value);
    sfree(key);
    sfree(value);
  }
  sfree(keys);

  if (m->expire > one_day * 3)
    expire_check_duration = one_day;
  else
    expire_check_duration = TIME_T_TO_CDTIME_T(one_day_in_sec / 4);

  m->next_expire_time = cdtime() + expire_check_duration;

  pthread_rwlock_unlock(&m->lock);
}

static int mi_create(const oconfig_item_t *ci, void **user_data) /* {{{ */
{
  mi_match_t *m;
  int status = 0;

  m = calloc(1, sizeof(*m));
  if (m == NULL) {
    ERROR("mi_create: calloc failed.");
    return -ENOMEM;
  }

  m->update_type = UPDATE_TIMESTAMP_ALWAYS;
  m->timestamps = c_avl_create((int (*)(const void *, const void *))strcmp);
  status = pthread_rwlock_init(&m->lock, NULL);
  if (status != 0) {
    log_err("Failed to initialize rwlock, err %u", status);
    return status;
  }

  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;

    if (strcasecmp("Min", child->key) == 0)
      status = mi_config_add_time(&m->min, child);
    else if (strcasecmp("Max", child->key) == 0)
      status = mi_config_add_time(&m->max, child);
    else if (strcasecmp("Expire", child->key) == 0)
      status = mi_config_add_time(&m->expire, child);
    else if (strcasecmp("Invert", child->key) == 0)
      status = mi_config_add_boolean(&m->invert, child);
    else if (strcasecmp("UpdateTimestamp", child->key) == 0)
      status = mi_config_set_update_type(m, child);
    else {
      ERROR("`interval' match: The `%s' configuration option is not "
            "understood and will be ignored.",
            child->key);
      status = 0;
    }

    if (status != 0)
      break;
  }

  *user_data = m;

  return status;
} /* }}} int mi_create */

static int mi_destroy(void **user_data) /* {{{ */
{
  if ((user_data != NULL) && (*user_data != NULL))
    mi_free_match(*user_data);
  return 0;
} /* }}} int mi_destroy */

static int mi_match(const data_set_t *ds, const value_list_t *vl, /* {{{ */
                    notification_meta_t __attribute__((unused)) * *meta,
                    void **user_data) {
  mi_match_t *m;
  int match_status = FC_MATCH_MATCHES;
  int nomatch_status = FC_MATCH_NO_MATCH;
  int retval;
  char identifier[768], *ipaddress;
  int status;
  cdtime_t *timestamp_p, timestamp, now = cdtime(), diff;
  _Bool update_timestamp = 0;

  if ((user_data == NULL) || (*user_data == NULL))
    return FC_MATCH_NO_MATCH;

  m = *user_data;

  check_expire(m);

  status = FORMAT_VL(identifier, sizeof(identifier), vl);
  if (status != 0)
    return FC_MATCH_NO_MATCH;

  if (vl->meta &&
      !meta_data_get_string(vl->meta, "network:ip_address", &ipaddress)) {
    int pos = strlen(identifier);
    snprintf(identifier + pos, sizeof(identifier) - pos, "@%s", ipaddress);
    sfree(ipaddress);
  }

  pthread_rwlock_rdlock(&m->lock);
  status = c_avl_get(m->timestamps, identifier, (void **)&timestamp_p);
  if (status == 0)
    timestamp = *timestamp_p;
  pthread_rwlock_unlock(&m->lock);

  if (status != 0) {
    /* not found */
    pthread_rwlock_wrlock(&m->lock);
    cdtime_t *data = calloc(1, sizeof(cdtime_t));
    if (data == NULL) {
      log_err("Out of memory.");
      pthread_rwlock_unlock(&m->lock);
      return FC_MATCH_NO_MATCH;
    }
    *data = now;
    c_avl_insert(m->timestamps, sstrdup(identifier), data);
    pthread_rwlock_unlock(&m->lock);
    return FC_MATCH_NO_MATCH;
  }

  /* found */
  diff = now - timestamp;

  if (m->expire > 0 && diff >= m->expire)
    return FC_MATCH_NO_MATCH;

  if (m->invert) {
    match_status = FC_MATCH_NO_MATCH;
    nomatch_status = FC_MATCH_MATCHES;
  }

  if ((m->min <= 0 || diff >= m->min) && (m->max <= 0 || diff <= m->max)) {
    retval = match_status;
  } else {
    retval = nomatch_status;
  }

  if (m->update_type == UPDATE_TIMESTAMP_ALWAYS) {
    update_timestamp = 1;
  } else if (m->update_type == UPDATE_TIMESTAMP_MATCH) {
    if (retval == FC_MATCH_MATCHES)
      update_timestamp = 1;
  } else if (m->update_type == UPDATE_TIMESTAMP_UNMATCH) {
    if (retval == FC_MATCH_NO_MATCH)
      update_timestamp = 1;
  }

  if (update_timestamp) {
    pthread_rwlock_wrlock(&m->lock);
    *timestamp_p = now;
    pthread_rwlock_unlock(&m->lock);
  }

  log_debug("match status: %s, retval:%d, diff:%" PRIu64 ", min:%" PRIu64
            ", max:%" PRIu64 ", invert: %d",
            identifier, retval, CDTIME_T_TO_TIME_T(diff),
            CDTIME_T_TO_TIME_T(m->min), CDTIME_T_TO_TIME_T(m->max), m->invert);

  return retval;
} /* }}} int mi_match */

void module_register(void) {
  match_proc_t mproc = {0};

  mproc.create = mi_create;
  mproc.destroy = mi_destroy;
  mproc.match = mi_match;
  fc_register_match("interval", mproc);
} /* module_register */
