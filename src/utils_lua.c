/**
 * collectd - src/utils_lua.c
 * Copyright (C) 2010       Florian Forster
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Authors:
 *   Florian Forster <octo at collectd.org>
 **/

#define _GNU_SOURCE
#include "utils/common/common.h"
#include "utils_lua.h"
#include <stdio.h>

static int ltoc_values(lua_State *L, /* {{{ */
                       const data_set_t *ds, value_t *ret_values) {
  if (!lua_istable(L, -1)) {
    WARNING("ltoc_values: not a table");
    return -1;
  }

  /* Push initial key */
  lua_pushnil(L); /* +1 = 1 */
  size_t i = 0;
  while (lua_next(L, -2) != 0) /* -1+2 = 2 || -1 = 0 */
  {
    if (i >= ds->ds_num) {
      lua_pop(L, 2); /* -2 = 0 */
      i++;
      break;
    }

    ret_values[i] = luaC_tovalue(L, -1, ds->ds[i].type);

    /* Pop the value */
    lua_pop(L, 1); /* -1 = 1 */
    i++;
  } /* while (lua_next) */

  if (i != ds->ds_num) {
    WARNING("ltoc_values: invalid size for datasource \"%s\": expected %" PRIsz
            ", got %" PRIsz,
            ds->type, ds->ds_num, i);
    return -1;
  }

  return 0;
} /* }}} int ltoc_values */

static int ltoc_table_values(lua_State *L, int idx, /* {{{ */
                             const data_set_t *ds, value_list_t *vl) {
  /* We're only called from "luaC_tovaluelist", which ensures that "idx" is an
   * absolute index (i.e. a positive number) */
  assert(idx > 0);

  lua_getfield(L, idx, "values");
  if (!lua_istable(L, -1)) {
    WARNING("utils_lua: ltoc_table_values: The \"values\" member is a %s "
            "value, not a table.",
            lua_typename(L, lua_type(L, -1)));
    lua_pop(L, 1);
    return -1;
  }

  vl->values_len = ds->ds_num;
  vl->values = calloc(vl->values_len, sizeof(*vl->values));
  if (vl->values == NULL) {
    ERROR("utils_lua: calloc failed.");
    vl->values_len = 0;
    lua_pop(L, 1);
    return -1;
  }

  int status = ltoc_values(L, ds, vl->values);

  lua_pop(L, 1);

  if (status != 0) {
    vl->values_len = 0;
    sfree(vl->values);
  }

  return status;
} /* }}} int ltoc_table_values */

static int luaC_pushvalues(lua_State *L, const data_set_t *ds,
                           const value_list_t *vl) /* {{{ */
{
  assert(vl->values_len == ds->ds_num);

  lua_newtable(L);
  for (size_t i = 0; i < vl->values_len; i++) {
    lua_pushinteger(L, (lua_Integer)i + 1);
    luaC_pushvalue(L, vl->values[i], ds->ds[i].type);
    lua_settable(L, -3);
  }

  return 0;
} /* }}} int luaC_pushvalues */

static int luaC_pushdstypes(lua_State *L, const data_set_t *ds) /* {{{ */
{
  lua_newtable(L);
  for (size_t i = 0; i < ds->ds_num; i++) {
    lua_pushinteger(L, (lua_Integer)i);
    lua_pushstring(L, DS_TYPE_TO_STRING(ds->ds[i].type));
    lua_settable(L, -3);
  }

  return 0;
} /* }}} int luaC_pushdstypes */

static int luaC_pushdsnames(lua_State *L, const data_set_t *ds) /* {{{ */
{
  lua_newtable(L);
  for (size_t i = 0; i < ds->ds_num; i++) {
    lua_pushinteger(L, (lua_Integer)i);
    lua_pushstring(L, ds->ds[i].name);
    lua_settable(L, -3);
  }

  return 0;
} /* }}} int luaC_pushdsnames */

/*
 * Public functions
 */
cdtime_t luaC_tocdtime(lua_State *L, int idx) /* {{{ */
{
  if (!lua_isnumber(L, /* stack pos = */ idx))
    return 0;

  double d = lua_tonumber(L, idx);

  return DOUBLE_TO_CDTIME_T(d);
} /* }}} int ltoc_table_cdtime */

int luaC_tostringbuffer(lua_State *L, int idx, /* {{{ */
                        char *buffer, size_t buffer_size) {
  const char *str = lua_tostring(L, idx);
  if (str == NULL)
    return -1;

  sstrncpy(buffer, str, buffer_size);
  return 0;
} /* }}} int luaC_tostringbuffer */

value_t luaC_tovalue(lua_State *L, int idx, int ds_type) /* {{{ */
{
  value_t v = {0};

  if (!lua_isnumber(L, idx))
    return v;

  if (ds_type == DS_TYPE_GAUGE)
    v.gauge = (gauge_t)lua_tonumber(L, /* stack pos = */ -1);
  else if (ds_type == DS_TYPE_DERIVE)
    v.derive = (derive_t)lua_tointeger(L, /* stack pos = */ -1);
  else if (ds_type == DS_TYPE_COUNTER)
    v.counter = (counter_t)lua_tointeger(L, /* stack pos = */ -1);
  else if (ds_type == DS_TYPE_ABSOLUTE)
    v.absolute = (absolute_t)lua_tointeger(L, /* stack pos = */ -1);

  return v;
} /* }}} value_t luaC_tovalue */

value_list_t *luaC_tovaluelist(lua_State *L, int idx) /* {{{ */
{
#if COLLECT_DEBUG
  int stack_top_before = lua_gettop(L);
#endif

  /* Convert relative indexes to absolute indexes, so it doesn't change when we
   * push / pop stuff. */
  if (idx < 1)
    idx += lua_gettop(L) + 1;

  /* Check that idx is in the valid range */
  if ((idx < 1) || (idx > lua_gettop(L))) {
    DEBUG("luaC_tovaluelist: idx(%d), top(%d)", idx, stack_top_before);
    return NULL;
  }

  value_list_t *vl = calloc(1, sizeof(*vl));
  if (vl == NULL) {
    DEBUG("luaC_tovaluelist: calloc failed");
    return NULL;
  }

  /* Push initial key */
  lua_pushnil(L);
  while (lua_next(L, idx) != 0) {
    const char *key = lua_tostring(L, -2);

    if (key == NULL) {
      DEBUG("luaC_tovaluelist: Ignoring non-string key.");
    } else if (strcasecmp("host", key) == 0)
      luaC_tostringbuffer(L, -1, vl->host, sizeof(vl->host));
    else if (strcasecmp("plugin", key) == 0)
      luaC_tostringbuffer(L, -1, vl->plugin, sizeof(vl->plugin));
    else if (strcasecmp("plugin_instance", key) == 0)
      luaC_tostringbuffer(L, -1, vl->plugin_instance,
                          sizeof(vl->plugin_instance));
    else if (strcasecmp("type", key) == 0)
      luaC_tostringbuffer(L, -1, vl->type, sizeof(vl->type));
    else if (strcasecmp("type_instance", key) == 0)
      luaC_tostringbuffer(L, -1, vl->type_instance, sizeof(vl->type_instance));
    else if (strcasecmp("time", key) == 0)
      vl->time = luaC_tocdtime(L, -1);
    else if (strcasecmp("interval", key) == 0)
      vl->interval = luaC_tocdtime(L, -1);
    else if (strcasecmp("values", key) == 0) {
      /* This key is not handled here, because we have to assure "type" is read
       * first. */
    } else {
      DEBUG("luaC_tovaluelist: Ignoring unknown key \"%s\".", key);
    }

    /* Pop the value */
    lua_pop(L, 1);
  }

  const data_set_t *ds = plugin_get_ds(vl->type);
  if (ds == NULL) {
    INFO("utils_lua: Unable to lookup type \"%s\".", vl->type);
    sfree(vl);
    return NULL;
  }

  int status = ltoc_table_values(L, idx, ds, vl);
  if (status != 0) {
    WARNING("utils_lua: ltoc_table_values failed.");
    sfree(vl);
    return NULL;
  }

#if COLLECT_DEBUG
  assert(stack_top_before == lua_gettop(L));
#endif
  return vl;
} /* }}} value_list_t *luaC_tovaluelist */

int luaC_pushcdtime(lua_State *L, cdtime_t t) /* {{{ */
{
  double d = CDTIME_T_TO_DOUBLE(t);

  lua_pushnumber(L, (lua_Number)d);
  return 0;
} /* }}} int luaC_pushcdtime */

int luaC_pushvalue(lua_State *L, value_t v, int ds_type) /* {{{ */
{
  if (ds_type == DS_TYPE_GAUGE)
    lua_pushnumber(L, (lua_Number)v.gauge);
  else if (ds_type == DS_TYPE_DERIVE)
    lua_pushinteger(L, (lua_Integer)v.derive);
  else if (ds_type == DS_TYPE_COUNTER)
    lua_pushinteger(L, (lua_Integer)v.counter);
  else if (ds_type == DS_TYPE_ABSOLUTE)
    lua_pushinteger(L, (lua_Integer)v.absolute);
  else
    return -1;
  return 0;
} /* }}} int luaC_pushvalue */

int luaC_pushvaluelist(lua_State *L, const data_set_t *ds,
                       const value_list_t *vl) /* {{{ */
{
  lua_newtable(L);

  lua_pushstring(L, vl->host);
  lua_setfield(L, -2, "host");

  lua_pushstring(L, vl->plugin);
  lua_setfield(L, -2, "plugin");
  lua_pushstring(L, vl->plugin_instance);
  lua_setfield(L, -2, "plugin_instance");

  lua_pushstring(L, vl->type);
  lua_setfield(L, -2, "type");
  lua_pushstring(L, vl->type_instance);
  lua_setfield(L, -2, "type_instance");

  luaC_pushvalues(L, ds, vl);
  lua_setfield(L, -2, "values");

  luaC_pushdstypes(L, ds);
  lua_setfield(L, -2, "dstypes");

  luaC_pushdsnames(L, ds);
  lua_setfield(L, -2, "dsnames");

  luaC_pushcdtime(L, vl->time);
  lua_setfield(L, -2, "time");

  luaC_pushcdtime(L, vl->interval);
  lua_setfield(L, -2, "interval");

  return 0;
} /* }}} int luaC_pushvaluelist */

static int luaC_pushOConfigValue(lua_State *L, const oconfig_item_t *ci,
                                 bool setkey) /* {{{ */
{
  int status = 0;
  oconfig_value_t *cv = ci->values;

  DEBUG("Lua plugin: Push ci->value");
  switch (cv->type) {
  case OCONFIG_TYPE_STRING:
    lua_pushstring(L, cv->value.string);
    if (setkey) {
      lua_setfield(L, -2, ci->key);
      DEBUG("Lua plugin: Push ci->value (OCONFIG_TYPE_STRING) %s => '%s'",
            ci->key, cv->value.string);
    } else {
      DEBUG("Lua plugin: Push ci->value (OCONFIG_TYPE_STRING) '%s'",
            cv->value.string);
    }
    break;
  case OCONFIG_TYPE_NUMBER:
    lua_pushnumber(L, cv->value.number);
    if (setkey) {
      lua_setfield(L, -2, ci->key);
      DEBUG("Lua plugin: Push ci->value (OCONFIG_TYPE_NUMBER) %s => '%f'",
            ci->key, cv->value.number);
    } else {
      DEBUG("Lua plugin: Push ci->value (OCONFIG_TYPE_NUMBER) => '%f'",
            cv->value.number);
    }
    break;
  case OCONFIG_TYPE_BOOLEAN:
    lua_pushboolean(L, cv->value.boolean);
    if (setkey) {
      lua_setfield(L, -2, ci->key);
      DEBUG("Lua plugin: Push ci->value (OCONFIG_TYPE_BOOLEAN) %s => '%d'",
            ci->key, cv->value.boolean);
    } else {
      DEBUG("Lua plugin: Push ci->value (OCONFIG_TYPE_BOOLEAN) '%d'",
            cv->value.boolean);
    }
    break;
  default:
    WARNING("Lua plugin: Unable to push known lua types ci->value");
    status = 1;
    break;
  }

  DEBUG("Lua plugin: luaC_pushOConfigValue successfully called.");
  return status;
} /* }}} int luaC_pushOConfigValue */

static int luaC_pushOConfigChildItem(lua_State *L,
                                     const oconfig_item_t *parent) /* {{{ */
{
  int status = 0;
  DEBUG("Lua plugin: Current number of config item '%d'", parent->children_num);

  if (parent->children_num == 0) {
    luaC_pushOConfigValue(L, parent, true);
  } else {
    /*
     * <PARENT_KEY PARENT_VALUE>
     *   CHILD_KEY CHILD_VALUE
     * </PARENT>
     * => PARENT_VALUE = {
     *      CHILD_KEY = CHILD_VALUE
     *    }
     */
    DEBUG("Lua plugin: process <%d> children of <%s>", parent->children_num,
          parent->key);
    DEBUG("Lua plugin: Push value as children's key");
    luaC_pushOConfigValue(L, parent, false);
    lua_createtable(L, parent->children_num, 0);
    for (int i = 0; i < parent->children_num; i++) {
      DEBUG("Lua plugin: Push child->children[%d]", i);
      oconfig_item_t *ci = parent->children + i;
      luaC_pushOConfigChildItem(L, ci);
    }
    lua_settable(L, -3);
    DEBUG("Lua plugin: %d children of %s processed",
          parent->children->children_num, parent->children->key);
  }

  DEBUG("Lua plugin: luaC_pushOConfigChildItem successfully called.");
  return status;
} /* }}} int luaC_pushOConfigChildItem */

int luaC_pushOConfigItems(lua_State *L, const oconfig_item_t *ci) /* {{{ */
{
  DEBUG("Lua plugin: Current number of config item '%d'", ci->children_num);

  lua_createtable(L, ci->children_num, 0);
  for (int i = 0; i < ci->children_num; i++) {
    DEBUG("Lua plugin: Push ci->children[%d]", i);
    oconfig_item_t *child = ci->children + i;
    if (child->children_num > 0) {
      for (int j = 0; j < i; j++) {
        oconfig_value_t *cv = child->values;
        if (cv->type == OCONFIG_TYPE_STRING &&
            !strcmp(ci->children[j].key, cv->value.string)) {
          WARNING("Lua plugin: Parent key '%s' and child key <%s %s> is "
                  "conflicted. Override by child key.",
                  ci->children[j].key, child->key, cv->value.string);
        }
      }
    }
    luaC_pushOConfigChildItem(L, child);
  }

  DEBUG("Lua plugin: luaC_pushOConfigItems successfully called.");
  return 0;
} /* }}} int luaC_pushOConfigItems */

int luaC_pushNotification(lua_State *L,
                          const notification_t *notification) /* {{{ */
{
  DEBUG("Lua plugin: luaC_pushNotification called.");

  lua_newtable(L);

  DEBUG("Lua plugin: Notification severity: <%d>", notification->severity);
  lua_pushinteger(L, notification->severity);
  lua_setfield(L, -2, "severity");

  luaC_pushcdtime(L, notification->time);
  lua_setfield(L, -2, "time");

  lua_pushstring(L, notification->message);
  lua_setfield(L, -2, "message");

  lua_pushstring(L, notification->host);
  lua_setfield(L, -2, "host");

  lua_pushstring(L, notification->plugin);
  lua_setfield(L, -2, "plugin");

  lua_pushstring(L, notification->plugin_instance);
  lua_setfield(L, -2, "plugin_instance");

  lua_pushstring(L, notification->type);
  lua_setfield(L, -2, "type");

  lua_pushstring(L, notification->type_instance);
  lua_setfield(L, -2, "type_instance");

  int meta_count = 0;
  notification_meta_t *meta = notification->meta;
  if (meta) {
    /* Setup empty table for 'meta' key */
    lua_newtable(L);
  }
  while (meta) {
    meta_count += 1;
    lua_newtable(L);
    switch (meta->type) {
    case NM_TYPE_STRING:
      DEBUG("Lua plugin: Set %s = %s", meta->name, meta->nm_value.nm_string);
      lua_pushstring(L, meta->nm_value.nm_string);
      break;
    case NM_TYPE_SIGNED_INT:
      DEBUG("Lua plugin: Set %s = %" PRIu64, meta->name,
            meta->nm_value.nm_signed_int);
      lua_pushnumber(L, meta->nm_value.nm_signed_int);
      break;
    case NM_TYPE_UNSIGNED_INT:
      DEBUG("Lua plugin: Set %s = %" PRIu64, meta->name,
            meta->nm_value.nm_unsigned_int);
      lua_pushnumber(L, meta->nm_value.nm_unsigned_int);
      break;
    case NM_TYPE_DOUBLE:
      DEBUG("Lua plugin: Set %s = %f", meta->name, meta->nm_value.nm_double);
      lua_pushnumber(L, meta->nm_value.nm_double);
      break;
    case NM_TYPE_BOOLEAN:
      DEBUG("Lua plugin: Set %s = %d", meta->name, meta->nm_value.nm_boolean);
      lua_pushboolean(L, meta->nm_value.nm_boolean);
      break;
    }
    lua_setfield(L, -2, meta->name);
    lua_rawseti(L, -2, meta_count);
    meta = meta->next;
  }
  DEBUG("Lua plugin: Number of meta: <%d>", meta_count);
  if (meta_count > 0) {
    lua_setfield(L, -2, "meta");
  }

  DEBUG("Lua plugin: luaC_pushNotification successfully called.");
  return 0;
} /* }}} int luaC_pushNotification */

int luaC_tonotification(lua_State *L, notification_t *notification) /* {{{ */
{
  const char *notification_keys[] = {
      "severity",        "time", "message",       "host", "plugin",
      "plugin_instance", "type", "type_instance", "meta", NULL};
  int i = 0;
  while (notification_keys[i]) {
    size_t len = 0;
    char const *buf = NULL;
    char const *key = notification_keys[i];
    lua_getfield(L, -1, key);
    int type = lua_type(L, -1);
    switch (type) {
    case LUA_TNUMBER:
      DEBUG("Lua plugin: keys[%d] LUA_TNUMBER: <%s>", i, notification_keys[i]);
      if (!strcmp(key, "severity")) {
        notification->severity = lua_tonumber(L, -1);
        DEBUG("Lua plugin: severity: <%f>", lua_tonumber(L, -1));
      } else if (!strcmp(key, "time")) {
        DEBUG("Lua plugin: time: <%f>", lua_tonumber(L, -1));
        notification->time = luaC_tocdtime(L, -1);
      } else {
        WARNING("Lua plugin: unknown key for notification: <%s>", key);
      }
      break;
    case LUA_TSTRING:
      DEBUG("Lua plugin: keys[%d] LUA_TSTRING: <%s>", i, notification_keys[i]);
      if (!strcmp(key, "message") || !strcmp(key, "host") ||
          !strcmp(key, "plugin") || !strcmp(key, "plugin_instance") ||
          !strcmp(key, "type") || !strcmp(key, "type_instance")) {
        buf = lua_tolstring(L, -1, &len);
        DEBUG("Lua plugin: value of <%s> length: <%zd>", key, len);
        if (len >= DATA_MAX_NAME_LEN) {
          WARNING("Lua plugin: key <%s> must be shorter than <%d>", key,
                  DATA_MAX_NAME_LEN);
          break;
        }
        if (!strcmp(key, "message")) {
          ssnprintf(notification->message, sizeof(notification->message), "%s",
                    buf);
        } else if (!strcmp(key, "host")) {
          ssnprintf(notification->host, sizeof(notification->host), "%s", buf);
        } else if (!strcmp(key, "plugin")) {
          ssnprintf(notification->plugin, sizeof(notification->plugin), "%s",
                    buf);
        } else if (!strcmp(key, "plugin_instance")) {
          ssnprintf(notification->plugin_instance,
                    sizeof(notification->plugin_instance), "%s", buf);
        } else if (!strcmp(key, "type")) {
          ssnprintf(notification->type, sizeof(notification->type), "%s", buf);
        } else if (!strcmp(key, "type_instance")) {
          ssnprintf(notification->type_instance,
                    sizeof(notification->type_instance), "%s", buf);
        }
      } else {
        WARNING("Lua plugin: unknown key for notification: <%s>", key);
        break;
      }
      DEBUG("Lua plugin: copy key: <%s>", key);
      break;
    case LUA_TTABLE:
      DEBUG("Lua plugin: keys[%d] LUA_TTABLE: <%s>", i, notification_keys[i]);
      if (!strcmp(key, "meta")) {
#if LUA_VERSION_NUM < 502
        len = lua_objlen(L, -2);
#else
        len = lua_rawlen(L, -2);
#endif
        DEBUG("Lua plugin: size of meta: <%zd>", len);
        if (len == 0)
          break;
        notification->meta = calloc(len, sizeof(notification_meta_t));
        int j = 0;
        for (j = 0; j < len; j++) {
          lua_rawgeti(L, -1, j);
          lua_pushnil(L);
          while (lua_next(L, -2)) {
            type = lua_type(L, -1);
            switch (type) {
            case LUA_TSTRING:
              strcpy(notification->meta[i].name, lua_tostring(L, -2));
              notification->meta[j].nm_value.nm_string = lua_tostring(L, -2);
              notification->meta[j].type = NM_TYPE_STRING;
              notification->meta[j].next = &notification->meta[i + 1];
              break;
            case LUA_TNUMBER:
              /* Note that the value of number is always treated as double */
              strcpy(notification->meta[i].name, lua_tostring(L, -2));
              notification->meta[j].nm_value.nm_double = lua_tonumber(L, -1);
              notification->meta[j].type = NM_TYPE_DOUBLE;
              notification->meta[j].next = &notification->meta[j + 1];
              break;
            default:
              WARNING("Lua plugin: value of meta[%d][%s] must be LUA_TSTRING "
                      "or LUA_TNUMBER",
                      j, lua_tostring(L, -2));
              break;
            }
          }
        }
        notification->meta[j - 1].next = &(notification->meta[0]);
      } else {
        WARNING("Lua plugin: key of values must be 'meta': <%s>", key);
      }
      break;
    case LUA_TNONE:
      WARNING("Lua plugin: non acceptable index should not specified: <%d>", i);
      break;
    default:
      WARNING(
          "Lua plugin: key must be type of LUA_TNUMBER or LUA_TSTRING: <%s>",
          key);
      break;
    }
    /* pop each value of keys */
    lua_pop(L, 1);
    DEBUG("Lua plugin: next index of keys: <%d>", i + 1);
    i++;
  }
  return 0;
} /* }}} int luaC_notificaion */
