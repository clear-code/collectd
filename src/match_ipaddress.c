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

static int match_ipaddress_create(const oconfig_item_t *ci, void **user_data) /* {{{ */
{
  return 0;
}

static int match_ipaddress_destroy(void **user_data) /* {{{ */
{
  return 0;
} /* }}} int match_ipaddress_destroy */

static int match_ipaddress_match(const data_set_t *ds, const value_list_t *vl, /* {{{ */
				 notification_meta_t __attribute__((unused)) * *meta,
				 void **user_data) {
  return FC_MATCH_NO_MATCH;
}

void module_register(void) {
  match_proc_t mproc = {0};

  mproc.create = match_ipaddress_create;
  mproc.destroy = match_ipaddress_destroy;
  mproc.match = match_ipaddress_match;
  fc_register_match("ipaddress", mproc);
} /* module_register */
