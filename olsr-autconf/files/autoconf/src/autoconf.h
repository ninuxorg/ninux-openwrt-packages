
/*
 * Copyright (c) 2009, OrazioPirataDelloSpazio - Ninux.org (ziducaixao-at-autistici.org)
 * Copyright (c) 2004, Andreas Tonnesen(andreto-at-olsr.org)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * * Neither the name of the UniK olsr daemon nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * Dynamic linked library for UniK OLSRd
 */

#ifndef _AUTOCONF_PLUGIN
#define _AUTOCONF_PLUGIN

#include <sys/time.h>
#include <regex.h>

#include "olsr_types.h"
#include "interfaces.h"
#include "olsr_protocol.h"
#include "common/list.h"

#include "olsrd_plugin.h"
#include "autoconf_msg.h"
#include "hashing.h"
#include "mantissa.h"

#define PLUGIN_NAME	"OLSRD autoconf plugin"
#define PLUGIN_VERSION	"0.1"
#define PLUGIN_AUTHOR   "OrazioPirataDelloSpazio - Ninux.org"

// useful to set for the freifunkfirmware to remove all
// calls to olsr_printf by the empty statement ";"
//#define olsr_printf(...) ;

#define MESSAGE_TYPE		131
#define PARSER_TYPE		MESSAGE_TYPE
#define EMISSION_INTERVAL	120     /* seconds */
#define EMISSION_JITTER         25      /* percent */
#define MAD_VALID_TIME		1800    /* seconds */

#define AUTOCONF_PROTOCOL_VERSION	1

#define MAX_NAME 127
#define MAX_FILE 255
#define MAX_SUFFIX 63

#define MID_ENTRIES 1
#define MID_MAXLEN 16
#define MID_PREFIX "mid%i."

#define OLSR_NAMESVC_DB_JITTER 5        /* percent */


/* Parser function to register with the sceduler */
olsr_bool olsr_parser(union olsr_message *, struct interface *, union olsr_ip_addr *);

/* callback for periodic timer */
void olsr_autoconf_gen(void *);

int encap_madmsg(struct madmsg *);


void update_autoconf_entry(union olsr_ip_addr *, struct madmsg *, int, olsr_reltime);


int register_olsr_param(char *key, char *value);


void autoconf_constructor(void);

void autoconf_destructor(void);

int autoconf_init(void);

#endif
