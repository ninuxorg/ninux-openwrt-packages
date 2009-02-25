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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <regex.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>

#include "olsr.h"
#include "ipcalc.h"
#include "net_olsr.h"
#include "routing_table.h"
#include "mantissa.h"
#include "scheduler.h"
#include "parser.h"
#include "duplicate_set.h"
#include "tc_set.h"
#include "hna_set.h"
#include "mid_set.h"
#include "link_set.h"

#include "plugin_util.h"
#include "autoconf.h"

/* config parameters */
static char my_hosts_file[MAX_FILE + 1];
static char my_sighup_pid_file[MAX_FILE + 1];

static char my_unique_address[UNIQUE_ADDR_LEN];
static int my_interval;
static double my_timeout = MAD_VALID_TIME;

static enum mode {
	VOID,
	AUTO,
	MANUAL,
	RANDOM
}my_mode; 


/* periodic message generation */
struct timer_entry *msg_gen_timer = NULL;



/**
 * do initialization
 */
void
autoconf_constructor(void)
{


}

static int
set_autoconf_mode(const char *value, void *data, set_plugin_parameter_addon addon)
{
  struct mad_entry **v = data;
  my_mode = VOID;
  if (0 < strlen(value)) {
	if (!strcmp(value, "auto"))
		*(enum mode*)data = AUTO;
	else if (!strcmp(value, "manual"))
		*(enum mode*)data = MANUAL;
	else if (!strcmp(value, "random"))
		*(enum mode*)data = RANDOM;
  }
  if (*(enum mode*)data != VOID) {
  	OLSR_PRINTF(1, "Autoconf plugin runs in mode %s \n",  value);
    return 0;
  } else {
    OLSR_PRINTF(0, "Illegal mode \"%s\"", value);
  }
  return 1;
}



// parameters: interval, unique_addr, mode ("auto", "manual", "random") 

static const struct olsrd_plugin_parameters plugin_parameters[] = {
  {.name = "interval",.set_plugin_parameter = &set_plugin_int,.data = &my_interval},
  {.name = "timeout",.set_plugin_parameter = &set_plugin_int,.data = &my_timeout},
  {.name = "unique_addr",.set_plugin_parameter = &set_plugin_string,.data = &my_unique_address,.addon = {sizeof(my_unique_address)} },
  {.name = "mode",.set_plugin_parameter = &set_autoconf_mode,.data = &my_mode },
   
};

void
olsrd_get_plugin_parameters(const struct olsrd_plugin_parameters **params, int *size)
{
  *params = plugin_parameters;
  *size = sizeof(plugin_parameters) / sizeof(*plugin_parameters);
}



/**
 * last initialization
 *
 * we have to do this here because some things like main_addr
 * or the dns suffix (for validation) are not known before
 *
 * this is beause of the order in which the plugin is initialized
 * by the plugin loader:
 *   - first the parameters are sent
 *   - then register_olsr_data() from olsrd_plugin.c is called
 *     which sets up main_addr and some other variables
 *   - register_olsr_data() then then finally calls this function
 */
int
autoconf_init(void)
{
  struct mad_entry *name;
  union olsr_ip_addr ipz;
  int ret;

  /* register functions with olsrd */
  olsr_parser_add_function(&olsr_parser, PARSER_TYPE);

  /* periodic message generation */
  msg_gen_timer = olsr_start_timer(my_interval * MSEC_PER_SEC, EMISSION_JITTER, OLSR_TIMER_PERIODIC, &olsr_autoconf_gen, NULL, 0);

  return 1;
}

/**
 * called at unload: free everything
 *
 */
void
autoconf_destructor(void)
{
  OLSR_PRINTF(2, "AUTOCONF PLUGIN: exit. cleaning up...\n");

  olsr_stop_timer(msg_gen_timer);

}

/**
 * Scheduled event: generate and send MAD packet
 */
void
olsr_autoconf_gen(void *foo __attribute__ ((unused)))
{
  /* send buffer: huge */
  char buffer[10240];
  union olsr_message *message = (union olsr_message *)buffer;
  struct interface *ifn;
  int msgsize;

  /* fill message */
  if (olsr_cnf->ip_version == AF_INET) {
    /* IPv4 */
    message->v4.olsr_msgtype = MESSAGE_TYPE;
    message->v4.olsr_vtime = reltime_to_me(my_timeout * MSEC_PER_SEC);
    memcpy(&message->v4.originator, &olsr_cnf->main_addr, olsr_cnf->ipsize);
    message->v4.ttl = MAX_TTL;
    message->v4.hopcnt = 0;
    message->v4.seqno = htons(get_msg_seqno());

    msgsize = encap_madmsg((struct madmsg *)&message->v4.message);
    msgsize = msgsize + 12;// with olsrmsg doesn't work  sizeof(struct olsrmsg);

    message->v4.olsr_msgsize = htons(msgsize);
  } else {
    /* IPv6 */
    message->v6.olsr_msgtype = MESSAGE_TYPE;
    message->v6.olsr_vtime = reltime_to_me(my_timeout * MSEC_PER_SEC);
    memcpy(&message->v6.originator, &olsr_cnf->main_addr, olsr_cnf->ipsize);
    message->v6.ttl = MAX_TTL;
    message->v6.hopcnt = 0;
    message->v6.seqno = htons(get_msg_seqno());

    msgsize = encap_madmsg((struct namemsg *)&message->v6.message);
    //msgsize = msgsize + sizeof(struct olsrmsg6);

    message->v6.olsr_msgsize = htons(msgsize);
  }

  /* looping trough interfaces */
  for (ifn = ifnet; ifn; ifn = ifn->int_next) {
    OLSR_PRINTF(3, "AUTOCONF PLUGIN: Generating packet - [%s]\n", ifn->int_name);
    if (net_outbuffer_push(ifn, message, msgsize) != msgsize) {
      /* send data and try again */
      net_output(ifn);
      if (net_outbuffer_push(ifn, message, msgsize) != msgsize) {
        OLSR_PRINTF(1, "AUTOCONF PLUGIN: could not send on interface: %s\n", ifn->int_name);
      }
    }
  }
}

/**
 * Parse name olsr message of MAD type
 */
olsr_bool
olsr_parser(union olsr_message *m, struct interface *in_if __attribute__ ((unused)), union olsr_ip_addr *ipaddr)
{
  struct madmsg *madmessage;
  union olsr_ip_addr originator;
  olsr_reltime vtime;
  int size;
  olsr_u16_t seqno;

  /* Fetch the originator of the messsage */
  if (olsr_cnf->ip_version == AF_INET) {
    memcpy(&originator, &m->v4.originator, olsr_cnf->ipsize);
    seqno = ntohs(m->v4.seqno);
  } else {
    memcpy(&originator, &m->v6.originator, olsr_cnf->ipsize);
    seqno = ntohs(m->v6.seqno);
  }

  /* Fetch the message based on IP version */
  if (olsr_cnf->ip_version == AF_INET) {
    vtime = me_to_reltime(m->v4.olsr_vtime);
    size = ntohs(m->v4.olsr_msgsize);
    madmessage = (struct madmsg *)&m->v4.message;
  } else {
    vtime = me_to_reltime(m->v6.olsr_vtime);
    size = ntohs(m->v6.olsr_msgsize);
    madmessage = (struct madmsg *)&m->v6.message;
  }
 
  if (!memcmp(madmessage->unique_addr, my_unique_address, UNIQUE_ADDR_LEN))
      return OLSR_FALSE;
  //if (ipequal(&originator, &olsr_cnf->main_addr))
  //    return OLSR_FALSE;

  update_autoconf_entry(&originator, madmessage, size, vtime);

  /* Forward the message */
  return OLSR_TRUE;
}

/**
 * Encapsulate a MAD message into a packet.
 *
 * It assumed that there is enough space in the buffer to do this!
 *
 * Returns: the length of the message that was appended
 */
int
encap_madmsg(struct madmsg *msg)
{
	
  struct mad_entry* entry;
  struct interface *ifn;
  struct ip_prefix_list *hna;
  char *pos = (char *)msg + sizeof(struct madmsg);
  olsr_u16_t i = 0;
  
   for (ifn = ifnet; ifn; ifn = ifn->int_next) {
  	// add IP and mask of interfaces
  	memcpy(pos,&ifn->int_addr.sin_addr.s_addr, sizeof(olsr_32_t));
  	memcpy(pos + sizeof(olsr_32_t) ,&ifn->int_netmask.sin_addr.s_addr,sizeof(olsr_32_t));
   	i++;
   	pos += sizeof(struct mad_entry);
   }
  

   for (hna = olsr_cnf->hna_entries; hna != NULL; hna = hna->next) {
   	  // add IP and MASK of the HNA routes
      union olsr_ip_addr netmask;
     // if (hna->net.prefix_len == 0) {
     //   continue;
     // }
     memcpy(pos,&hna->net.prefix.v4,sizeof(olsr_32_t)); 
     olsr_prefix_to_netmask(&netmask, hna->net.prefix_len);
     memcpy(pos + sizeof(olsr_32_t), &netmask.v4, sizeof(olsr_32_t));
     i++;
     pos += sizeof(struct mad_entry);
    }

  msg->nr_ip = htons(i);
  msg->version = htons(AUTOCONF_PROTOCOL_VERSION);
  
  return pos - (char *)msg;    
 }


void
update_autoconf_entry(union olsr_ip_addr *originator, struct madmsg *msg, int msg_size, olsr_reltime vtime)
{
  struct ipaddr_str strbuf;
  char *pos, *end_pos;
  struct interface *ifn;
  struct mad_entry *from_packet;
  struct ip_prefix_list *hna;
  int i;
  olsr_u32_t max_netmask; 
  union olsr_ip_addr netmask;
  char buf[64];

  OLSR_PRINTF(3, "AUTOCONF PLUGIN: Received Message from %s\n", olsr_ip_to_string(&strbuf, originator));

  if (ntohs(msg->version) != AUTOCONF_PROTOCOL_VERSION) {
    OLSR_PRINTF(3, "AUTOCONF PLUGIN: ignoring wrong version %d\n", msg->version);
    return;
  }


  pos = (char *)msg + sizeof(struct madmsg);
  end_pos = pos + msg_size - sizeof(struct mad_entry *);   
 
  
  for (i = ntohs(msg->nr_ip); i > 0 && pos < end_pos; i--) {
    from_packet = (struct mad_entry *)pos;
    olsr_u32_t net_to_check = from_packet->ip & from_packet->mask;
	// CHECK IF SOME IPs collides
		
	for (ifn = ifnet; ifn; ifn = ifn->int_next) {
    	max_netmask = (from_packet->mask >= ifn->int_netmask.sin_addr.s_addr ) ?
  	                             from_packet->mask :
  	                             ifn->int_netmask.sin_addr.s_addr;
  	olsr_u32_t remote_net = max_netmask & from_packet->ip;
	olsr_u32_t local_net = max_netmask & ifn->int_addr.sin_addr.s_addr;
    	if (remote_net == local_net) {
    	
  		// There is a fuckin' collision man!
  		OLSR_PRINTF(4, "AUTOCONF PLUGIN: found collision with the interface IP %s\n",inet_ntop(AF_INET,&from_packet->ip,buf, sizeof(buf))); 
  		;
    	}
     }
  

     for (hna = olsr_cnf->hna_entries; hna != NULL; hna = hna->next) {
       olsr_prefix_to_netmask(&netmask, hna->net.prefix_len);
       olsr_u32_t max_netmask = (from_packet->mask >= (olsr_u32_t)netmask.v4.s_addr ) ?
  	                            from_packet->mask :
  	                            (olsr_u32_t)netmask.v4.s_addr;

        olsr_u32_t remote_net = max_netmask & from_packet->ip;
	olsr_u32_t local_net = max_netmask & hna->net.prefix.v4.s_addr;
    	if (remote_net == local_net) {
  		  // There is a fuckin' collision man!
  		  OLSR_PRINTF(4, "AUTOCONF PLUGIN: found collision with the announced IP %s\n" , inet_ntop(AF_INET, &from_packet->ip, buf, sizeof(buf)));

  		  ;
    	}
     }
	

    pos += sizeof(struct mad_entry);
    //pos += 1 + ((ntohs(from_packet->len) - 1) | 3); //????
  }
  if (i != 0)
    OLSR_PRINTF(4, "AUTOCONF PLUGIN: Lost %d entries in received packet due to length inconsistency (%s)\n", i, olsr_ip_to_string(&strbuf, originator));
}

