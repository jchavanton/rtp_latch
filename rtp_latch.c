/*
 * RTP latch module
 *
 * Copyright (C) 2018 Julien Chavanton (Flowroute.com)
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * Kamailio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * Kamailio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */


#include "../../core/sr_module.h"
#include "../../core/mod_fix.h"
#include "../../core/lvalue.h"
#include "../../modules/rtp_latch/rtp_latch.h"

#include <stdio.h>
#include <string.h>


MODULE_VERSION

int latch_delay_ms = 0;
static int mod_init(void);
static void destroy(void);
static int child_init(int rank);

static int fixup_rtp_spoof(void** param, int param_no);

static int rtp_spoof_f(struct sip_msg *msg, char* src_ip, char* src_port, char* dst_ip, char* dst_port);

static cmd_export_t cmds[] = {
		{"rtp_spoof", (cmd_function)rtp_spoof_f, 4, fixup_rtp_spoof, 0, REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE},
		{0, 0, 0, 0, 0, 0}
};


static param_export_t params[] = {
		{"delay_ms", INT_PARAM, &latch_delay_ms},
		{0, 0, 0}
};


struct module_exports exports = {
		"rtp_latch",			/* module name */
		DEFAULT_DLFLAGS,		/* dlopen flags */
		cmds,						/* exported functions */
		params,					/* exported parameters */
		0,							/* RPC method exports */
		0,							/* exported pseudo-variables */
		0,							/* response handling function */
		mod_init,				/* initialization module */
		child_init,				/* per-child init function */
		destroy,					/* destroy function */
};


static int fixup_rtp_spoof(void** param, int param_no) {
		if (param_no == 1)
			return fixup_spve_null(param, 1);
		if (param_no == 2)
			return fixup_igp_null(param, 1);
		if (param_no == 3)
			return fixup_spve_null(param, 1);
		if (param_no == 4)
			return fixup_igp_null(param, 1);
		LM_ERR("invalid parameter count [%d]\n", param_no);
		return -1;
}


static shared_global_vars_t *vars;

#define PROC_COUNT 1

static int mod_init(void)
{
	vars = shm_malloc(sizeof(shared_global_vars_t));
	vars->spoof_info_list = (spoof_info_t*) shm_malloc(sizeof(spoof_info_t));
	clist_init(vars->spoof_info_list, next, prev);
	LM_ERR("\n");
	register_procs(PROC_COUNT);
	return 0;
}


static int child_init(int rank)
{
	if (rank==PROC_MAIN) {
		int pid;
		pid=fork_process(PROC_XWORKER, "RTP latcher", 1);
		if (pid<0)
			return -1; /* error */
		if(pid==0){
			wait_latch();
			return 0;
		}
	}
	if(rank == PROC_INIT || rank == PROC_MAIN || rank == PROC_TCP_MAIN)
		return 0; /* do nothing for the main process */

	return 0;
}


static void destroy(void)
{
}


/*
 *  Generic checksum calculation function
 */
static unsigned short csum(unsigned short *ptr,int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;

	return(answer);
}

const unsigned char RTP[12] = {0x80,0x27,0x31,0x33,0x73,0x13,0x37,0x76,0x08,0x60,0x02,0x00};


static char *shm_strdup(str *src) {
		char *res;
		if (!src || !src->s)
			return NULL;
		if (!(res = (char *) shm_malloc(src->len + 1)))
			return NULL;
		strncpy(res, src->s, src->len);
			res[src->len] = 0;
		return res;
}

static void spoof_info_list_add(spoof_info_t *si) {
	lock_get(&vars->lock);
	if(!vars->spoof_info_list) {
		vars->spoof_info_list = si;
		LM_DBG(": init spoof info list\n");
		clist_init(vars->spoof_info_list, next, prev);
	} else {
		LM_DBG(": append spoof info\n");
		clist_append(vars->spoof_info_list, si, next, prev);
	}
	lock_release(&vars->lock);
}

static int spoof_process_queue(void) {
	spoof_info_t *si;
	struct timeval now;
	gettimeofday(&now, NULL);
	int64_t now_ms = (now.tv_sec) * 1000 + (now.tv_usec) / 1000;

	lock_get(&vars->lock);
	clist_foreach(vars->spoof_info_list, si, next) {
		int64_t due_ms = si->time_ms - now_ms;
		LM_DBG("[%p<%p>%p]src[%.*s:%d]dst[%.*s:%d][%ld][%ld][%ldms]\n",
			 si->prev, si, si->next,
			 si->src_ip.len, si->src_ip.s, si->src_port,
			 si->dst_ip.len, si->dst_ip.s, si->dst_port,
			 now_ms, si->time_ms, due_ms);
		if (due_ms <= 0) {
			LM_DBG("[%p<%p>%p]src[%.*s:%d]dst[%.*s:%d][%ld][%ld][%ldms] sending\n",
			 si->prev, si, si->next,
			 si->src_ip.len, si->src_ip.s, si->src_port,
			 si->dst_ip.len, si->dst_ip.s, si->dst_port,
			 now_ms, si->time_ms, due_ms);
			spoof_info_t *tmp = si;
			si = si->prev;
			clist_rm(tmp, next, prev);
			lock_release(&vars->lock);
			rtp_spoof_do(tmp);
			spoof_info_del(tmp);
			return 1;
		} else {
			goto done;
		}
	}
	goto done;

	done:
		lock_release(&vars->lock);
		return 0;
}

spoof_info_t* spoof_info_new(str *src_ip, int src_port, str *dst_ip, int dst_port) {
	struct timeval now;
	gettimeofday(&now, NULL);

	spoof_info_t *si = (spoof_info_t*) shm_malloc(sizeof(spoof_info_t));
	if (!si)
			return si;
	si->src_ip.s = shm_strdup(src_ip);
	if (!si->src_ip.s) {
		shm_free(si);
		return NULL;
	}
	si->src_ip.len = src_ip->len;
	si->src_port = src_port;
	si->dst_ip.s = shm_strdup(dst_ip);
	if (!si->src_ip.s) {
		shm_free(si->src_ip.s);
		shm_free(si);
		return NULL;
	}
	si->dst_ip.len = dst_ip->len;
	si->dst_port = dst_port;

	si->time_ms = (now.tv_sec) * 1000 + (now.tv_usec) / 1000 + latch_delay_ms;
	return si;
}


void spoof_info_del(spoof_info_t* si) {
	shm_free(si->src_ip.s);
	shm_free(si->dst_ip.s);
	shm_free(si);
}


void wait_latch (void) {
	while(1) {
		LM_DBG(":wait[%d]\n", (int)time(NULL));
		while (spoof_process_queue());
		usleep(1000);
	}
}

int rtp_spoof_f(struct sip_msg *msg, char *p_src_ip, char *p_src_port, char *p_dst_ip, char *p_dst_port)
{
	str src_ip = {NULL, 0};
	str dst_ip = {NULL, 0};
	int src_port = 0;
	int dst_port = 0;
	if (fixup_get_svalue(msg, (gparam_t*)p_src_ip, &src_ip) != 0) {
		LM_ERR("cannot get the param src_ip\n");
		return -1;
	}
	if (fixup_get_svalue(msg, (gparam_t*)p_dst_ip, &dst_ip) != 0) {
		LM_ERR("cannot get the param dst_ip\n");
		return -1;
	}
	if (fixup_get_ivalue(msg, (gparam_t*)p_src_port, &src_port) != 0) {
		LM_ERR("cannot get the param src_port\n");
		return -1;
	}
	if (fixup_get_ivalue(msg, (gparam_t*)p_dst_port, &dst_port) != 0) {
		LM_ERR("cannot get the param dst_port\n");
		return -1;
	}
	spoof_info_t* si = spoof_info_new(&src_ip, src_port, &dst_ip, dst_port);
	LM_DBG("queuing [%.*s:%d]>>[%.*s:%d]\n",
						 si->src_ip.len, si->src_ip.s, si->src_port,
						 si->dst_ip.len, si->dst_ip.s, si->dst_port);
	spoof_info_list_add(si);
	return 1;
}

int rtp_spoof_do(spoof_info_t* si)
{
	//Create a raw socket of type IPPROTO
	int s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);

	if(s == -1) {
		//socket creation failed, may be because of non-root privileges
		LM_ERR("Failed to create raw socket");
		return 0;
	}

	//Datagram to represent the packet
	char datagram[4096] , source_ip[32] , *data , *pseudogram;
	//zero out the packet buffer
	memset (datagram, 0, 4096);
	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	//UDP header
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in sin;
	struct pseudo_header psh;
	//Data part
	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
	memcpy(data, RTP, sizeof(RTP));
	//some address resolution
	strcpy(source_ip , si->src_ip.s);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	sin.sin_addr.s_addr = inet_addr(si->dst_ip.s);

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof(RTP);
	iph->id = htonl(54321); //Id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;  // Set to 0 before calculating checksum
	iph->saddr = inet_addr(si->src_ip.s); // Spoof the source ip address
	iph->daddr = sin.sin_addr.s_addr;
	// IP checksum
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);

	udph->source = htons (si->src_port);
	udph->dest = htons (si->dst_port);
	udph->len = htons(8 + sizeof(RTP));
	udph->check = 0; // leave checksum 0 now, filled later by pseudo header
	// Now the UDP checksum using the pseudo header
	psh.src_address = inet_addr(si->src_ip.s);
	psh.dst_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_UDP;
	psh.udp_length = htons(sizeof(struct udphdr) + sizeof(RTP) );
	
	int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + sizeof(RTP);
	pseudogram = malloc(psize);
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + sizeof(RTP));
	udph->check = csum( (unsigned short*) pseudogram , psize);
	
	// Send the packet
	if (sendto (s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
		LM_ERR("sendto failed");
	} else {
		LM_DBG("packet sent -- length[%d]\n" , iph->tot_len);
	}
	return 1;
}


