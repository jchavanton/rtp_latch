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

#ifndef _RTP_LATCH_MOD_H_
#define _RTP_LATCH_MOD_H_

#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<errno.h>
#include<netinet/udp.h>
#include<netinet/ip.h>
#include <arpa/inet.h>

/* UDP header */
struct pseudo_header {
	u_int32_t src_address;
	u_int32_t dst_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};

typedef struct spoof_info {
	struct spoof_info* next;
	struct spoof_info* prev;
	str src_ip;
	int src_port;
	str dst_ip;
	int dst_port;
	int64_t time_ms;
} spoof_info_t;

typedef struct shared_global_vars {
	spoof_info_t *spoof_info_list;
} shared_global_vars_t;

void wait_latch (void);
void spoof_info_print(void);
spoof_info_t* spoof_info_new(str *src_ip, int src_port, str *dst_ip, int dst_port);
void spoof_info_del(spoof_info_t* si);
int rtp_spoof_do(spoof_info_t* si);
#endif
