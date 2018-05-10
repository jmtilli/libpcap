/*
 *  pcap-ldp.c: Packet capture interface to LDP
 *
 *  Copyright (c) 2000 Torsten Landschoff <torsten@debian.org>
 *  		       Sebastian Krahmer  <krahmer@cs.uni-potsdam.de>
 *  Copyright (c) 2014 Luigi Rizzo
 *  Copyright (c) 2018 Juha-Matti Tilli <juha-matti.tilli@iki.fi>
 *
 *  License: BSD
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *  3. The names of the authors may not be used to endorse or promote
 *     products derived from this software without specific prior
 *     written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 *  IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <poll.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ldp.h>
#include <linkcommon.h>

#include "pcap-int.h"
#include "pcap-ldp.h"



/*
 * $FreeBSD: head/lib/libpcap/pcap-netmap.c 272659 2014-10-06 15:48:28Z luigi $
 *
 * This code is meant to build also on other versions of libpcap.
 *
 * older libpcap miss p->priv, use p->md.device instead (and allocate).
 * Also opt.timeout was in md.timeout before.
 * Use #define PCAP_IF_UP to discriminate
 */
#ifdef PCAP_IF_UP
#define LDP_PRIV(p)	((struct pcap_ldp *)(p->priv))
#define the_timeout	opt.timeout
#else
#define HAVE_NO_PRIV
#define	LDP_PRIV(p)	((struct pcap_ldp *)(p->md.device))
#define SET_PRIV(p, x)	p->md.device = (void *)x
#define the_timeout	md.timeout
#endif


struct pcap_ldp {
  struct ldp_interface *intf;
  pcap_handler cb;
  u_char *cb_arg;
  int must_clear_promisc; /* flag */
  uint64_t rx_pkts; /* # of pkts received before the filter */
};

static int
pcap_ldp_stats(pcap_t *p, struct pcap_stat *ps)
{
  struct pcap_ldp *pl = LDP_PRIV(p);
  ps->ps_recv = pl->rx_pkts;
  ps->ps_drop = 0;
  ps->ps_ifdrop = 0;
  return 0;
}

static void
pcap_ldp_filter(u_char *arg, struct pcap_pkthdr *h, const u_char *buf)
{
	pcap_t *p = (pcap_t *)arg;
	struct pcap_ldp *pl = LDP_PRIV(p);
	const struct bpf_insn *pc = p->fcode.bf_insns;

	++pl->rx_pkts;
	if (pc == NULL || bpf_filter(pc, buf, h->len, h->caplen))
		pl->cb(pl->cb_arg, h, buf);
}

static int
ldp_dispatch(struct ldp_interface *intf, int cnt, pcap_handler cb, u_char *arg)
{
  uint64_t ts;
  int realcnt = cnt;
  int recvcnt, i;
  if (realcnt < 0)
  {
    realcnt = 256;
  }
  if (realcnt > 256)
  {
    realcnt = 256;
  }
  struct ldp_packet pkts[realcnt];
  recvcnt = ldp_in_nextpkts_ts(intf->inq[0], pkts, realcnt, &ts);
  for (i = 0; i < recvcnt; i++)
  {
    struct pcap_pkthdr hdr;
    hdr.len = hdr.caplen = pkts[i].sz;
    hdr.ts.tv_sec = ts/(1000ULL*1000ULL);
    hdr.ts.tv_usec = ts%(1000ULL*1000ULL);
    cb(arg, &hdr, pkts[i].data);
  }
  ldp_in_deallocate_some(intf->inq[0], pkts, recvcnt);
}

static int
pcap_ldp_dispatch(pcap_t *p, int cnt, pcap_handler cb, u_char *user)
{
	int ret;
	struct pcap_ldp *pl = LDP_PRIV(p);
	struct ldp_interface *d = pl->intf;
	struct pollfd pfd = { .fd = -1, .events = POLLIN, .revents = 0 };

	pl->cb = cb;
	pl->cb_arg = user;

	for (;;) {
		if (p->break_loop) {
			p->break_loop = 0;
			return PCAP_ERROR_BREAK;
		}
		/* nm_dispatch won't run forever */

		ret = ldp_dispatch((void *)d, cnt, (void *)pcap_ldp_filter, (void *)p);
		if (ret != 0)
			break;
		errno = 0;
                if (d->inq[0]->fd >= 0)
                {
                  pfd.fd = d->inq[0]->fd;
		  ret = poll(&pfd, 1, p->the_timeout);
                }
	}
	return ret;
}

static int
pcap_ldp_inject(pcap_t *p, const void *buf, size_t size)
{
  struct ldp_interface *intf = LDP_PRIV(p)->intf;
  struct ldp_packet pkt;
  int ret;
  pkt.data = (void*)buf;
  pkt.sz = size;
  ret = ldp_out_inject(intf->outq[0], &pkt, 1);
  ldp_out_txsync(intf->outq[0]);
  return ret;
}

static void
pcap_ldp_close(pcap_t *p)
{
  struct pcap_ldp *pl = LDP_PRIV(p);
  struct ldp_interface *intf = pl->intf;
  if (pl->must_clear_promisc) {
    ldp_interface_set_promisc_mode(intf, 0);
  }
  ldp_interface_close(intf);
#ifdef HAVE_NO_PRIV
  free(pl);
  SET_PRIV(p, NULL); // unnecessary
#endif
  pcap_cleanup_live_common(p);
}

static int
pcap_ldp_activate(pcap_t *p)
{
	struct pcap_ldp *pn = p->priv;
	struct ldp_interface *intf;
	uint32_t if_flags = 0;

	intf = ldp_interface_open(p->opt.device+4, 1, 1);
	if (intf == NULL) {
		pcap_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "ldp open: cannot access %s",
		    p->opt.device);
		pcap_cleanup_live_common(p);
		return (PCAP_ERROR);
	}
#if 0
	fprintf(stderr, "%s device %s priv %p fd %d ports %d..%d\n",
	    __FUNCTION__, p->opt.device, d, d->fd,
	    d->first_rx_ring, d->last_rx_ring);
#endif
	pn->intf = intf;
	p->fd = intf->inq[0]->fd;

	/*
	 * Turn a negative snapshot value (invalid), a snapshot value of
	 * 0 (unspecified), or a value bigger than the normal maximum
	 * value, into the maximum allowed value.
	 *
	 * If some application really *needs* a bigger snapshot
	 * length, we should just increase MAXIMUM_SNAPLEN.
	 */
	if (p->snapshot <= 0 || p->snapshot > MAXIMUM_SNAPLEN)
		p->snapshot = MAXIMUM_SNAPLEN;

	if (p->opt.promisc) {
		int was_promisc = ldp_interface_get_promisc_mode(intf);
		if (!was_promisc) {
			pn->must_clear_promisc = 1;
			ldp_interface_set_promisc_mode(intf, 1);
			
		}
	}
	p->linktype = DLT_EN10MB;
	p->selectable_fd = p->fd;
	p->read_op = pcap_ldp_dispatch;
	p->inject_op = pcap_ldp_inject;
	p->setfilter_op = install_bpf_program;
	p->setdirection_op = NULL;
	p->set_datalink_op = NULL;
	p->getnonblock_op = pcap_getnonblock_fd;
	p->setnonblock_op = pcap_setnonblock_fd;
	p->stats_op = pcap_ldp_stats;
	p->cleanup_op = pcap_ldp_close;

	return (0);
}

pcap_t *
pcap_ldp_create(const char *device, char *ebuf, int *is_ours)
{
	pcap_t *p;

	*is_ours = (!strncmp(device, "ldp:", 4));
	if (! *is_ours)
		return NULL;
	p = pcap_create_common(ebuf, sizeof (struct pcap_ldp));
	if (p == NULL)
		return (NULL);
	p->activate_op = pcap_ldp_activate;
	return (p);
}

/*
 * The "device name" for ldp devices isn't a name for a device, it's
 * an expression that indicates how the device should be set up, so
 * there's no way to enumerate them.
 */
int
pcap_ldp_findalldevs(pcap_if_list_t *devlistp _U_, char *err_str _U_)
{
	return 0;
}
