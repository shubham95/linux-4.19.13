/*
 * net/core/netclassid_cgroup.c	Classid Cgroupfs Handling
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Thomas Graf <tgraf@suug.ch>
 */

#include <linux/slab.h>
#include <linux/cgroup.h>
#include <linux/fdtable.h>
#include <linux/sched/task.h>

//TODO
#include <net/cls_cgroup.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/timekeeping.h>
#include <linux/time32.h>

struct packet_count_state pcs = {0};
static DEFINE_MUTEX(tcp_counter_lock);

inline struct cgroup_cls_state *css_cls_state(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct cgroup_cls_state, css) : NULL;
}
EXPORT_SYMBOL_GPL(css_cls_state);

struct cgroup_cls_state *task_cls_state(struct task_struct *p)
{
	return css_cls_state(task_css_check(p, net_cls_cgrp_id,
					    rcu_read_lock_bh_held()));
}
EXPORT_SYMBOL_GPL(task_cls_state);

static struct cgroup_subsys_state *
cgrp_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct cgroup_cls_state *cs;

	cs = kzalloc(sizeof(*cs), GFP_KERNEL);
	if (!cs)
		return ERR_PTR(-ENOMEM);

	return &cs->css;
}

static int cgrp_css_online(struct cgroup_subsys_state *css)
{
	struct cgroup_cls_state *cs = css_cls_state(css);
	struct cgroup_cls_state *parent = css_cls_state(css->parent);

	if (parent)
		cs->classid = parent->classid;

	return 0;
}

static void cgrp_css_free(struct cgroup_subsys_state *css)
{
	kfree(css_cls_state(css));
}

static int update_classid_sock(const void *v, struct file *file, unsigned n)
{
	int err;
	struct socket *sock = sock_from_file(file, &err);

	if (sock) {
		spin_lock(&cgroup_sk_update_lock);
		sock_cgroup_set_classid(&sock->sk->sk_cgrp_data,
					(unsigned long)v);
		spin_unlock(&cgroup_sk_update_lock);
	}
	return 0;
}

static void cgrp_attach(struct cgroup_taskset *tset)
{
	struct cgroup_subsys_state *css;
	struct task_struct *p;

	cgroup_taskset_for_each(p, css, tset) {
		task_lock(p);
		iterate_fd(p->files, 0, update_classid_sock,
			   (void *)(unsigned long)css_cls_state(css)->classid);
		task_unlock(p);
	}
}

static u64 read_classid(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return css_cls_state(css)->classid;
}

static int write_classid(struct cgroup_subsys_state *css, struct cftype *cft,
			 u64 value)
{
	struct cgroup_cls_state *cs = css_cls_state(css);
	struct css_task_iter it;
	struct task_struct *p;

	cgroup_sk_alloc_disable();

	cs->classid = (u32)value;

	css_task_iter_start(css, 0, &it);
	while ((p = css_task_iter_next(&it))) {
		task_lock(p);
		iterate_fd(p->files, 0, update_classid_sock,
			   (void *)(unsigned long)cs->classid);
		task_unlock(p);
		cond_resched();
	}
	css_task_iter_end(&it);

	return 0;
}

static u64 read_tcp_packets_sent(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return css_cls_state(css)->tcp_packets_sent;
}

static int write_tcp_packets_sent(struct cgroup_subsys_state *css, struct cftype *cft,
                         u64 value)
{
        struct cgroup_cls_state *cs = css_cls_state(css);
        cs->tcp_packets_sent = (u32)value;
	printk("Value written to tcp_packets_sent = %d\n", cs->tcp_packets_sent);
	return 0;
}

static u64 read_tcp_packets_rcvd(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return css_cls_state(css)->tcp_packets_rcvd;
}

static int write_tcp_packets_rcvd(struct cgroup_subsys_state *css, struct cftype *cft,
                         u64 value)
{
        struct cgroup_cls_state *cs = css_cls_state(css);
        cs->tcp_packets_rcvd = (u32)value;
	printk("Value written to tcp_packets_rcvd = %d\n", cs->tcp_packets_rcvd);
	return 0;
}

static u64 read_udp_packets_sent(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return css_cls_state(css)->udp_packets_sent;
}

static int write_udp_packets_sent(struct cgroup_subsys_state *css, struct cftype *cft,
                         u64 value)
{
        struct cgroup_cls_state *cs = css_cls_state(css);
        cs->udp_packets_sent = (u32)value;
	printk("Value written to udp_packets_sent = %d\n", cs->udp_packets_sent);
	return 0;
}

static u64 read_udp_packets_rcvd(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return css_cls_state(css)->udp_packets_rcvd;
}

static int write_udp_packets_rcvd(struct cgroup_subsys_state *css, struct cftype *cft,
                         u64 value)
{
        struct cgroup_cls_state *cs = css_cls_state(css);
        cs->tcp_packets_rcvd = (u32)value;
	printk("Value written to udp_packets_rcvd = %d\n", cs->udp_packets_rcvd);
	return 0;
}

static u64 read_tcp_send_rate_pps(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return css_cls_state(css)->tcp_send_rate_pps;
}

static int write_tcp_send_rate_pps(struct cgroup_subsys_state *css, struct cftype *cft,
                         u64 value)
{
        struct cgroup_cls_state *cs = css_cls_state(css);
        cs->tcp_send_rate_pps = (u32)value;
	printk("Value written to tcp_send_rate_pps = %d\n", cs->tcp_send_rate_pps);
	return 0;
}

static u64 read_tcp_rcv_rate_pps(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return css_cls_state(css)->tcp_rcv_rate_pps;
}

static int write_tcp_rcv_rate_pps(struct cgroup_subsys_state *css, struct cftype *cft,
                         u64 value)
{
        struct cgroup_cls_state *cs = css_cls_state(css);
        cs->tcp_rcv_rate_pps = (u32)value;
	printk("Value written to tcp_rcv_rate_pps = %d\n", cs->tcp_rcv_rate_pps);
	return 0;
}

static u64 read_udp_send_rate_pps(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return css_cls_state(css)->udp_send_rate_pps;
}

static int write_udp_send_rate_pps(struct cgroup_subsys_state *css, struct cftype *cft,
                         u64 value)
{
        struct cgroup_cls_state *cs = css_cls_state(css);
        cs->udp_send_rate_pps = (u32)value;
	printk("Value written to udp_send_rate_pps = %d\n", cs->udp_send_rate_pps);
	return 0;
}

static u64 read_udp_rcv_rate_pps(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return css_cls_state(css)->udp_rcv_rate_pps;
}

static int write_udp_rcv_rate_pps(struct cgroup_subsys_state *css, struct cftype *cft,
                         u64 value)
{
        struct cgroup_cls_state *cs = css_cls_state(css);
        cs->udp_rcv_rate_pps = (u32)value;
	printk("Value written to udp_rcv_rate_pps = %d\n", cs->udp_rcv_rate_pps);
	return 0;
}

static u64 read_avg_tcp_segment_size(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return css_cls_state(css)->avg_tcp_segment_size;
}

static int write_avg_tcp_segment_size(struct cgroup_subsys_state *css, struct cftype *cft,
                         u64 value)
{
        struct cgroup_cls_state *cs = css_cls_state(css);
        cs->avg_tcp_segment_size = (u32)value;
	printk("Value written to avg_tcp_segment_size = %d\n", cs->avg_tcp_segment_size);
	return 0;
}

static __kernel_time_t get_cur_time(void)
{
	struct timespec ts;
	getnstimeofday(&ts);

	return ts.tv_sec;
}

static void reset_packet_count_state(struct packet_count_state *pcs)
{
	pcs->cur_time = get_cur_time();
	pcs->tcp_packets_sent_ps = 0;
        pcs->tcp_packets_rcvd_ps = 0;
        pcs->udp_packets_sent_ps = 0;
        pcs->udp_packets_rcvd_ps = 0;

}

static inline u32 incr_count(struct sock *sk, 
		struct cgroup_cls_state *ccs, int type, int pack_size)
{
	char *str = NULL;
	u32 *num_packs = NULL;
	u32 max_packs = 0; 
	u32 *num_packs_ps = NULL;
	struct inet_sock *inet;
	struct tcp_sock *tsock;

	tsock = tcp_sk(sk);

	if(type == TCP_PACKETS_SENT)
	{
		//ccs->tcp_packets_sent += tsock->data_segs_out - 1;
		u32 tmp = ccs->tcp_packets_sent + 1;

		if(tmp > 0 && pack_size > 0)  //checking for overflow
		{
			ccs->tcp_data_sent += pack_size;
			ccs->avg_tcp_segment_size = ccs->tcp_data_sent / tmp;
		}
		num_packs = &(ccs->tcp_packets_sent);
		num_packs_ps = &(pcs.tcp_packets_sent_ps);
		max_packs = ccs->tcp_send_rate_pps;
		str = "TCP packets sent";
	}
	else if(type == TCP_PACKETS_RCVD)
	{
		//ccs->tcp_packets_rcvd += tsock->data_segs_in - 1;
		num_packs = &(ccs->tcp_packets_rcvd);
		num_packs_ps = &(pcs.tcp_packets_rcvd_ps);
		max_packs = ccs->tcp_rcv_rate_pps;
		str = "TCP packets rcvd";
	}
	else if(type == UDP_PACKETS_SENT)
	{
		num_packs = &(ccs->udp_packets_sent);
		num_packs_ps = &(pcs.udp_packets_sent_ps);
		max_packs = ccs->udp_send_rate_pps;
		str = "UDP packets sent";
	}
	else if(type == UDP_PACKETS_RCVD)
	{
		num_packs = &(ccs->udp_packets_rcvd);
		num_packs_ps = &(pcs.udp_packets_rcvd_ps);
		max_packs = ccs->udp_rcv_rate_pps;
		str = "UDP packets rcvd";
	}

	inet = inet_sk(sk);

	if(get_cur_time() > pcs.cur_time) 
	{
		reset_packet_count_state(&pcs);
	}
	else if (max_packs > 0 && *num_packs_ps >= max_packs)
	{
		printk("%s dropped. num_packs = %d, num_packs_ps = %d, "
			"classid = %d, pid = %d, sport = %d, dport = %d, "
			"pack_size = %d, tcp_data_sent = %llu\n",
			str, *num_packs, *num_packs_ps, ccs->classid, 
			current->pid, inet->inet_sport, inet->inet_dport, 
			pack_size, ccs->tcp_data_sent);
		return 1;
	}

	*num_packs += 1;
	*num_packs_ps += 1;

	printk("%s till now = %d, classid = %d, pid = %d, sport = %d, "
			"dport = %d, pack_size = %d, tcp_data_sent = %llu\n", 
			str, *num_packs, ccs->classid, current->pid,
			inet->inet_sport, inet->inet_dport, 
			pack_size, ccs->tcp_data_sent);

	return 0;
}

int update_packet_count(struct sock *sk, int type, int pack_size)
{
        struct task_struct *t = NULL;
        struct cgroup_cls_state *ccs = NULL;
        int sock_classid;
	u32 ret = 0;

	#if 0
	if(0 && sk->sk_socket && sk->sk_socket->cur_process)
		ccs = task_cls_state(sk->sk_socket->cur_process);
	else
		ccs = task_cls_state(current);
	ret = incr_count(sk, ccs, type, pack_size);
	#endif
	//Lock it because multiple process can access at same time
	//mutex_lock(&tcp_counter_lock);

	//Find classid of current socket packet
        sock_classid = sock_cgroup_classid(&(sk->sk_cgrp_data));

	//Find ccs of current process
        ccs = task_cls_state(current);

	//If current process is having same classid as packet
        if(ccs && ccs->classid == sock_classid)
        {
		ret = incr_count(sk, ccs, type, pack_size);
        }
	else
	{
		//Loop through all processes and find correct process
                for_each_process(t)
                {
                        ccs = task_cls_state(t);
                        if(ccs && ccs->classid == sock_classid)
                        {
				ret = incr_count(sk, ccs, type, pack_size);
                                break;
                        }
                }
	}

	return ret;
	//mutex_unlock(&tcp_counter_lock);
}
EXPORT_SYMBOL_GPL(update_packet_count);


static struct cftype ss_files[] = {
	{
		.name		= "classid",
		.read_u64	= read_classid,
		.write_u64	= write_classid,
	},

	{
		.name		= "tcp_packets_sent",
		.read_u64	= read_tcp_packets_sent,
		.write_u64	= write_tcp_packets_sent,
	},

	{
		.name		= "tcp_packets_rcvd",
		.read_u64	= read_tcp_packets_rcvd,
		.write_u64	= write_tcp_packets_rcvd,
	},

	{
		.name		= "udp_packets_sent",
		.read_u64	= read_udp_packets_sent,
		.write_u64	= write_udp_packets_sent,
	},

	{
		.name		= "udp_packets_rcvd",
		.read_u64	= read_udp_packets_rcvd,
		.write_u64	= write_udp_packets_rcvd,
	},

	{
		.name		= "tcp_send_rate_pps",
		.read_u64	= read_tcp_send_rate_pps,
		.write_u64	= write_tcp_send_rate_pps,
	},

	{
		.name		= "tcp_rcv_rate_pps",
		.read_u64	= read_tcp_rcv_rate_pps,
		.write_u64	= write_tcp_rcv_rate_pps,
	},

	{
		.name		= "udp_send_rate_pps",
		.read_u64	= read_udp_send_rate_pps,
		.write_u64	= write_udp_send_rate_pps,
	},

	{
		.name		= "udp_rcv_rate_pps",
		.read_u64	= read_udp_rcv_rate_pps,
		.write_u64	= write_udp_rcv_rate_pps,
	},

	{
		.name		= "avg_tcp_segment_size",
		.read_u64	= read_avg_tcp_segment_size,
		.write_u64	= write_avg_tcp_segment_size,
	},

	{ }	/* terminate */
};

struct cgroup_subsys net_cls_cgrp_subsys = {
	.css_alloc		= cgrp_css_alloc,
	.css_online		= cgrp_css_online,
	.css_free		= cgrp_css_free,
	.attach			= cgrp_attach,
	.legacy_cftypes		= ss_files,
};
