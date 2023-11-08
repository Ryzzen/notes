```c
struct thread_info {
	struct task_struct *task;
	struct exec_domain *exec_domain;
	__u32 flags;
	__u32 status;
	__u32 cpu;
	int preempt_count;
	mm_segment_t addr_limit;
	struct restart_block restart_block;
	void __user *sysenter_return;
#ifdef CONFIG_X86_32
	unsigned long previous_esp;
	__u8 supervisor_stack[0];
#endif
	int uaccess_err;
};


struct task_struct {
	...
	/* Process credentials: */

	/* Tracer's credentials at attach: */
	const struct cred __rcu		*ptracer_cred;

	/* Objective and real subjective task credentials (COW): */
	const struct cred __rcu		*real_cred;

	/* Effective (overridable) subjective task credentials (COW): */
	const struct cred __rcu		*cred;
	... 
};


struct cred {
	atomic_t    usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t    subscribers;           /* number of processes subscribed */
	void        *put_addr;
	unsigned    magic;
#define CRED_MAGIC  0x43736564
#define CRED_MAGIC_DEAD 0x44656144
#endif
	kuid_t      uid;                   /* real UID of the task */
	kgid_t      gid;                   /* real GID of the task */
	kuid_t      suid;                  /* saved UID of the task */
	kgid_t      sgid;                  /* saved GID of the task */
	kuid_t      euid;                  /* effective UID of the task */
	kgid_t      egid;                  /* effective GID of the task */
	kuid_t      fsuid;                 /* UID for VFS ops */
	kgid_t      fsgid;                 /* GID for VFS ops */
	unsigned    securebits;            /* SUID-less security management */
	kernel_cap_t    cap_inheritable;   /* caps our children can inherit */
	kernel_cap_t    cap_permitted;     /* caps we're permitted */
	kernel_cap_t    cap_effective;     /* caps we can actually use */
	kernel_cap_t    cap_bset;          /* capability bounding set */
	kernel_cap_t    cap_ambient;       /* Ambient capability set */
#ifdef CONFIG_KEYS
	unsigned char   jit_keyring;       /* default keyring to attach requested
	/* keys to */
	struct key __rcu *session_keyring; /* keyring inherited over fork */
	struct key  *process_keyring;      /* keyring private to this process */
	struct key  *thread_keyring;       /* keyring private to this thread */
	struct key  *request_key_auth;     /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
	void        *security;             /* subjective LSM security */
#endif
	struct user_struct *user;          /* real user ID subscription */
	struct user_namespace *user_ns;    /* user_ns the caps and keyrings are relative to. */
	struct group_info *group_info;     /* supplementary groups for euid/fsgid */
	struct rcu_head rcu;               /* RCU deletion hook */
} __randomize_layout;


struct restart_block {
 long (*fn)(struct restart_block *);
	union {
	struct {
	...
	};
	/* For futex_wait and futex_wait_requeue_pi */
	struct {
	...
	} futex;
	/* For nanosleep */
	struct {
	...
	} nanosleep;
	/* For poll */
	struct {
	...
	} poll;
};
```