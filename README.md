## Supported Kernel Versions

selinux_MAF_fork is supported on:

- Linux 4.19 or later
- Some Linux 4.14 kernels (reference: 4.14.180 or later)

For Linux 4.14 or earlier kernels, support requires the following SELinux
layouts:

`/security/selinux/include/security.h`

```c
extern struct page *selinux_kernel_status_page(struct selinux_state *state);
```

`/security/selinux/ss/services.c`

```c
static void context_struct_compute_av(struct policydb *policydb,
                                      struct context *scontext,
                                      struct context *tcontext,
                                      u16 tclass,
                                      struct av_decision *avd,
                                      struct extended_perms *xperms);
```

<sub>Theoretically, some Linux 4.9 kernels may also be supported (reference: 4.9.223 or later), but they have not been thoroughly tested.</sub>

## Operating Modes

Use the `mode` control parameter to check the current operating mode.

1. NORMAL

The normal operating mode. The kernel supports both `policydb` redirection and
status-page redirection, and the module has successfully captured and loaded a
clean system `policydb`. Access Vector calculations made inside the clean
evaluation scope are redirected to that policy database, shielding them from
Magisk-injected policy changes.

2. POLICYDB_REQ

The kernel supports both `policydb` redirection and status-page redirection,
but the module could not obtain a usable clean `policydb`. No manual AV
calculation or hard-coded access/context filtering is used; SELinux policy
evaluation remains on the kernel's live path.

3. UNSUPORRT

The kernel does not support `policydb` redirection. Policy-related
redirect and filtering hooks are disabled, while status-page handling remains
independent; the kernel's native SELinux policy behavior is preserved.

The status-page and clean-policy capture hooks are independent of these mode
labels and may remain active when policydb redirection is unavailable.
