Use the `mode` control parameter to check the current operating mode.

1. NORMAL-K (Native Redirection Mode)

The optimal operating mode of the module. It leverages the kernel's native redirection mechanism in the `context_struct_compute_av` function to redirect all AV (Access Vector) permission calculation requests directly to the clean system `policydb`, thereby fundamentally shielding Magisk-injected rules and custom security contexts.

2. NORMAL-M (Manual Simulation Calculation Mode)

Legacy kernel compatibility mode. It intercepts `context_struct_compute_av` calls via an inline hook and uses a custom AV rule calculation engine to manually compute permission results using the clean `policydb`, replacing the native kernel logic.

3. PARTIAL_FALLBACK (Partial Degradation Mode)

A degraded operating mode. The clean policy has been captured, but full AV interception cannot be enabled. Only basic filtering is performed based on string patterns in the policy blob to intercept explicit Magisk context probing.

4. FULL_FALLBACK (Full Degradation Mode)

The lowest protection level. No clean policy data has been captured, and only basic interception is performed using a hard-coded sensitive feature library. The module will fall back to this level during LOAD mode.

The hard-coded sensitive feature library used for basic filtering is supported only on kernels running version 4.14 or lower. For kernel versions 4.19 and above, no disguise mechanism will be enabled during fallback to FULL_FALLBACK mode.