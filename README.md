Input control parameter 'mode' to check the working mode.

1. NORMAL-K (Native Redirection Mode)

The optimal operating state of the module. It leverages the native parameter redirection mechanism of the kernel's context_struct_compute_av function to redirect all AV (Access Vector) permission calculation requests directly to the clean system policydb, fundamentally shielding Magisk-injected rules and custom security contexts.

2. NORMAL-M (Manual Simulation Calculation Mode)

Legacy kernel compatibility mode. It takes over context_struct_compute_av calls via inline hook, and uses a self-developed AV rule calculation engine to manually compute permission results based on the clean policydb, replacing the native kernel logic. 

3. PARTIAL_FALLBACK (Partial Degradation Mode)

Degraded operating state. The clean policy has been captured but full AV interception cannot be enabled. Only basic filtering is performed based on string features of the policy blob to intercept explicit Magisk context probing. 

4. FULL_FALLBACK (Full Degradation Mode)

The lowest protection level. No clean policy data has been captured, and only basic interception is performed relying on a hard-coded sensitive feature library. The module will fall back to this level in Load mode. 
