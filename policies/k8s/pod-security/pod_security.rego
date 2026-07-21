# Rego policy for Kubernetes pod-security checks. Applies uniformly to
# Pod and every controller kind that wraps a pod template (Deployment,
# DaemonSet, StatefulSet, ReplicaSet, Job, CronJob) — see
# internal/parser/k8s and internal/normalizer's typeMap, which flatten
# them all to the same "pod_workload" normalized type.

package policyforge.k8s.pod_security

# PF-K8S-001: no container may run as privileged
deny[msg] {
	input.type == "pod_workload"
	input.attributes.privileged == "true"
	msg := sprintf("PF-K8S-001: %q runs a privileged container", [input.name])
}

severity["PF-K8S-001"] = "CRITICAL"

# PF-K8S-002: pod must not use the host network namespace
deny[msg] {
	input.type == "pod_workload"
	input.attributes.host_network == "true"
	msg := sprintf("PF-K8S-002: %q uses hostNetwork", [input.name])
}

severity["PF-K8S-002"] = "HIGH"

# PF-K8S-003: no container may allow privilege escalation
deny[msg] {
	input.type == "pod_workload"
	input.attributes.allow_privilege_escalation == "true"
	msg := sprintf("PF-K8S-003: %q allows privilege escalation", [input.name])
}

severity["PF-K8S-003"] = "HIGH"

# PF-K8S-004: containers must not explicitly disable runAsNonRoot
deny[msg] {
	input.type == "pod_workload"
	input.attributes.run_as_non_root_false == "true"
	msg := sprintf("PF-K8S-004: %q explicitly sets runAsNonRoot: false", [input.name])
}

severity["PF-K8S-004"] = "MEDIUM"

# PF-K8S-005: containers should declare resource limits
deny[msg] {
	input.type == "pod_workload"
	input.attributes.missing_resource_limits == "true"
	msg := sprintf("PF-K8S-005: %q has a container with no resource limits", [input.name])
}

severity["PF-K8S-005"] = "LOW"
