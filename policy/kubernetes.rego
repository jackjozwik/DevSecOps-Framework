package main

import future.keywords.in

deny_non_root[msg] {
    some i in input.spec.containers
    not i.securityContext.runAsNonRoot
    msg := sprintf("Container %s should not run as root", [i.name])
}


deny_privileged[msg] {
    some i in input.spec.containers
    i.securityContext.privileged == true
    msg := sprintf("Container %s should not run as privileged", [i.name])
}


deny_privilege_escalation[msg] {
    some i in input.spec.containers
    not i.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container %s should not allow privilege escalation", [i.name])
}


deny_no_selinux[msg] {
    some i in input.spec.containers
    not i.securityContext.seLinuxOptions
    msg := sprintf("Container %s should set SELinux context", [i.name])
}


deny_no_apparmor[msg] {
    some i in input.metadata.annotations
    not contains(i, "container.apparmor.security.beta.kubernetes.io/")
    msg := sprintf("Pod %s should set AppArmor profile", [input.metadata.name])
}


deny_no_seccomp[msg] {
    some i in input.metadata.annotations
    not contains(i, "container.seccomp.security.alpha.kubernetes.io/")
    msg := sprintf("Pod %s should set seccomp profile", [input.metadata.name])
}


deny_kube_system[msg] {
    input.metadata.namespace == "kube-system"
    msg := "Namespace kube-system should not be used by users"
}
