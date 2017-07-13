# Docker Security defaults

## Capabilities

The default set of capabilities in Docker is the following:

    CAP_CHOWN
    CAP_DAC_OVERRIDE
    CAP_FSETID
    CAP_FOWNER
    CAP_MKNOD
    CAP_NET_RAW
    CAP_SETGID
    CAP_SETUID
    CAP_SETFCAP
    CAP_SETPCAP
    CAP_NET_BIND_SERVICE
    CAP_SYS_CHROOT
    CAP_KILL
    CAP_AUDIT_WRITE

## Seccomp

The default Seccomp profile in Docker can be found [here](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).

## AppArmor

The default AppArmor profile template in Docker can be found here [here](https://github.com/moby/moby/blob/master/profiles/apparmor/template.go).

