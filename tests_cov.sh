#!/usr/local/bin/bash

tar -xf tests.tar.xz

cc kcovtrace.c -o kcovtrace

export WORKDIR=$(pwd)
export KCOVTRACE=$WORKDIR/kcovtrace
export KPATH=$WORKDIR/rawfile

#export KCOVTRACE=/root/kcovtrace/kcovtrace KPATH=/root/kcovtrace/rawfile

rm $KPATH

cd tests/sys

$KCOVTRACE acl/00
$KCOVTRACE acl/01
$KCOVTRACE acl/02
$KCOVTRACE acl/03
$KCOVTRACE acl/04

$KCOVTRACE aio/aio_kqueue_test
$KCOVTRACE aio/lio_kqueue_test

$KCOVTRACE aio/aio_test file_poll
$KCOVTRACE aio/aio_test file_signal
$KCOVTRACE aio/aio_test file_suspend
$KCOVTRACE aio/aio_test file_thread
$KCOVTRACE aio/aio_test file_waitcomplete
$KCOVTRACE aio/aio_test fifo_poll
$KCOVTRACE aio/aio_test fifo_signal
$KCOVTRACE aio/aio_test fifo_suspend
$KCOVTRACE aio/aio_test fifo_thread
$KCOVTRACE aio/aio_test fifo_waitcomplete
$KCOVTRACE aio/aio_test socket_poll
$KCOVTRACE aio/aio_test socket_signal
$KCOVTRACE aio/aio_test socket_suspend
$KCOVTRACE aio/aio_test socket_thread
$KCOVTRACE aio/aio_test socket_waitcomplete
$KCOVTRACE aio/aio_test pty_poll
$KCOVTRACE aio/aio_test pipe_signal
$KCOVTRACE aio/aio_test pipe_suspend
$KCOVTRACE aio/aio_test pipe_thread
$KCOVTRACE aio/aio_test pipe_waitcomplete
$KCOVTRACE aio/aio_test md_poll
$KCOVTRACE aio/aio_test md_signal
$KCOVTRACE aio/aio_test md_suspend
$KCOVTRACE aio/aio_test md_thread
$KCOVTRACE aio/aio_test md_waitcomplete
$KCOVTRACE aio/aio_test aio_fsync_errors
$KCOVTRACE aio/aio_test aio_fsync_sync_test
$KCOVTRACE aio/aio_test aio_fsync_dsync_test
$KCOVTRACE aio/aio_test aio_large_read_test
$KCOVTRACE aio/aio_test aio_socket_two_reads
$KCOVTRACE aio/aio_test aio_socket_blocking_short_write
$KCOVTRACE aio/aio_test aio_socket_blocking_short_write_vectored
$KCOVTRACE aio/aio_test aio_socket_short_write_cancel
$KCOVTRACE aio/aio_test aio_writev_dos_iov_len
$KCOVTRACE aio/aio_test aio_writev_dos_iovcnt
$KCOVTRACE aio/aio_test aio_writev_efault
$KCOVTRACE aio/aio_test aio_writev_empty_file_poll
$KCOVTRACE aio/aio_test aio_writev_empty_file_signal
$KCOVTRACE aio/aio_test vectored_big_iovcnt
$KCOVTRACE aio/aio_test vectored_file_poll
$KCOVTRACE aio/aio_test vectored_md_poll
$KCOVTRACE aio/aio_test vectored_zvol_poll
$KCOVTRACE aio/aio_test vectored_unaligned
$KCOVTRACE aio/aio_test vectored_socket_poll

$KCOVTRACE aio/lio_test lio_listio_eagain_kevent
$KCOVTRACE aio/lio_test lio_listio_empty_nowait
#$KCOVTRACE aio/lio_test lio_listio_empty_nowait_kevent
$KCOVTRACE aio/lio_test lio_listio_empty_nowait_signal
$KCOVTRACE aio/lio_test lio_listio_empty_nowait_thread
$KCOVTRACE aio/lio_test lio_listio_empty_wait
$KCOVTRACE aio/lio_test lio_listio_invalid_opcode

$KCOVTRACE audit/administrative settimeofday_success
$KCOVTRACE audit/administrative settimeofday_failure
$KCOVTRACE audit/administrative clock_settime_success
$KCOVTRACE audit/administrative clock_settime_failure
$KCOVTRACE audit/administrative adjtime_success
$KCOVTRACE audit/administrative adjtime_failure
$KCOVTRACE audit/administrative ntp_adjtime_success
$KCOVTRACE audit/administrative ntp_adjtime_failure
$KCOVTRACE audit/administrative nfs_getfh_success
$KCOVTRACE audit/administrative nfs_getfh_failure
$KCOVTRACE audit/administrative acct_success
$KCOVTRACE audit/administrative acct_failure
$KCOVTRACE audit/administrative auditctl_success
$KCOVTRACE audit/administrative auditctl_failure
$KCOVTRACE audit/administrative getauid_success
$KCOVTRACE audit/administrative getauid_failure
$KCOVTRACE audit/administrative setauid_success
$KCOVTRACE audit/administrative setauid_failure
$KCOVTRACE audit/administrative getaudit_success
$KCOVTRACE audit/administrative getaudit_failure
$KCOVTRACE audit/administrative setaudit_success
$KCOVTRACE audit/administrative setaudit_failure
$KCOVTRACE audit/administrative getaudit_addr_success
$KCOVTRACE audit/administrative getaudit_addr_failure
$KCOVTRACE audit/administrative setaudit_addr_success
$KCOVTRACE audit/administrative setaudit_addr_failure
$KCOVTRACE audit/administrative auditon_default_success
$KCOVTRACE audit/administrative auditon_default_failure
$KCOVTRACE audit/administrative auditon_getpolicy_success
$KCOVTRACE audit/administrative auditon_getpolicy_failure
$KCOVTRACE audit/administrative auditon_setpolicy_success
$KCOVTRACE audit/administrative auditon_setpolicy_failure
$KCOVTRACE audit/administrative auditon_getkmask_success
$KCOVTRACE audit/administrative auditon_getkmask_failure
$KCOVTRACE audit/administrative auditon_setkmask_success
$KCOVTRACE audit/administrative auditon_setkmask_failure
$KCOVTRACE audit/administrative auditon_getqctrl_success
$KCOVTRACE audit/administrative auditon_getqctrl_failure
$KCOVTRACE audit/administrative auditon_setqctrl_success
$KCOVTRACE audit/administrative auditon_setqctrl_failure
$KCOVTRACE audit/administrative auditon_getclass_success
$KCOVTRACE audit/administrative auditon_getclass_failure
$KCOVTRACE audit/administrative auditon_setclass_success
$KCOVTRACE audit/administrative auditon_setclass_failure
$KCOVTRACE audit/administrative auditon_getcond_success
$KCOVTRACE audit/administrative auditon_getcond_failure
$KCOVTRACE audit/administrative auditon_setcond_success
$KCOVTRACE audit/administrative auditon_setcond_failure
$KCOVTRACE audit/administrative auditon_getcwd_failure
$KCOVTRACE audit/administrative auditon_getcar_failure
$KCOVTRACE audit/administrative auditon_getstat_failure
$KCOVTRACE audit/administrative auditon_setstat_failure
$KCOVTRACE audit/administrative auditon_setumask_failure
$KCOVTRACE audit/administrative auditon_setsmask_failure
$KCOVTRACE audit/administrative reboot_failure
$KCOVTRACE audit/administrative quotactl_failure
$KCOVTRACE audit/administrative mount_failure
$KCOVTRACE audit/administrative nmount_failure
$KCOVTRACE audit/administrative swapon_failure
$KCOVTRACE audit/administrative swapoff_failure

$KCOVTRACE audit/file-close munmap_success
$KCOVTRACE audit/file-close munmap_failure
$KCOVTRACE audit/file-close close_success
$KCOVTRACE audit/file-close close_failure
$KCOVTRACE audit/file-close closefrom_success
$KCOVTRACE audit/file-close revoke_success
$KCOVTRACE audit/file-close revoke_failure

$KCOVTRACE audit/file-create mkdir_success
$KCOVTRACE audit/file-create mkdir_failure
$KCOVTRACE audit/file-create mkdirat_success
$KCOVTRACE audit/file-create mkdirat_failure
$KCOVTRACE audit/file-create mkfifo_success
$KCOVTRACE audit/file-create mkfifo_failure
$KCOVTRACE audit/file-create mkfifoat_success
$KCOVTRACE audit/file-create mkfifoat_failure
$KCOVTRACE audit/file-create mknod_success
$KCOVTRACE audit/file-create mknod_failure
$KCOVTRACE audit/file-create mknodat_success
$KCOVTRACE audit/file-create mknodat_failure
$KCOVTRACE audit/file-create rename_success
$KCOVTRACE audit/file-create rename_failure
$KCOVTRACE audit/file-create renameat_success
$KCOVTRACE audit/file-create renameat_failure
$KCOVTRACE audit/file-create link_success
$KCOVTRACE audit/file-create link_failure
$KCOVTRACE audit/file-create linkat_success
$KCOVTRACE audit/file-create linkat_failure
$KCOVTRACE audit/file-create symlink_success
$KCOVTRACE audit/file-create symlink_failure
$KCOVTRACE audit/file-create symlinkat_success
$KCOVTRACE audit/file-create symlinkat_failure

$KCOVTRACE audit/file-delete rmdir_success
$KCOVTRACE audit/file-delete rmdir_failure
$KCOVTRACE audit/file-delete rename_success
$KCOVTRACE audit/file-delete rename_failure
$KCOVTRACE audit/file-delete renameat_success
$KCOVTRACE audit/file-delete renameat_failure
$KCOVTRACE audit/file-delete unlink_success
$KCOVTRACE audit/file-delete unlink_failure
$KCOVTRACE audit/file-delete unlinkat_success
$KCOVTRACE audit/file-delete unlinkat_failure

$KCOVTRACE audit/file-read readlink_success
$KCOVTRACE audit/file-read readlink_failure
$KCOVTRACE audit/file-read readlinkat_success
$KCOVTRACE audit/file-read readlinkat_failure

$KCOVTRACE audit/file-write truncate_success 
$KCOVTRACE audit/file-write truncate_failure
$KCOVTRACE audit/file-write ftruncate_success
$KCOVTRACE audit/file-write ftruncate_failure

$KCOVTRACE audit/inter-process msgget_success
$KCOVTRACE audit/inter-process msgget_failure
$KCOVTRACE audit/inter-process msgsnd_success
$KCOVTRACE audit/inter-process msgsnd_failure
$KCOVTRACE audit/inter-process msgrcv_success
$KCOVTRACE audit/inter-process msgrcv_failure
$KCOVTRACE audit/inter-process msgctl_rmid_success
$KCOVTRACE audit/inter-process msgctl_rmid_failure
$KCOVTRACE audit/inter-process msgctl_stat_success
$KCOVTRACE audit/inter-process msgctl_stat_failure
$KCOVTRACE audit/inter-process msgctl_set_success
$KCOVTRACE audit/inter-process msgctl_set_failure
$KCOVTRACE audit/inter-process msgctl_illegal_command
$KCOVTRACE audit/inter-process shmget_success
$KCOVTRACE audit/inter-process shmget_failure
$KCOVTRACE audit/inter-process shmat_success
$KCOVTRACE audit/inter-process shmat_failure
$KCOVTRACE audit/inter-process shmdt_success
$KCOVTRACE audit/inter-process shmdt_failure
$KCOVTRACE audit/inter-process shmctl_rmid_success
$KCOVTRACE audit/inter-process shmctl_rmid_failure
$KCOVTRACE audit/inter-process shmctl_stat_success
$KCOVTRACE audit/inter-process shmctl_stat_failure
$KCOVTRACE audit/inter-process shmctl_set_success
$KCOVTRACE audit/inter-process shmctl_set_failure
$KCOVTRACE audit/inter-process shmctl_illegal_command
$KCOVTRACE audit/inter-process semget_success
$KCOVTRACE audit/inter-process semget_failure
$KCOVTRACE audit/inter-process semop_success
$KCOVTRACE audit/inter-process semop_failure
$KCOVTRACE audit/inter-process semctl_getval_success
$KCOVTRACE audit/inter-process semctl_getval_failure
$KCOVTRACE audit/inter-process semctl_setval_success
$KCOVTRACE audit/inter-process semctl_setval_failure
$KCOVTRACE audit/inter-process semctl_getpid_success
$KCOVTRACE audit/inter-process semctl_getpid_failure
$KCOVTRACE audit/inter-process semctl_getncnt_success
$KCOVTRACE audit/inter-process semctl_getncnt_failure
$KCOVTRACE audit/inter-process semctl_getzcnt_success
$KCOVTRACE audit/inter-process semctl_getzcnt_failure
$KCOVTRACE audit/inter-process semctl_getall_success
$KCOVTRACE audit/inter-process semctl_getall_failure
$KCOVTRACE audit/inter-process semctl_setall_success
$KCOVTRACE audit/inter-process semctl_setall_failure
$KCOVTRACE audit/inter-process semctl_stat_success
$KCOVTRACE audit/inter-process semctl_stat_failure
$KCOVTRACE audit/inter-process semctl_set_success
$KCOVTRACE audit/inter-process semctl_set_failure
$KCOVTRACE audit/inter-process semctl_rmid_success
$KCOVTRACE audit/inter-process semctl_rmid_failure
$KCOVTRACE audit/inter-process semctl_illegal_command
$KCOVTRACE audit/inter-process shm_open_success
$KCOVTRACE audit/inter-process shm_open_failure
$KCOVTRACE audit/inter-process shm_unlink_success
$KCOVTRACE audit/inter-process shm_unlink_failure
$KCOVTRACE audit/inter-process pipe_success
$KCOVTRACE audit/inter-process pipe_failure
$KCOVTRACE audit/inter-process posix_openpt_success
$KCOVTRACE audit/inter-process posix_openpt_failure

$KCOVTRACE audit/ioctl ioctl_success
$KCOVTRACE audit/ioctl ioctl_failure

$KCOVTRACE audit/miscellaneous audit_failure
$KCOVTRACE audit/miscellaneous sysarch_success
$KCOVTRACE audit/miscellaneous sysarch_failure
$KCOVTRACE audit/miscellaneous sysctl_success
$KCOVTRACE audit/miscellaneous sysctl_failure

$KCOVTRACE audit/network socket_success
$KCOVTRACE audit/network socket_failure
$KCOVTRACE audit/network socketpair_success
$KCOVTRACE audit/network socketpair_failure
$KCOVTRACE audit/network setsockopt_success
$KCOVTRACE audit/network setsockopt_failure
$KCOVTRACE audit/network bind_success
$KCOVTRACE audit/network bind_failure
$KCOVTRACE audit/network bindat_success
$KCOVTRACE audit/network bindat_failure
$KCOVTRACE audit/network listen_success
$KCOVTRACE audit/network listen_failure
$KCOVTRACE audit/network connect_success
$KCOVTRACE audit/network connect_failure
$KCOVTRACE audit/network connectat_success
$KCOVTRACE audit/network connectat_failure
$KCOVTRACE audit/network accept_success
$KCOVTRACE audit/network accept_failure
$KCOVTRACE audit/network send_success
$KCOVTRACE audit/network send_failure
$KCOVTRACE audit/network recv_success
$KCOVTRACE audit/network recv_failure
$KCOVTRACE audit/network sendto_success
$KCOVTRACE audit/network sendto_failure
$KCOVTRACE audit/network recvfrom_success
$KCOVTRACE audit/network recvfrom_failure
$KCOVTRACE audit/network sendmsg_success
$KCOVTRACE audit/network sendmsg_failure
$KCOVTRACE audit/network recvmsg_success
$KCOVTRACE audit/network recvmsg_failure
$KCOVTRACE audit/network shutdown_success
$KCOVTRACE audit/network shutdown_failure
$KCOVTRACE audit/network sendfile_success
$KCOVTRACE audit/network sendfile_failure
$KCOVTRACE audit/network setfib_success
$KCOVTRACE audit/network setfib_failure

$KCOVTRACE audit/open open_read_success
$KCOVTRACE audit/open open_read_failure
$KCOVTRACE audit/open openat_read_success
$KCOVTRACE audit/open openat_read_failure
$KCOVTRACE audit/open open_read_creat_success
$KCOVTRACE audit/open open_read_creat_failure
$KCOVTRACE audit/open openat_read_creat_success
$KCOVTRACE audit/open openat_read_creat_failure
$KCOVTRACE audit/open open_read_trunc_success
$KCOVTRACE audit/open open_read_trunc_failure
$KCOVTRACE audit/open openat_read_trunc_success
$KCOVTRACE audit/open openat_read_trunc_failure
$KCOVTRACE audit/open open_read_creat_trunc_success
$KCOVTRACE audit/open open_read_creat_trunc_failure
$KCOVTRACE audit/open openat_read_creat_trunc_success
$KCOVTRACE audit/open openat_read_creat_trunc_failure
$KCOVTRACE audit/open open_write_success
$KCOVTRACE audit/open open_write_failure
$KCOVTRACE audit/open openat_write_success
$KCOVTRACE audit/open openat_write_failure
$KCOVTRACE audit/open open_write_creat_success
$KCOVTRACE audit/open open_write_creat_failure
$KCOVTRACE audit/open openat_write_creat_success
$KCOVTRACE audit/open openat_write_creat_failure
$KCOVTRACE audit/open open_write_trunc_success
$KCOVTRACE audit/open open_write_trunc_failure
$KCOVTRACE audit/open openat_write_trunc_success
$KCOVTRACE audit/open openat_write_trunc_failure
$KCOVTRACE audit/open open_write_creat_trunc_success
$KCOVTRACE audit/open open_write_creat_trunc_failure
$KCOVTRACE audit/open openat_write_creat_trunc_success
$KCOVTRACE audit/open openat_write_creat_trunc_failure
$KCOVTRACE audit/open open_read_write_success
$KCOVTRACE audit/open open_read_write_failure
$KCOVTRACE audit/open openat_read_write_success
$KCOVTRACE audit/open openat_read_write_failure
$KCOVTRACE audit/open open_read_write_creat_success
$KCOVTRACE audit/open open_read_write_creat_failure
$KCOVTRACE audit/open openat_read_write_creat_success
$KCOVTRACE audit/open openat_read_write_creat_failure
$KCOVTRACE audit/open open_read_write_trunc_success
$KCOVTRACE audit/open open_read_write_trunc_failure
$KCOVTRACE audit/open openat_read_write_trunc_success
$KCOVTRACE audit/open openat_read_write_trunc_failure
$KCOVTRACE audit/open open_read_write_creat_trunc_success
$KCOVTRACE audit/open open_read_write_creat_trunc_failure
$KCOVTRACE audit/open openat_read_write_creat_trunc_success
$KCOVTRACE audit/open openat_read_write_creat_trunc_failure

$KCOVTRACE audit/process-control fork_success
$KCOVTRACE audit/process-control _exit_success
$KCOVTRACE audit/process-control rfork_success
$KCOVTRACE audit/process-control rfork_failure
$KCOVTRACE audit/process-control wait4_success
$KCOVTRACE audit/process-control wait4_failure
$KCOVTRACE audit/process-control wait6_success
$KCOVTRACE audit/process-control wait6_failure
$KCOVTRACE audit/process-control kill_success
$KCOVTRACE audit/process-control kill_failure
$KCOVTRACE audit/process-control chdir_success
$KCOVTRACE audit/process-control chdir_failure
$KCOVTRACE audit/process-control fchdir_success
$KCOVTRACE audit/process-control fchdir_failure
$KCOVTRACE audit/process-control chroot_success
$KCOVTRACE audit/process-control chroot_failure
$KCOVTRACE audit/process-control umask_success
$KCOVTRACE audit/process-control setuid_success
$KCOVTRACE audit/process-control seteuid_success
$KCOVTRACE audit/process-control setgid_success
$KCOVTRACE audit/process-control setegid_success
$KCOVTRACE audit/process-control setreuid_success
$KCOVTRACE audit/process-control setregid_success
$KCOVTRACE audit/process-control setresuid_success
$KCOVTRACE audit/process-control setresgid_success
$KCOVTRACE audit/process-control getresuid_success
$KCOVTRACE audit/process-control getresuid_failure
$KCOVTRACE audit/process-control getresgid_success
$KCOVTRACE audit/process-control getresgid_failure
$KCOVTRACE audit/process-control setpriority_success
$KCOVTRACE audit/process-control setpriority_failure
$KCOVTRACE audit/process-control setgroups_success
$KCOVTRACE audit/process-control setgroups_failure
$KCOVTRACE audit/process-control setpgrp_success
$KCOVTRACE audit/process-control setpgrp_failure
$KCOVTRACE audit/process-control setsid_success
$KCOVTRACE audit/process-control setsid_failure
$KCOVTRACE audit/process-control setrlimit_success
$KCOVTRACE audit/process-control setrlimit_failure
$KCOVTRACE audit/process-control mlock_success
$KCOVTRACE audit/process-control mlock_failure
$KCOVTRACE audit/process-control munlock_success
$KCOVTRACE audit/process-control munlock_failure
$KCOVTRACE audit/process-control minherit_success
$KCOVTRACE audit/process-control minherit_failure
$KCOVTRACE audit/process-control setlogin_success
$KCOVTRACE audit/process-control setlogin_failure
$KCOVTRACE audit/process-control rtprio_success
$KCOVTRACE audit/process-control rtprio_failure
$KCOVTRACE audit/process-control profil_success
$KCOVTRACE audit/process-control profil_failure
$KCOVTRACE audit/process-control ptrace_success
$KCOVTRACE audit/process-control ptrace_failure
$KCOVTRACE audit/process-control ktrace_success
$KCOVTRACE audit/process-control ktrace_failure
$KCOVTRACE audit/process-control procctl_success
$KCOVTRACE audit/process-control procctl_failure
$KCOVTRACE audit/process-control cap_enter_success
$KCOVTRACE audit/process-control cap_getmode_success
$KCOVTRACE audit/process-control cap_getmode_failure

$KCOVTRACE auditpipe/auditpipe_test auditpipe_get_qlen
$KCOVTRACE auditpipe/auditpipe_test auditpipe_get_qlimit
$KCOVTRACE auditpipe/auditpipe_test auditpipe_set_qlimit
$KCOVTRACE auditpipe/auditpipe_test auditpipe_get_qlimit_min
$KCOVTRACE auditpipe/auditpipe_test auditpipe_get_qlimit_max
$KCOVTRACE auditpipe/auditpipe_test auditpipe_get_maxauditdata

$KCOVTRACE capsicum/bindat_connectat bindat_connectat_1
$KCOVTRACE capsicum/bindat_connectat bindat_connectat_2
$KCOVTRACE capsicum/bindat_connectat bindat_connectat_3

$KCOVTRACE capsicum/ioctls_test cap_ioctls__listen_copy

kyua test capsicum/functional

$KCOVTRACE devrandom/uint128_test uint128_inc
$KCOVTRACE devrandom/uint128_test uint128_add64
$KCOVTRACE devrandom/uint128_test uint128_chacha_ctr

$KCOVTRACE fifo/fifo_create
$KCOVTRACE fifo/fifo_io
$KCOVTRACE fifo/fifo_misc
$KCOVTRACE fifo/fifo_open
$KCOVTRACE fifo/fifo_kqueue fifo_kqueue__writes
$KCOVTRACE fifo/fifo_kqueue fifo_kqueue__connecting_reader
$KCOVTRACE fifo/fifo_kqueue fifo_kqueue__reads
$KCOVTRACE fifo/fifo_kqueue fifo_kqueue__read_eof_wakeups
$KCOVTRACE fifo/fifo_kqueue fifo_kqueue__read_eof_state_when_reconnecting

$KCOVTRACE file/closefrom_test
$KCOVTRACE file/dup_test
$KCOVTRACE file/fcntlflags_test
$KCOVTRACE file/ftruncate_test
$KCOVTRACE file/newfileops_on_fork_test
file/flock_test

for file in fs/fusefs/* ; do $KCOVTRACE ./$file ; done 

$KCOVTRACE fs/tmpfs/h_tools

$KCOVTRACE kern/subr_unit_test
$KCOVTRACE kern/basic_signal signal_test
$KCOVTRACE kern/basic_signal trap_signal_test
$KCOVTRACE kern/fdgrowtable_test free_oldtables
$KCOVTRACE kern/fdgrowtable_test oldtables_shared_via_threads
$KCOVTRACE kern/fdgrowtable_test oldtables_shared_via_process
$KCOVTRACE kern/kern_copyin kern_copyin
$KCOVTRACE kern/kern_descrip_test dup2__simple
$KCOVTRACE kern/kern_descrip_test dup2__ebadf_when_2nd_arg_out_of_range
$KCOVTRACE kern/kern_descrip_test kern_maxfiles__increase
$KCOVTRACE kern/kill_zombie kill_zombie
$KCOVTRACE kern/ktls_test ktls_transmit_aes128_cbc_1_0_sha1_short
$KCOVTRACE kern/libkern_crc32 crc32c_basic_correctness
$KCOVTRACE kern/libkern_crc32 crc32c_alignment
$KCOVTRACE kern/libkern_crc32 crc32c_trailing_bytes
$KCOVTRACE kern/lockf_test randlock
$KCOVTRACE kern/lockf_test deadlock
$KCOVTRACE kern/mqueue_test mqueue
$KCOVTRACE kern/pdeathsig arg_validation
$KCOVTRACE kern/pdeathsig fork_no_inherit
$KCOVTRACE kern/pdeathsig exec_inherit
$KCOVTRACE kern/pdeathsig signal_delivered
$KCOVTRACE kern/pdeathsig signal_delivered_ptrace
$KCOVTRACE kern/ptrace_test ptrace__parent_wait_after_trace_me
$KCOVTRACE kern/ptrace_test ptrace__parent_wait_after_attach
$KCOVTRACE kern/ptrace_test ptrace__parent_sees_exit_after_child_debugger
$KCOVTRACE kern/ptrace_test ptrace__parent_sees_exit_after_unrelated_debugger
$KCOVTRACE kern/ptrace_test ptrace__parent_exits_before_child
$KCOVTRACE kern/ptrace_test ptrace__follow_fork_both_attached
$KCOVTRACE kern/ptrace_test ptrace__follow_fork_child_detached
$KCOVTRACE kern/ptrace_test ptrace__follow_fork_parent_detached
$KCOVTRACE kern/ptrace_test ptrace__follow_fork_both_attached_unrelated_debugger
$KCOVTRACE kern/ptrace_test ptrace__follow_fork_child_detached_unrelated_debugger
$KCOVTRACE kern/ptrace_test ptrace__follow_fork_parent_detached_unrelated_debugger
$KCOVTRACE kern/ptrace_test ptrace__getppid
$KCOVTRACE kern/ptrace_test ptrace__new_child_pl_syscall_code_fork
$KCOVTRACE kern/ptrace_test ptrace__new_child_pl_syscall_code_vfork
$KCOVTRACE kern/ptrace_test ptrace__new_child_pl_syscall_code_thread
$KCOVTRACE kern/ptrace_test ptrace__lwp_events
$KCOVTRACE kern/ptrace_test ptrace__lwp_events_exec
$KCOVTRACE kern/ptrace_test ptrace__siginfo
$KCOVTRACE kern/ptrace_test ptrace__ptrace_exec_disable
$KCOVTRACE kern/ptrace_test ptrace__ptrace_exec_enable
$KCOVTRACE kern/ptrace_test ptrace__event_mask
$KCOVTRACE kern/ptrace_test ptrace__ptrace_vfork
$KCOVTRACE kern/ptrace_test ptrace__ptrace_vfork_follow
$KCOVTRACE kern/ptrace_test ptrace__PT_KILL_breakpoint
$KCOVTRACE kern/ptrace_test ptrace__PT_KILL_system_call
$KCOVTRACE kern/ptrace_test ptrace__PT_KILL_threads
$KCOVTRACE kern/ptrace_test ptrace__PT_KILL_competing_signal
$KCOVTRACE kern/ptrace_test ptrace__PT_KILL_competing_stop
$KCOVTRACE kern/ptrace_test ptrace__PT_KILL_with_signal_full_sigqueue
$KCOVTRACE kern/ptrace_test ptrace__PT_CONTINUE_with_signal_system_call_entry
$KCOVTRACE kern/ptrace_test ptrace__PT_CONTINUE_with_signal_system_call_entry_and_exit
$KCOVTRACE kern/ptrace_test ptrace__PT_CONTINUE_with_signal_full_sigqueue
$KCOVTRACE kern/ptrace_test ptrace__PT_CONTINUE_with_signal_masked_full_sigqueue
$KCOVTRACE kern/ptrace_test ptrace__PT_CONTINUE_change_sig
$KCOVTRACE kern/ptrace_test ptrace__PT_CONTINUE_with_sigtrap_system_call_entry
$KCOVTRACE kern/ptrace_test ptrace__PT_CONTINUE_with_signal_mix
$KCOVTRACE kern/ptrace_test ptrace__PT_CONTINUE_with_signal_kqueue
$KCOVTRACE kern/ptrace_test ptrace__killed_with_sigmask
$KCOVTRACE kern/ptrace_test ptrace__PT_CONTINUE_with_sigmask
$KCOVTRACE kern/ptrace_test ptrace__PT_CONTINUE_with_signal_thread_sigmask
$KCOVTRACE kern/ptrace_test ptrace__parent_terminate_with_pending_sigstop1
$KCOVTRACE kern/ptrace_test ptrace__parent_terminate_with_pending_sigstop2
$KCOVTRACE kern/ptrace_test ptrace__event_mask_sigkill_discard
$KCOVTRACE kern/ptrace_test ptrace__PT_ATTACH_with_SBDRY_thread
$KCOVTRACE kern/ptrace_test ptrace__PT_STEP_with_signal
$KCOVTRACE kern/ptrace_test ptrace__breakpoint_siginfo
$KCOVTRACE kern/ptrace_test ptrace__step_siginfo
$KCOVTRACE kern/ptrace_test ptrace__PT_CONTINUE_different_thread
$KCOVTRACE kern/ptrace_test ptrace__PT_LWPINFO_stale_siginfo
$KCOVTRACE kern/ptrace_test ptrace__syscall_args
$KCOVTRACE kern/ptrace_test ptrace__proc_reparent
$KCOVTRACE kern/ptrace_test ptrace__procdesc_wait_child
$KCOVTRACE kern/ptrace_test ptrace__procdesc_reparent_wait_child
$KCOVTRACE kern/reaper reaper_wait_child_first
$KCOVTRACE kern/reaper reaper_wait_grandchild_first
$KCOVTRACE kern/reaper reaper_sigchld_child_first
$KCOVTRACE kern/reaper reaper_sigchld_grandchild_first
$KCOVTRACE kern/reaper reaper_status
$KCOVTRACE kern/reaper reaper_getpids
$KCOVTRACE kern/reaper reaper_kill_badsig
$KCOVTRACE kern/reaper reaper_kill_sigzero
$KCOVTRACE kern/reaper reaper_kill_empty
$KCOVTRACE kern/reaper reaper_kill_normal
$KCOVTRACE kern/reaper reaper_kill_subtree
$KCOVTRACE kern/reaper reaper_pdfork
$KCOVTRACE kern/sigaltstack ss_onstack
$KCOVTRACE kern/sys_getrandom getrandom_count
$KCOVTRACE kern/sys_getrandom getrandom_fault
$KCOVTRACE kern/sys_getrandom getrandom_randomness
$KCOVTRACE kern/sysctl_kern_proc sysctl_kern_proc_cwd
$KCOVTRACE kern/sysctl_kern_proc sysctl_kern_proc_filedesc
$KCOVTRACE kern/sysv_test msg
#$KCOVTRACE kern/sysv_test sem
$KCOVTRACE kern/sysv_test shm
$KCOVTRACE kern/sysv_test shm_remap
$KCOVTRACE kern/unix_passfd_test simple_send_fd
$KCOVTRACE kern/unix_passfd_test simple_send_fd_msg_cmsg_cloexec
$KCOVTRACE kern/unix_passfd_test send_and_close
$KCOVTRACE kern/unix_passfd_test send_and_cancel
$KCOVTRACE kern/unix_passfd_test two_files
$KCOVTRACE kern/unix_passfd_test bundle
$KCOVTRACE kern/unix_passfd_test bundle_cancel
$KCOVTRACE kern/unix_passfd_test devfs_orphan
$KCOVTRACE kern/unix_passfd_test rights_creds_payload
$KCOVTRACE kern/unix_passfd_test truncated_rights
$KCOVTRACE kern/unix_passfd_test copyout_rights_error
$KCOVTRACE kern/unix_passfd_test empty_rights_message
$KCOVTRACE kern/unix_seqpacket_test create_socket
$KCOVTRACE kern/unix_seqpacket_test create_socketpair
$KCOVTRACE kern/unix_seqpacket_test listen_unbound
$KCOVTRACE kern/unix_seqpacket_test bind
$KCOVTRACE kern/unix_seqpacket_test listen_bound
$KCOVTRACE kern/unix_seqpacket_test connect
$KCOVTRACE kern/unix_seqpacket_test accept
$KCOVTRACE kern/unix_seqpacket_test fcntl_nonblock
$KCOVTRACE kern/unix_seqpacket_test resize_buffers
$KCOVTRACE kern/unix_seqpacket_test resize_connected_buffers
$KCOVTRACE kern/unix_seqpacket_test send_recv
$KCOVTRACE kern/unix_seqpacket_test send_recv_nonblocking
$KCOVTRACE kern/unix_seqpacket_test send_recv_with_connect
$KCOVTRACE kern/unix_seqpacket_test sendto_recvfrom
$KCOVTRACE kern/unix_seqpacket_test shutdown_send
$KCOVTRACE kern/unix_seqpacket_test shutdown_send_sigpipe
$KCOVTRACE kern/unix_seqpacket_test emsgsize
$KCOVTRACE kern/unix_seqpacket_test emsgsize_nonblocking
$KCOVTRACE kern/unix_seqpacket_test eagain_8k_8k
$KCOVTRACE kern/unix_seqpacket_test eagain_8k_128k
$KCOVTRACE kern/unix_seqpacket_test eagain_128k_8k
$KCOVTRACE kern/unix_seqpacket_test eagain_128k_128k
$KCOVTRACE kern/unix_seqpacket_test sendrecv_8k
$KCOVTRACE kern/unix_seqpacket_test sendrecv_16k
$KCOVTRACE kern/unix_seqpacket_test sendrecv_32k
$KCOVTRACE kern/unix_seqpacket_test sendrecv_64k
$KCOVTRACE kern/unix_seqpacket_test sendrecv_128k
$KCOVTRACE kern/unix_seqpacket_test sendrecv_8k_nonblocking
$KCOVTRACE kern/unix_seqpacket_test sendrecv_16k_nonblocking
$KCOVTRACE kern/unix_seqpacket_test sendrecv_32k_nonblocking
$KCOVTRACE kern/unix_seqpacket_test sendrecv_64k_nonblocking
$KCOVTRACE kern/unix_seqpacket_test sendrecv_128k_nonblocking
$KCOVTRACE kern/unix_seqpacket_test rcvbuf_oversized
$KCOVTRACE kern/unix_seqpacket_test pipe_simulator_8k_8k
$KCOVTRACE kern/unix_seqpacket_test pipe_simulator_8k_128k
$KCOVTRACE kern/unix_seqpacket_test pipe_simulator_128k_8k
$KCOVTRACE kern/unix_seqpacket_test pipe_simulator_128k_128k
$KCOVTRACE kern/unix_seqpacket_test pipe_8k_8k
$KCOVTRACE kern/unix_seqpacket_test pipe_8k_128k
$KCOVTRACE kern/unix_seqpacket_test pipe_128k_8k
$KCOVTRACE kern/unix_seqpacket_test pipe_128k_128k
$KCOVTRACE kern/unix_socketpair_test getpeereid
$KCOVTRACE kern/waitpid_nohang waitpid_nohang
kyua test kern/sendfile_test

$KCOVTRACE kern/acct/acct_test encode_long
$KCOVTRACE kern/acct/acct_test encode_tv_zero
$KCOVTRACE kern/acct/acct_test encode_tv_only_sec
$KCOVTRACE kern/acct/acct_test encode_tv_only_usec
$KCOVTRACE kern/acct/acct_test encode_tv_many_usec
$KCOVTRACE kern/acct/acct_test encode_tv_usec_overflow
$KCOVTRACE kern/acct/acct_test encode_tv_upper_limit
$KCOVTRACE kern/acct/acct_test encode_tv_random_million

kyua test kern/execve/execve_test

$KCOVTRACE kern/pipe/big_pipe_test
$KCOVTRACE kern/pipe/pipe_fstat_bug_test
$KCOVTRACE kern/pipe/pipe_ino_test
$KCOVTRACE kern/pipe/pipe_overcommit1_test
$KCOVTRACE kern/pipe/pipe_overcommit2_test
$KCOVTRACE kern/pipe/pipe_reverse_test
$KCOVTRACE kern/pipe/pipe_reverse2_test
$KCOVTRACE kern/pipe/pipe_wraparound_test
$KCOVTRACE kern/pipe/pipe_kqueue_test pipe_kqueue__write_end
$KCOVTRACE kern/pipe/pipe_kqueue_test pipe_kqueue__closed_read_end
$KCOVTRACE kern/pipe/pipe_kqueue_test pipe_kqueue__closed_read_end_register_before_close
$KCOVTRACE kern/pipe/pipe_kqueue_test pipe_kqueue__closed_write_end
$KCOVTRACE kern/pipe/pipe_kqueue_test pipe_kqueue__closed_write_end_register_before_close

$KCOVTRACE kqueue/proc1_test proc1
$KCOVTRACE kqueue/proc3_test proc3
$KCOVTRACE kqueue/sig_test sig
$KCOVTRACE kqueue/vnode_test dir_no_note_link_create_file_in
$KCOVTRACE kqueue/vnode_test dir_no_note_link_delete_file_in
$KCOVTRACE kqueue/vnode_test dir_no_note_link_mv_dir_within
$KCOVTRACE kqueue/vnode_test dir_no_note_link_mv_file_within
$KCOVTRACE kqueue/vnode_test dir_note_link_create_dir_in
$KCOVTRACE kqueue/vnode_test dir_note_link_delete_dir_in
$KCOVTRACE kqueue/vnode_test dir_note_link_mv_dir_in
$KCOVTRACE kqueue/vnode_test dir_note_link_mv_dir_out
$KCOVTRACE kqueue/vnode_test dir_note_write_create_dir_in
$KCOVTRACE kqueue/vnode_test dir_note_write_create_file_in
$KCOVTRACE kqueue/vnode_test dir_note_write_delete_dir_in
$KCOVTRACE kqueue/vnode_test dir_note_write_delete_file_in
$KCOVTRACE kqueue/vnode_test dir_note_write_mv_dir_in
$KCOVTRACE kqueue/vnode_test dir_note_write_mv_dir_out
$KCOVTRACE kqueue/vnode_test dir_note_write_mv_dir_within
$KCOVTRACE kqueue/vnode_test dir_note_write_mv_file_in
$KCOVTRACE kqueue/vnode_test dir_note_write_mv_file_out
$KCOVTRACE kqueue/vnode_test dir_note_write_mv_file_within
kqueue/libkqueue/kqueue_test

kyua test mqueue/mqueue_test

kyua test net/if_bridge_test
kyua test net/if_clone_test
$KCOVTRACE net/if_epair params
kyua test net/if_gif
kyua test net/if_lagg_test
kyua test net/if_stf
kyua test net/if_tun_test
kyua test net/if_vlan
$KCOVTRACE net/routing/test_rtsock_lladdr rtm_add_v6_ll_lle_success
$KCOVTRACE net/routing/test_rtsock_lladdr rtm_add_v6_gu_lle_success
$KCOVTRACE net/routing/test_rtsock_lladdr rtm_add_v4_gu_lle_success
$KCOVTRACE net/routing/test_rtsock_lladdr rtm_del_v6_ll_lle_success
$KCOVTRACE net/routing/test_rtsock_lladdr rtm_del_v6_gu_lle_success
$KCOVTRACE net/routing/test_rtsock_lladdr rtm_del_v4_gu_lle_success

$KCOVTRACE netgraph/basic send_recv
$KCOVTRACE netgraph/basic node
$KCOVTRACE netgraph/basic message
$KCOVTRACE netgraph/basic same_name
$KCOVTRACE netgraph/basic queuelimit
$KCOVTRACE netgraph/bridge basic
$KCOVTRACE netgraph/bridge loop
$KCOVTRACE netgraph/bridge persistence
$KCOVTRACE netgraph/bridge many_unicasts
$KCOVTRACE netgraph/bridge many_broadcasts
$KCOVTRACE netgraph/bridge uplink_private
$KCOVTRACE netgraph/bridge uplink_classic
$KCOVTRACE netgraph/hub basic
$KCOVTRACE netgraph/hub loop
$KCOVTRACE netgraph/hub persistence
$KCOVTRACE netgraph/hub many_hooks
$KCOVTRACE netgraph/vlan_rotate basic
$KCOVTRACE netgraph/vlan_rotate ethertype
$KCOVTRACE netgraph/vlan_rotate reverse
$KCOVTRACE netgraph/vlan_rotate typeether
$KCOVTRACE netgraph/vlan_rotate minmax
kyua test netgraph/ng_macfilter_test

$KCOVTRACE netinet/ip_reass_test ip_reass__multiple_last_fragments
$KCOVTRACE netinet/ip_reass_test ip_reass__zero_length_fragment
$KCOVTRACE netinet/ip_reass_test ip_reass__large_fragment
$KCOVTRACE netinet/so_reuseport_lb_test basic_ipv4
$KCOVTRACE netinet/so_reuseport_lb_test basic_ipv6
$KCOVTRACE netinet/socket_afinet socket_afinet
$KCOVTRACE netinet/socket_afinet socket_afinet_bind_zero
$KCOVTRACE netinet/socket_afinet socket_afinet_bind_ok
$KCOVTRACE netinet/tcp_connect_port_test basic_ipv4
$KCOVTRACE netinet/tcp_connect_port_test basic_ipv6
kyua test netinet/arp
kyua test netinet/carp
kyua test netinet/divert
kyua test netinet/fibs
kyua test netinet/forward
kyua test netinet/lpm
kyua test netinet/output
kyua test netinet/redirect
$KCOVTRACE netinet/libalias/1_instance 2_destroynull
$KCOVTRACE netinet/libalias/1_instance 1_singleinit
$KCOVTRACE netinet/libalias/1_instance 3_multiinit
$KCOVTRACE netinet/libalias/1_instance 4_multiinstance
$KCOVTRACE netinet/libalias/2_natout 1_simplemasq
$KCOVTRACE netinet/libalias/2_natout 2_unregistered
$KCOVTRACE netinet/libalias/2_natout 3_cgn
$KCOVTRACE netinet/libalias/2_natout 4_udp
$KCOVTRACE netinet/libalias/2_natout 5_sameport
$KCOVTRACE netinet/libalias/2_natout 6_cleartable
$KCOVTRACE netinet/libalias/2_natout 7_stress
$KCOVTRACE netinet/libalias/2_natout 8_portrange
$KCOVTRACE netinet/libalias/3_natin 1_portforward
$KCOVTRACE netinet/libalias/3_natin 2_portoverlap
$KCOVTRACE netinet/libalias/3_natin 3_redirectany
$KCOVTRACE netinet/libalias/3_natin 4_redirectaddr
$KCOVTRACE netinet/libalias/3_natin 5_lsnat
$KCOVTRACE netinet/libalias/3_natin 6_oneshot

kyua test netinet6/divert
kyua test netinet6/exthdr
kyua test netinet6/fibs6
kyua test netinet6/forward6
kyua test netinet6/lpm6
kyua test netinet6/mld
kyua test netinet6/ndp
kyua test netinet6/output6
kyua test netinet6/redirect
kyua test netinet6/scapyi386
kyua test netinet6/frag6/frag6_02
kyua test netinet6/frag6/frag6_03
kyua test netinet6/frag6/frag6_04
kyua test netinet6/frag6/frag6_05
kyua test netinet6/frag6/frag6_06
kyua test netinet6/frag6/frag6_07
kyua test netinet6/frag6/frag6_08
kyua test netinet6/frag6/frag6_09
kyua test netinet6/frag6/frag6_10
kyua test netinet6/frag6/frag6_11
kyua test netinet6/frag6/frag6_12
kyua test netinet6/frag6/frag6_13
kyua test netinet6/frag6/frag6_14
kyua test netinet6/frag6/frag6_15
kyua test netinet6/frag6/frag6_16
kyua test netinet6/frag6/frag6_17
kyua test netinet6/frag6/frag6_18
kyua test netinet6/frag6/frag6_19
kyua test netinet6/frag6/frag6_20

kyua test netipsec/tunnel/aes_cbc_128_hmac_sha1
kyua test netipsec/tunnel/aes_cbc_256_hmac_sha2_256
kyua test netipsec/tunnel/aes_gcm_128
kyua test netipsec/tunnel/aes_gcm_256
kyua test netipsec/tunnel/aesni_aes_cbc_128_hmac_sha1
kyua test netipsec/tunnel/aesni_aes_cbc_256_hmac_sha2_256
kyua test netipsec/tunnel/aesni_aes_gcm_128
kyua test netipsec/tunnel/aesni_aes_gcm_256
kyua test netipsec/tunnel/empty

kyua test netpfil/pf/altq
kyua test netpfil/pf/anchor
kyua test netpfil/pf/checksum
kyua test netpfil/pf/dup
kyua test netpfil/pf/forward
kyua test netpfil/pf/fragmentation
kyua test netpfil/pf/get_state
kyua test netpfil/pf/icmp
kyua test netpfil/pf/killstate
kyua test netpfil/pf/macro
kyua test netpfil/pf/map_e
kyua test netpfil/pf/names
kyua test netpfil/pf/nat
kyua test netpfil/pf/pass_block
kyua test netpfil/pf/pfsync
kyua test netpfil/pf/proxy
kyua test netpfil/pf/rdr
kyua test netpfil/pf/ridentifier
kyua test netpfil/pf/route_to
kyua test netpfil/pf/rules_counter
kyua test netpfil/pf/set_skip
kyua test netpfil/pf/set_tos
kyua test netpfil/pf/src_track
kyua test netpfil/pf/syncookie
kyua test netpfil/pf/synproxy
kyua test netpfil/pf/table
kyua test netpfil/pf/tos
$KCOVTRACE netpfil/pf/ioctl/validation addtables
$KCOVTRACE netpfil/pf/ioctl/validation deltables
$KCOVTRACE netpfil/pf/ioctl/validation gettables
$KCOVTRACE netpfil/pf/ioctl/validation getastats
$KCOVTRACE netpfil/pf/ioctl/validation gettstats
$KCOVTRACE netpfil/pf/ioctl/validation clrtstats
$KCOVTRACE netpfil/pf/ioctl/validation settflags
$KCOVTRACE netpfil/pf/ioctl/validation addaddrs
$KCOVTRACE netpfil/pf/ioctl/validation deladdrs
$KCOVTRACE netpfil/pf/ioctl/validation setaddrs
$KCOVTRACE netpfil/pf/ioctl/validation getaddrs
$KCOVTRACE netpfil/pf/ioctl/validation clrastats
$KCOVTRACE netpfil/pf/ioctl/validation tstaddrs
$KCOVTRACE netpfil/pf/ioctl/validation inadefine
$KCOVTRACE netpfil/pf/ioctl/validation igetifaces
$KCOVTRACE netpfil/pf/ioctl/validation cxbegin
$KCOVTRACE netpfil/pf/ioctl/validation cxrollback
$KCOVTRACE netpfil/pf/ioctl/validation commit
$KCOVTRACE netpfil/pf/ioctl/validation getsrcnodes
$KCOVTRACE netpfil/pf/ioctl/validation tag
$KCOVTRACE netpfil/pf/ioctl/validation rpool_mtx
$KCOVTRACE netpfil/pf/ioctl/validation rpool_mtx2

kyua test netpfil/common/dummynet
kyua test netpfil/common/forward
kyua test netpfil/common/fragments
kyua test netpfil/common/nat
kyua test netpfil/common/pass_block
kyua test netpfil/common/tos

$KCOVTRACE posixshm/memfd_test basic
$KCOVTRACE posixshm/memfd_test cloexec
$KCOVTRACE posixshm/memfd_test disallowed_sealing
$KCOVTRACE posixshm/memfd_test write_seal
$KCOVTRACE posixshm/memfd_test mmap_write_seal
$KCOVTRACE posixshm/memfd_test truncate_seals
$KCOVTRACE posixshm/memfd_test get_seals
$KCOVTRACE posixshm/memfd_test dup_seals
$KCOVTRACE posixshm/memfd_test immutable_seals
$KCOVTRACE posixshm/posixshm_test remap_object
$KCOVTRACE posixshm/posixshm_test rename_from_anon
$KCOVTRACE posixshm/posixshm_test rename_bad_path_pointer
$KCOVTRACE posixshm/posixshm_test rename_from_nonexisting
$KCOVTRACE posixshm/posixshm_test rename_to_anon
$KCOVTRACE posixshm/posixshm_test rename_to_replace
$KCOVTRACE posixshm/posixshm_test rename_to_noreplace
$KCOVTRACE posixshm/posixshm_test rename_to_exchange
$KCOVTRACE posixshm/posixshm_test rename_to_exchange_nonexisting
$KCOVTRACE posixshm/posixshm_test rename_to_self
$KCOVTRACE posixshm/posixshm_test rename_bad_flag
$KCOVTRACE posixshm/posixshm_test reopen_object
$KCOVTRACE posixshm/posixshm_test readonly_mmap_write
$KCOVTRACE posixshm/posixshm_test open_after_link
$KCOVTRACE posixshm/posixshm_test open_invalid_path
$KCOVTRACE posixshm/posixshm_test open_write_only
$KCOVTRACE posixshm/posixshm_test open_extra_flags
$KCOVTRACE posixshm/posixshm_test open_anon
$KCOVTRACE posixshm/posixshm_test open_anon_readonly
$KCOVTRACE posixshm/posixshm_test open_bad_path_pointer
$KCOVTRACE posixshm/posixshm_test open_path_too_long
$KCOVTRACE posixshm/posixshm_test open_nonexisting_object
$KCOVTRACE posixshm/posixshm_test open_create_existing_object
$KCOVTRACE posixshm/posixshm_test shm_functionality_across_fork
$KCOVTRACE posixshm/posixshm_test trunc_resets_object
$KCOVTRACE posixshm/posixshm_test unlink_bad_path_pointer
$KCOVTRACE posixshm/posixshm_test unlink_path_too_long
$KCOVTRACE posixshm/posixshm_test object_resize
$KCOVTRACE posixshm/posixshm_test cloexec
$KCOVTRACE posixshm/posixshm_test mode
$KCOVTRACE posixshm/posixshm_test fallocate
$KCOVTRACE posixshm/posixshm_test largepage_basic
$KCOVTRACE posixshm/posixshm_test largepage_config
$KCOVTRACE posixshm/posixshm_test largepage_mmap
$KCOVTRACE posixshm/posixshm_test largepage_munmap
$KCOVTRACE posixshm/posixshm_test largepage_madvise
$KCOVTRACE posixshm/posixshm_test largepage_mlock
$KCOVTRACE posixshm/posixshm_test largepage_msync
$KCOVTRACE posixshm/posixshm_test largepage_mprotect
$KCOVTRACE posixshm/posixshm_test largepage_minherit
$KCOVTRACE posixshm/posixshm_test largepage_pipe
$KCOVTRACE posixshm/posixshm_test largepage_reopen

$KCOVTRACE sys/arb_test arb_test
$KCOVTRACE sys/bitset_test bit_foreach
$KCOVTRACE sys/bitstring_test bitstr_in_struct
$KCOVTRACE sys/bitstring_test bitstr_size
$KCOVTRACE sys/bitstring_test bit_ffc_area
$KCOVTRACE sys/bitstring_test bit_ffs_area
$KCOVTRACE sys/bitstring_test bit_set
$KCOVTRACE sys/bitstring_test bit_clear
$KCOVTRACE sys/bitstring_test bit_ffs
$KCOVTRACE sys/bitstring_test bit_ffc
$KCOVTRACE sys/bitstring_test bit_ffs_at
$KCOVTRACE sys/bitstring_test bit_ffc_at
$KCOVTRACE sys/bitstring_test bit_nclear
$KCOVTRACE sys/bitstring_test bit_nset
$KCOVTRACE sys/bitstring_test bit_count
$KCOVTRACE sys/bitstring_test bit_ffs_area_no_match
$KCOVTRACE sys/bitstring_test bit_ffc_area_no_match
$KCOVTRACE sys/bitstring_test bit_foreach
$KCOVTRACE sys/bitstring_test bit_foreach_at
$KCOVTRACE sys/bitstring_test bit_foreach_unset
$KCOVTRACE sys/bitstring_test bit_foreach_unset_at
$KCOVTRACE sys/qmath_test basic_s8q
$KCOVTRACE sys/qmath_test basic_s16q
$KCOVTRACE sys/qmath_test basic_s32q
$KCOVTRACE sys/qmath_test basic_s64q
$KCOVTRACE sys/qmath_test basic_u8q
$KCOVTRACE sys/qmath_test basic_u16q
$KCOVTRACE sys/qmath_test basic_u32q
$KCOVTRACE sys/qmath_test basic_u64q
$KCOVTRACE sys/qmath_test qmulq_s64q
$KCOVTRACE sys/qmath_test qdivq_s64q
$KCOVTRACE sys/qmath_test qaddq_s64q
$KCOVTRACE sys/qmath_test qsubq_s64q
$KCOVTRACE sys/qmath_test qfraci_s64q
$KCOVTRACE sys/qmath_test qmuli_s64q
$KCOVTRACE sys/qmath_test qaddi_s64q
$KCOVTRACE sys/qmath_test qsubi_s64q
$KCOVTRACE sys/qmath_test circle_u64q
$KCOVTRACE sys/rb_test rb_test
$KCOVTRACE sys/splay_test splay_test

$KCOVTRACE vfs/lookup_cap_dotdot openat__basic_positive
$KCOVTRACE vfs/lookup_cap_dotdot openat__basic_negative
$KCOVTRACE vfs/lookup_cap_dotdot capmode__negative
$KCOVTRACE vfs/lookup_cap_dotdot lookup_cap_dotdot__basic
$KCOVTRACE vfs/lookup_cap_dotdot lookup_cap_dotdot__advanced
$KCOVTRACE vfs/lookup_cap_dotdot lookup_cap_dotdot__negative

$KCOVTRACE vm/mlock_test mlock__copy_on_write_anon
$KCOVTRACE vm/mlock_test mlock__copy_on_write_vnode
$KCOVTRACE vm/mlock_test mlock__truncate_and_resize
$KCOVTRACE vm/mlock_test mlock__truncate_and_unlock
$KCOVTRACE vm/mmap_test mmap__map_at_zero
$KCOVTRACE vm/mmap_test mmap__bad_arguments
$KCOVTRACE vm/mmap_test mmap__dev_zero_private
$KCOVTRACE vm/mmap_test mmap__dev_zero_shared
$KCOVTRACE vm/mmap_test mmap__write_only
$KCOVTRACE vm/page_fault_signal page_fault_signal__segv_maperr_1
$KCOVTRACE vm/page_fault_signal page_fault_signal__segv_accerr_1
$KCOVTRACE vm/page_fault_signal page_fault_signal__segv_accerr_2
$KCOVTRACE vm/page_fault_signal page_fault_signal__bus_objerr_1
$KCOVTRACE vm/page_fault_signal page_fault_signal__bus_objerr_2
$KCOVTRACE vm/shared_shadow_inval_test shared_shadow_inval__nocollapse_noblockxfer_nofullmod
$KCOVTRACE vm/shared_shadow_inval_test shared_shadow_inval__nocollapse_noblockxfer_fullmod
$KCOVTRACE vm/shared_shadow_inval_test shared_shadow_inval__nocollapse_blockxfer_nofullmod
$KCOVTRACE vm/shared_shadow_inval_test shared_shadow_inval__nocollapse_blockxfer_fullmod
$KCOVTRACE vm/shared_shadow_inval_test shared_shadow_inval__collapse_noblockxfer_nofullmod
$KCOVTRACE vm/shared_shadow_inval_test shared_shadow_inval__collapse_noblockxfer_fullmod
$KCOVTRACE vm/shared_shadow_inval_test shared_shadow_inval__collapse_blockxfer_nofullmod
$KCOVTRACE vm/shared_shadow_inval_test shared_shadow_inval__collapse_blockxfer_fullmod

kyua test vmm/vmm_cred_jail


cd $WORKDIR

if ! [ -f "cloc" ] ; then
    echo "Executing cloc --include-lang="C,C/C++ Header" --csv --report-file=cloc /usr/src/sys"
    cloc --include-lang="C,C/C++ Header" --csv --report-file=cloc /usr/src/sys
fi

#for file in /usr/lib/debug/boot/kernel/* ; do nm -elP $file ; done > nmlines
if ! [ -f "nmlines" ] ; then
    echo "Executing nm -elP /usr/lib/debug/boot/kernel/kernel.debug"
    nm -elP /usr/lib/debug/boot/kernel/kernel.debug > nmlines
fi

#addr2line -fp -e /usr/lib/debug/boot/kernel/kernel.debug < rawfile > trace

echo "Executing python cov.py"
python cov.py

rm -r cov_out
genhtml coverage --output-directory cov_out

