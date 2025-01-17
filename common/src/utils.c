#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include <sys/syslog.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <dirent.h>
#include <signal.h>

#include "common.h"
#include "utils.h"

static FILE *console_file = NULL;
void print_log(const char *fmt, ...) {
    va_list args = NULL;
    va_start(args, fmt);

#ifdef UNTETHER
    if (console_file == NULL) {
        if ((console_file = fopen("/dev/console", "a")) == NULL) return;
    }
    vfprintf(console_file, fmt, args);
    va_end(args);
    fflush(console_file);
#else  
    vsyslog(LOG_CRIT, fmt, args);
    va_end(args);
#endif
    usleep(1000);
}

pid_t pid_for_proc_name(const char *process_name) {
    int count = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0) + 100;
    if (count <= 0) return -1;

    pid_t *pids = calloc(1, sizeof(pid_t) * count);
    count = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pid_t) * count);
    if (count <= 0) {
        free(pids);
        return 1;
    }
    
    char *name = calloc(1, PROC_PIDPATHINFO_MAXSIZE);
    for (int i = 0; i < count; i++) {
        bzero(name, PROC_PIDPATHINFO_MAXSIZE);
        pid_t pid = pids[i];

        if (proc_name(pid, name, sizeof(name)) <= 0) continue;
        if (strncmp((const char *)name, process_name, PROC_PIDPATHINFO_MAXSIZE) == 0) {
            free(name);
            free(pids);
            return pid;
        }
    }

    free(name);
    free(pids);
    return -1;
}

char *get_hw_model(void) {
    size_t size = 0;
    sysctlbyname("hw.model", NULL, &size, NULL, 0);
    char *model = calloc(1, size+1);
    sysctlbyname("hw.model", model, &size, NULL, 0);
    return model;
}

void killall(const char *name) {
    pid_t pid = -1;
    while (1) {
        pid_t _pid = pid_for_proc_name(name);
        if (_pid == -1 || _pid == pid) break;
        pid = _pid;
        kill(_pid, SIGKILL);
        usleep(1000);
    }
}

int create_file(const char *path, mode_t mode, uid_t uid, gid_t gid) {
    if (access(path, F_OK) == 0) {
        if (chmod(path, mode) != 0) return -1;
        if (chown(path, uid, gid) != 0) return -1;
        sync();
        return 0;
    }

    int fd = open(path, O_RDWR|O_CREAT);
    if (fd == -1) return -1;
    close(fd);
    sync();

    if (chmod(path, mode) != 0) return -1;
    if (chown(path, uid, gid) != 0) return -1;
    sync();
    return 0;
}

int set_file_permissions(const char *path, mode_t mode, uid_t uid, gid_t gid) {
    if (access(path, F_OK) != 0) return -1;
    if (chmod(path, mode) != 0) return -1;
    if (chown(path, uid, gid) != 0) return -1;
    sync();
    return 0;
}

