#ifndef utils_h
#define utils_h

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define PROC_PIDPATHINFO            11
#define PROC_PIDPATHINFO_SIZE       1024
#define PROC_PIDPATHINFO_MAXSIZE    (4*1024)
#define PROC_ALL_PIDS               1
#define PROC_PGRP_ONLY              2
#define PROC_TTY_ONLY               3
#define PROC_UID_ONLY               4
#define PROC_RUID_ONLY              5
#define PROC_PPID_ONLY              6
#define PROC_KDBG_ONLY              7

extern int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
extern int proc_name(int pid, void * buffer, uint32_t buffersize);
extern char **environ;

pid_t pid_for_proc_name(const char *process_name);
void killall(const char *name);
int create_file(const char *path, mode_t mode, uid_t uid, gid_t gid);
int set_file_permissions(const char *path, mode_t mode, uid_t uid, gid_t gid);
void print_log(const char *fmt, ...);
char *get_hw_model(void);

#endif /* utils_h */