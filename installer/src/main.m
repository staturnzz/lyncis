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
#include <arpa/inet.h>
#include <sys/socket.h>
#include <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <pthread.h>

#include "common.h"
#include "offsets.h"
#include "memory.h"
#include "exploit.h"
#include "patches.h"
#include "utils.h"
#include "installer.h"

kinfo_t *kinfo = NULL;

int exit_installer(const char *reason) {
    char *msg = calloc(1, 1024);
    snprintf(msg, 1024, "\n\n#### LYNCIS CRASH ####\n%s\n\n", reason);
    dyld_quit(msg);

    free(msg);
    exit(0);
    return 0;
}

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

int clear_mobile_installation_cache(void) {
    if (access("/var/mobile/Library/Caches/com.apple.mobile.installation.plist", F_OK) == 0) {
        unlink("/var/mobile/Library/Caches/com.apple.mobile.installation.plist");
        sync();
    }

    DIR *dir = opendir("/var/mobile/Library/Caches");
    if (dir == NULL) return 1;
    struct dirent *entry = NULL;

    while ((entry = readdir(dir)) != NULL) {
        char *item = (char *)(entry->d_name);
        if (strncmp(item, "com.apple.LaunchServices", strlen("com.apple.LaunchServices")) == 0) {
            if (strstr(item, ".csstore") != NULL) {
                char *full_path = calloc(1, PATH_MAX);
                snprintf(full_path, PATH_MAX, "/var/mobile/Library/Caches/%s", item);
                unlink(full_path);
                free(full_path);
                sync();
            }
        }
    }

    closedir(dir);
    return 0;
}

int show_non_default_apps(void) {
    NSNumber *num_true = [NSNumber numberWithBool:YES];
    NSNumber *num_false = [NSNumber numberWithBool:NO];
    char *hw_model = get_hw_model();

    if (hw_model != NULL) {
        NSString *plist_path = [NSString stringWithFormat:@"/System/Library/CoreServices/SpringBoard.app/%s.plist", hw_model];
        free(hw_model);
        
        if (access(plist_path.UTF8String, F_OK) == 0) {
            NSMutableDictionary *plist = [[NSMutableDictionary alloc] initWithContentsOfFile:plist_path];
            if (plist != NULL) {
                NSMutableDictionary *capabilities = plist[@"capabilities"];
                if (capabilities != NULL) {
                    [capabilities setObject:num_false forKey:@"hide-non-default-apps"];
                    [plist writeToFile:plist_path atomically:YES];
                    sync();
                }
            }
        }
    }

    NSString *plist_path = @"/var/mobile/Library/Preferences/com.apple.springboard.plist";
    NSMutableDictionary *plist = [[NSMutableDictionary alloc] initWithContentsOfFile:plist_path];
    if (plist == NULL) {
        plist = [NSMutableDictionary dictionary];
        if (plist == NULL) return 1;
    }

    [plist setObject:num_true forKey:@"SBShowNonDefaultSystemApps"];
    [plist writeToFile:plist_path atomically:YES];
    sync();

    chmod(plist_path.UTF8String, 0700);
    chown(plist_path.UTF8String, 501, 501);
    return 0;
}

int uicache(void) {
    // stack casues webkit to crash
    char **args = calloc(1, sizeof(char *) * 2);
    args[0] = "/usr/bin/uicache";
    args[1] = NULL;

    pid_t pid = -1;
    int status = -1;
    int rv = posix_spawn(&pid, "/usr/bin/uicache", NULL, NULL, args, NULL);
    if (rv != 0 || pid == -1) goto done;
    
    do { if (waitpid(pid, &status, 0) == -1) goto done; }
    while (!WIFEXITED(status) && !WIFSIGNALED(status));

done:
    free(args);
    return status;
}

int run_tar(const char *tar_path, const char *output_path) {
    // stack casues webkit to crash
    char **args = calloc(1, sizeof(char *) * 9);
    args[0] = "/bin/tar";
    args[1] = "-xf";
    args[2] = (char *)tar_path;
    args[3] = "-C";
    args[4] = (char *)output_path;
    args[5] = "--preserve-permissions";
    args[6] = "--no-overwrite-dir";
    args[7] = NULL;

    pid_t pid = -1;
    int status = -1;
    int rv = posix_spawn(&pid, "/bin/tar", NULL, NULL, args, NULL);
    if (rv != 0 || pid == -1) goto done;
    
    do { if (waitpid(pid, &status, 0) == -1) goto done; }
    while (!WIFEXITED(status) && !WIFSIGNALED(status));

done:
    free(args);
    return status;
}

int install_bootstrap(void) {
    chmod("/private", 0755);
    chmod("/private/var", 0755);
    chmod("/private/var/mobile", 0755);
    chmod("/private/var/mobile/Library", 0755);
    chmod("/private/var/mobile/Library/Preferences", 0755);

    mkdir("/Library/LaunchDaemons", 0755);
    mkdir("/private/var/mobile/Media", 0755);
    sync();

    chmod("/bin/tar", 0755);
    chown("/bin/tar", 0, 0);
    chmod("/tmp/bootstrap.tar", 0777);
    run_tar("/tmp/bootstrap.tar", "/");
    unlink("/tmp/bootstrap.tar");

    clear_mobile_installation_cache();
    for (int i = 0; i < 50; i++) {
        show_non_default_apps();
    }

    uicache();
    create_file("/.cydia_no_stash", 0644, 0, 0);
    create_file("/.lyncis_installed", 0644, 0, 0);
    sync();

    killall("installd");
    killall("fseventsd");
    return 0;
}

int install_untether(void) {
    unlink("/System/Library/Caches/com.apple.xcpd");
    chmod("/tmp/lyncis.tar", 0777);
    run_tar("/tmp/lyncis.tar", "/");

    char **args = calloc(1, sizeof(char *) * 9);
    args[0] = "/bin/bash";
    args[1] = "/install.sh";
    args[2] = NULL;

    pid_t pid = -1;
    int status = -1;
    int rv = posix_spawn(&pid, args[0], NULL, NULL, args, environ);
    if (rv != 0 || pid == -1) goto done;
    
    do { if (waitpid(pid, &status, 0) == -1) goto done; }
    while (!WIFEXITED(status) && !WIFSIGNALED(status));

done:
    free(args);
    unlink("/install.sh");
    return status;
}

int save_buffer(void *data, uint32_t size, const char *path) {
    unlink(path);
    sync();

    FILE *file = fopen(path, "wb+");
    if (file == NULL) return -1;

    fwrite(data, size, 1, file);
    fflush(file);
    fclose(file);
    sync();

    chmod(path, 0777);
    chown(path, 0, 0);
    return access(path, F_OK);
}

const char *detect_jailbreak(void) {
    if (access("/.lyncis_installed", F_OK) == 0) return "lyncis";
    if (access("/panguaxe", F_OK) == 0 ||
        access("/panguaxe.installed", F_OK) == 0 ||
        access("/var/mobile/Media/panguaxe.installed", F_OK) == 0) return "Pangu";

    if (access("/evasi0n7", F_OK) == 0 ||
        access("/System/Library/LaunchDaemons/com.evad3rs.evasi0n7.untether.plist", F_OK) == 0 ||
        access("/evasi0n7-installed", F_OK) == 0) return "evasi0n7";

    if (access("/.cydia_no_stash", F_OK) == 0 ||
        access("/Applications/Cydia.app/Cydia", F_OK) == 0 ||
        access("/usr/lib/apt", F_OK) == 0) return "Unknown";
    return NULL;
}

int main(int argc, char **argv, char **env, char **apple) {
    openlog("com.staturnz.lyncis", LOG_PID, LOG_DAEMON);
    resources_t *resources = calloc(1, sizeof(resources_t));
    memcpy(resources, (void *)(*(uint32_t **)(argv[0])), sizeof(resources_t));
    if (resources->magic != 0x41414100) {
        return exit_installer("invalid resource magic\n");
    }

    const char *detected = detect_jailbreak();
    if (detected != NULL) {
        void *msg = calloc(1, 512);
        snprintf(msg, 512, "already jailbroken with: %s\n", detected);
        return exit_installer(msg);
    }

    kinfo = run_exploit();
    if (kinfo == NULL) {
        return exit_installer("kernel exploit failed\n");
    }

    uint32_t kern_ucred = rk32(kinfo->kern_proc_addr + koffsetof(proc, ucred));
    uint32_t self_ucred = rk32(kinfo->self_proc_addr + koffsetof(proc, ucred));
    wk32(kinfo->self_proc_addr + koffsetof(proc, ucred), kern_ucred);
    setuid(0);
    setgid(0);

    if (getuid() != 0 || getgid() != 0) {
        return exit_installer("failed to get root\n");
    }

    patch_kernel(kinfo);
    if (remount_rootfs() != 0) {
        return exit_installer("failed to remount rootfs\n");
    }

    if (save_buffer(resources->tar_data, resources->tar_size, "/bin/tar") != 0) {
        return exit_installer("failed to save /bin/tar\n");
    }

    if (save_buffer(resources->bootstrap_data, resources->bootstrap_size, "/tmp/bootstrap.tar") != 0) {
        return exit_installer("failed to save /tmp/bootstrap.tar\n");
    }

    if (save_buffer(resources->untether_data, resources->untether_size, "/tmp/lyncis.tar") != 0) {
        return exit_installer("failed to save /tmp/lyncis.tar\n");
    }

    free(resources);
    if (install_bootstrap() != 0) {
        return exit_installer("failed to install bootstrap\n");
    }

    if (install_untether() != 0) {
        return exit_installer("failed to install untether\n");
    }

    usleep(100000);
    reboot(0);
    return 0;
}
