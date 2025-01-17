#ifndef installer_h
#define installer_h

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct {
    uint32_t magic;
    void *bootstrap_data;
    uint32_t bootstrap_size;
    void *untether_data;
    uint32_t untether_size;
    void *tar_data;
    uint32_t tar_size;
} resources_t;

void dyld_quit(const char *reason);

#endif /* installer_h */
