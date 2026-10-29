/*
 * Mock ECU firmware.
 * Version and build metadata are injected at compile time by the Makefile.
 */
#include <stdio.h>

#ifndef FW_VERSION
#define FW_VERSION "0.0.0-dev"
#endif

#ifndef FW_BUILD
#define FW_BUILD "local"
#endif

int main(void) {
    printf("ECU firmware %s (build %s)\n", FW_VERSION, FW_BUILD);
    return 0;
}
