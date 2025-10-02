#include <stdio.h>

int main() {
    long uid;
    asm volatile (
        "mov $102, %%rax\n\t"  /* syscall number for getuid on x86-64 (example) */
        "syscall\n\t"
        : "=a" (uid)           /* output: uid in rax */
        :                      /* no inputs here */
        : "rcx", "r11"         /* clobbered by syscall */
    );
    printf("uid=%ld\n", uid);
    return 0;
}