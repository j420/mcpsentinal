/* True negative — hard-coded trusted library load (libssl). */
#include <dlfcn.h>

int load() {
    void *h = dlopen("libssl.so.3", RTLD_LAZY);
    return h ? 0 : 1;
}
