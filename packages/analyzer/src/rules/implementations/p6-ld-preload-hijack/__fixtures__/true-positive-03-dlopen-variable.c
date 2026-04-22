/* True positive #3 — dlopen with variable path (lethal edge #3). */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    const char *libpath = getenv("PLUGIN_PATH");
    void *handle = dlopen(libpath, RTLD_LAZY);
    if (!handle) return 1;
    return 0;
}
