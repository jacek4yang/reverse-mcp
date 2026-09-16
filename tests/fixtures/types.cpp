// Type-recovery fixture (#11): multiple functions share one plain struct
// (field-evidence aggregation), and a C++ class with a vtable maps virtual
// calls to candidate methods. Deliberately unoptimized so shapes survive.
#include <stdio.h>

// Plain struct shared by several functions: recover offsets from access.
struct Config {
    int level;         // +0x00, 4 bytes, read+write
    long long key;     // +0x08, 8 bytes, write then read
    int mode;          // +0x10, 4 bytes, read only
};

static Config g_config;

void config_init(void) {
    g_config.level = 3;
    g_config.key = 0x12345678LL;
    g_config.mode = 1;
}

int config_eval(int arg) {
    g_config.level += arg & 1;
    return g_config.level * 2 + (int)(g_config.key & 0xFF) + g_config.mode;
}

// C++ class with a vtable: slots map to candidate methods.
struct Device {
    virtual ~Device() {}
    virtual int reset(void) { return 1; }
    virtual int probe(void) { return 2; }
    virtual int poll(void) { return 3; }
};

static Device g_dev;

int device_drive(Device *d) {
    return d->reset() + d->probe();
}

int main(void) {
    config_init();
    int r = config_eval(5);
    r += device_drive(&g_dev);
    printf("r=%d\n", r);
    return 0;
}
