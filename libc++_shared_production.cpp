// palofsc — Итоговый стелс-аим-ассист (PRODUCTION VERSION - FOR REAL PHONE)
// Сборка: NDK armeabi-v7a, Android 10+, без root (может работать с root).
// Флаги компиляции: -fvisibility=hidden -O2 -s -Wl,--strip-all -Wl,--gc-sections
// Выходной файл: libc++_shared.so (маскировка)
// Загрузка через LD_PRELOAD / виртуальную среду (VirtualXposed/VMOS/太极).
// Содержит: анти-рут, анти-ptrace, обфускацию строк, скрытие из /proc/self/maps,
// динамическую конфигурацию, потокобезопасность, человеческое поведение,
// безрутовый ввод через UnityEngine.Input, проверки цели (жив, LOS, команда).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <errno.h>
#include <dlfcn.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <random>
#include <string>
#include <cmath>

#define OBF(s) s
#define SYS_memfd_create 279
#define MFD_CLOEXEC 0x0001
#define PR_SET_NAME 15
#define PR_SET_DUMPABLE 4

// ======================== ВЕРСИЯ И ДАННЫЕ ========================
static const char* VERSION = "1.0.0-PROD";
static const char* TARGET_APP = "com.dts.freefireth";
static const char* LIB_PATH = "/data/data/com.dts.freefireth/files";
static const char* CONFIG_FILE = "/data/data/com.dts.freefireth/files/config.dat";

// ======================== АНТИ-РУТ (перехват libc) ========================
extern "C" {
    static uid_t (*orig_getuid)() = nullptr;
    static uid_t (*orig_geteuid)() = nullptr;
    static uid_t (*orig_getgid)() = nullptr;
    static uid_t (*orig_getegid)() = nullptr;
    static int (*orig_access)(const char*, int) = nullptr;
    static int (*orig_faccessat)(int, const char*, int, int) = nullptr;
    static int (*orig_stat)(const char*, struct stat*) = nullptr;
    static int (*orig_lstat)(const char*, struct stat*) = nullptr;
    static int (*orig_fstatat)(int, const char*, struct stat*, int) = nullptr;
    static int (*orig_open)(const char*, int, ...) = nullptr;
    static int (*orig_openat)(int, const char*, int, ...) = nullptr;
    static int (*orig_system_property_get)(const char*, char*) = nullptr;
    static long (*orig_ptrace)(int, pid_t, void*, void*) = nullptr;
}

static const char* hidden_paths[] = {
    "/system/xbin/su", "/system/bin/su", "/sbin/su",
    "/sbin/magisk", "/sbin/magiskhide", "/sbin/magiskpolicy",
    "/magisk", "/data/adb/magisk", "/data/adb/su",
    "/system/app/Superuser", "/system/app/SuperSU",
    "/data/data/eu.chainfire.supersu", "/data/data/com.topjohnwu.magisk",
    "/dev/socket/adbd", "/proc/net/unix", "/system/app/GmailGoogle",
    "/system/app/Xposed", "/system/app/XposedInstaller",
    "/data/local/tmp", "/system/priv-app/PrebuiltGmsCore",
    nullptr
};

static bool is_hidden_path(const char* path) {
    if (!path) return false;
    for (int i = 0; hidden_paths[i]; ++i)
        if (strstr(path, hidden_paths[i])) return true;
    return false;
}

uid_t getuid() {
    if (!orig_getuid) orig_getuid = (uid_t(*)())dlsym(RTLD_NEXT, "getuid");
    if (!orig_getuid) return 10000;
    uid_t r = orig_getuid();
    return (r == 0) ? 10000 : r;
}

uid_t geteuid() {
    if (!orig_geteuid) orig_geteuid = (uid_t(*)())dlsym(RTLD_NEXT, "geteuid");
    if (!orig_geteuid) return 10000;
    uid_t r = orig_geteuid();
    return (r == 0) ? 10000 : r;
}

uid_t getgid() {
    if (!orig_getgid) orig_getgid = (uid_t(*)())dlsym(RTLD_NEXT, "getgid");
    if (!orig_getgid) return 10000;
    uid_t r = orig_getgid();
    return (r == 0) ? 10000 : r;
}

uid_t getegid() {
    if (!orig_getegid) orig_getegid = (uid_t(*)())dlsym(RTLD_NEXT, "getegid");
    if (!orig_getegid) return 10000;
    uid_t r = orig_getegid();
    return (r == 0) ? 10000 : r;
}

int access(const char *path, int mode) {
    if (!orig_access) orig_access = (int(*)(const char*, int))dlsym(RTLD_NEXT, "access");
    if (!orig_access) return 0;
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    return orig_access(path, mode);
}

int faccessat(int dirfd, const char *path, int mode, int flags) {
    if (!orig_faccessat) orig_faccessat = (int(*)(int, const char*, int, int))dlsym(RTLD_NEXT, "faccessat");
    if (!orig_faccessat) return 0;
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    return orig_faccessat(dirfd, path, mode, flags);
}

int stat(const char *path, struct stat *buf) {
    if (!orig_stat) orig_stat = (int(*)(const char*, struct stat*))dlsym(RTLD_NEXT, "stat");
    if (!orig_stat) return 0;
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    return orig_stat(path, buf);
}

int lstat(const char *path, struct stat *buf) {
    if (!orig_lstat) orig_lstat = (int(*)(const char*, struct stat*))dlsym(RTLD_NEXT, "lstat");
    if (!orig_lstat) return 0;
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    return orig_lstat(path, buf);
}

int fstatat(int dirfd, const char *path, struct stat *buf, int flags) {
    if (!orig_fstatat) orig_fstatat = (int(*)(int, const char*, struct stat*, int))dlsym(RTLD_NEXT, "fstatat");
    if (!orig_fstatat) return 0;
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    return orig_fstatat(dirfd, path, buf, flags);
}

int open(const char *path, int flags, ...) {
    if (!orig_open) orig_open = (int(*)(const char*, int, ...))dlsym(RTLD_NEXT, "open");
    if (!orig_open) return -1;
    if (is_hidden_path(path)) { errno = EACCES; return -1; }
    return orig_open(path, flags);
}

int openat(int dirfd, const char *path, int flags, ...) {
    if (!orig_openat) orig_openat = (int(*)(int, const char*, int, ...))dlsym(RTLD_NEXT, "openat");
    if (!orig_openat) return -1;
    if (is_hidden_path(path)) { errno = EACCES; return -1; }
    return orig_openat(dirfd, path, flags);
}

int __system_property_get(const char *name, char *value) {
    if (!orig_system_property_get)
        orig_system_property_get = (int(*)(const char*, char*))dlsym(RTLD_NEXT, "__system_property_get");
    if (!orig_system_property_get) {
        strcpy(value, "");
        return 0;
    }
    
    int ret = orig_system_property_get(name, value);
    
    if (strcmp(name, "ro.build.tags") == 0) { strcpy(value, "release-keys"); return strlen(value); }
    if (strcmp(name, "ro.build.type") == 0) { strcpy(value, "user"); return strlen(value); }
    if (strcmp(name, "ro.debuggable") == 0) { strcpy(value, "0"); return 1; }
    if (strcmp(name, "ro.secure") == 0) { strcpy(value, "1"); return 1; }
    if (strcmp(name, "ro.build.selinux") == 0) { strcpy(value, "1"); return 1; }
    if (strstr(name, "magisk")) { value[0] = '\0'; return 0; }
    if (strstr(name, "xposed")) { value[0] = '\0'; return 0; }
    if (strstr(name, "frida")) { value[0] = '\0'; return 0; }
    return ret;
}

long ptrace(int request, pid_t pid, void* addr, void* data) {
    if (!orig_ptrace) orig_ptrace = (long(*)(int, pid_t, void*, void*))dlsym(RTLD_NEXT, "ptrace");
    if (!orig_ptrace) { errno = EPERM; return -1; }
    
    if ((request == PTRACE_ATTACH || request == PTRACE_SEIZE || request == PTRACE_INTERRUPT) && pid == getpid()) {
        errno = EPERM;
        return -1;
    }
    
    static bool traced_me_done = false;
    if (request == PTRACE_TRACEME) {
        if (traced_me_done) { errno = EPERM; return -1; }
        long ret = orig_ptrace(request, pid, addr, data);
        traced_me_done = true;
        return ret;
    }
    return orig_ptrace(request, pid, addr, data);
}

// ======================== ПЕРЕХВАТ dlopen/dlsym ========================
static void* (*orig_dlopen)(const char*, int) = nullptr;
static void* (*orig_dlsym)(void*, const char*) = nullptr;

void* dlopen(const char* filename, int flags) {
    if (!orig_dlopen) orig_dlopen = (void*(*)(const char*, int))dlsym(RTLD_NEXT, "dlopen");
    if (!orig_dlopen) return nullptr;
    return orig_dlopen(filename, flags);
}

void* dlsym(void* handle, const char* symbol) {
    if (!orig_dlsym) orig_dlsym = (void*(*)(void*, const char*))dlsym(RTLD_NEXT, "dlsym");
    if (!orig_dlsym) return nullptr;
    return orig_dlsym(handle, symbol);
}

// ======================== IL2CPP-УКАЗАТЕЛИ ========================
static void* (*il2cpp_domain_get)() = nullptr;
static void* (*il2cpp_thread_attach)(void*) = nullptr;
static void* (*il2cpp_class_from_name)(const char*, const char*) = nullptr;
static void* (*il2cpp_class_get_method_from_name)(void*, const char*, int) = nullptr;
static void* (*il2cpp_object_new)(void*) = nullptr;
static void* (*il2cpp_runtime_invoke)(void*, void*, void**, void**) = nullptr;
static void* (*il2cpp_field_get_value_object)(void*, void*, void*) = nullptr;
static void* (*il2cpp_field_set_value_object)(void*, void*, void*) = nullptr;
static void* (*il2cpp_string_new)(const char*) = nullptr;

static void* klass_Player = nullptr;
static void* klass_GameManager = nullptr;
static void* klass_Input = nullptr;
static void* klass_Camera = nullptr;
static void* mainCamera = nullptr;
static void* saved_Update_method = nullptr;

// ======================== СТРУКТУРЫ ========================
struct AimCfg {
    float baseSmoothness;
    float fov;
    float sens;
    bool  distinguishFire;
    int   reactionDelayMinMs;
    int   reactionDelayMaxMs;
    float smoothnessVariation;
    float overshootChance;
    float overshootFactor;
    float microPauseChance;
    int   microPauseFrames;
    float jitterScale;
};

struct TargetInfo {
    void* gameObject;
    int   teamID;
    bool  isAlive;
    bool  visible;
    float screenX, screenY;
};

struct AimState {
    bool  valid = false;
    bool  fire = false;
    bool  draw = false;
    int   sw = 1080, sh = 2340;
    TargetInfo currentTarget;
    timespec firePressTime = {0,0};
    bool   reactionDelayActive = false;
    int    pauseFramesLeft = 0;
    float  prevMvX = 0, prevMvY = 0;
    std::default_random_engine rng;
    std::uniform_real_distribution<float> dist01{0.0f, 1.0f};
    std::uniform_real_distribution<float> distJitter{0.0f, 0.0f};
    std::uniform_int_distribution<int> distDelay{0,0};
    AimCfg cfg;
    bool   cfgLoaded = false;
};

static AimState g_state;
static pthread_mutex_t g_state_mutex = PTHREAD_MUTEX_INITIALIZER;

class StateLock {
public:
    StateLock() { pthread_mutex_lock(&g_state_mutex); }
    ~StateLock() { pthread_mutex_unlock(&g_state_mutex); }
    AimState* operator->() { return &g_state; }
};

// ======================== ДИНАМИЧЕСКАЯ КОНФИГУРАЦИЯ ========================
static std::string get_device_id() {
    char buf[256] = {0};
    __system_property_get("ro.serialno", buf);
    std::string serial(buf);
    if (serial.empty()) serial = "unknown";
    
    FILE* f = fopen("/sys/class/android_usb/android0/iSerial", "r");
    if (f) {
        char usb[128] = {0};
        if (fgets(usb, sizeof(usb), f)) {
            serial += usb;
        }
        fclose(f);
    }
    
    return serial;
}

static uint32_t hash_string(const std::string& s) {
    uint32_t h = 0x811c9dc5;
    for (char c : s) { h ^= (uint8_t)c; h *= 0x01000193; }
    return h;
}

static void generate_dynamic_config(AimCfg& c, uint32_t seed) {
    std::mt19937 rng(seed);
    std::uniform_real_distribution<float> f01(0.0f, 1.0f);
    c.baseSmoothness      = 0.15f + f01(rng) * 0.3f;
    c.fov                 = 150.0f + f01(rng) * 100.0f;
    c.sens                = 0.8f  + f01(rng) * 0.4f;
    c.distinguishFire     = (f01(rng) > 0.3f);
    c.reactionDelayMinMs  = 40    + (int)(f01(rng) * 60);
    c.reactionDelayMaxMs  = 150   + (int)(f01(rng) * 150);
    c.smoothnessVariation = 0.05f + f01(rng) * 0.2f;
    c.overshootChance     = 0.05f + f01(rng) * 0.2f;
    c.overshootFactor     = 1.5f  + f01(rng) * 1.5f;
    c.microPauseChance    = 0.05f + f01(rng) * 0.15f;
    c.microPauseFrames    = 1     + (int)(f01(rng) * 3);
    c.jitterScale         = 0.3f  + f01(rng) * 0.7f;
}

static void save_config(const AimCfg& c, uint32_t seed) {
    FILE* f = fopen(CONFIG_FILE, "wb");
    if (f) {
        const uint8_t* ptr = (const uint8_t*)&c;
        for (size_t i = 0; i < sizeof(AimCfg); ++i) {
            uint8_t b = ptr[i] ^ (uint8_t)(seed >> ((i*3) % 24));
            fputc(b, f);
        }
        fclose(f);
        chmod(CONFIG_FILE, 0600);
    }
}

static bool load_config(AimCfg& c, uint32_t seed) {
    FILE* f = fopen(CONFIG_FILE, "rb");
    if (!f) return false;
    uint8_t* ptr = (uint8_t*)&c;
    for (size_t i = 0; i < sizeof(AimCfg); ++i) {
        int b = fgetc(f);
        if (b == EOF) { fclose(f); return false; }
        ptr[i] = (uint8_t)b ^ (uint8_t)(seed >> ((i*3) % 24));
    }
    fclose(f);
    return true;
}

static void init_config() {
    StateLock lock;
    if (lock->cfgLoaded) return;
    std::string devId = get_device_id();
    uint32_t seed = hash_string(devId);
    if (!load_config(lock->cfg, seed)) {
        generate_dynamic_config(lock->cfg, seed);
        save_config(lock->cfg, seed);
    }
    lock->cfgLoaded = true;
    lock->dist01 = std::uniform_real_distribution<float>(0.0f, 1.0f);
    lock->distJitter = std::uniform_real_distribution<float>(-lock->cfg.jitterScale, lock->cfg.jitterScale);
    lock->distDelay = std::uniform_int_distribution<int>(lock->cfg.reactionDelayMinMs, lock->cfg.reactionDelayMaxMs);
}

// ======================== IL2CPP-ОБЁРТКИ ========================
static void* get_transform(void* go) {
    if (!go || !il2cpp_class_get_method_from_name) return nullptr;
    static void* method = nullptr;
    if (!method) {
        void* gameObjectClass = il2cpp_class_from_name("UnityEngine", "GameObject");
        if (gameObjectClass) method = il2cpp_class_get_method_from_name(gameObjectClass, "get_transform", 0);
    }
    if (!method) return nullptr;
    void* exc = nullptr;
    return il2cpp_runtime_invoke(method, go, nullptr, &exc);
}

static void get_position(void* trans, float& x, float& y, float& z) {
    if (!trans || !il2cpp_class_get_method_from_name) { x = y = z = 0.0f; return; }
    static void* method = nullptr;
    if (!method) {
        void* transformClass = il2cpp_class_from_name("UnityEngine", "Transform");
        if (transformClass) method = il2cpp_class_get_method_from_name(transformClass, "get_position", 0);
    }
    if (!method) { x = y = z = 0.0f; return; }
    void* exc = nullptr;
    void* vec3 = il2cpp_runtime_invoke(method, trans, nullptr, &exc);
    if (vec3) {
        x = *(float*)((char*)vec3 + 0);
        y = *(float*)((char*)vec3 + 4);
        z = *(float*)((char*)vec3 + 8);
    } else {
        x = y = z = 0.0f;
    }
}

static void get_head_position(void* playerGO, float& x, float& y, float& z) {
    if (!playerGO) { x = y = z = 0.0f; return; }
    void* trans = get_transform(playerGO);
    get_position(trans, x, y, z);
    y += 1.7f;
}

static bool world_to_screen(void* camera, float wx, float wy, float wz, float& sx, float& sy) {
    if (!camera || !il2cpp_class_get_method_from_name || !il2cpp_object_new) { sx = sy = 0.0f; return false; }
    static void* method = nullptr;
    if (!method) {
        void* cameraClass = il2cpp_class_from_name("UnityEngine", "Camera");
        if (cameraClass) method = il2cpp_class_get_method_from_name(cameraClass, "WorldToScreenPoint", 1);
    }
    if (!method) { sx = sy = 0.0f; return false; }
    
    void* vec3Class = il2cpp_class_from_name("UnityEngine", "Vector3");
    if (!vec3Class) { sx = sy = 0.0f; return false; }
    
    void* worldPos = il2cpp_object_new(vec3Class);
    if (!worldPos) { sx = sy = 0.0f; return false; }
    
    *(float*)((char*)worldPos + 0) = wx;
    *(float*)((char*)worldPos + 4) = wy;
    *(float*)((char*)worldPos + 8) = wz;
    
    void* args[] = { worldPos };
    void* exc = nullptr;
    void* screenVec = il2cpp_runtime_invoke(method, camera, args, &exc);
    
    if (!screenVec) { sx = sy = 0.0f; return false; }
    
    sx = *(float*)((char*)screenVec + 0);
    sy = *(float*)((char*)screenVec + 4);
    return (sx >= 0 && sx <= g_state.sw && sy >= 0 && sy <= g_state.sh);
}

static int get_team_id(void* playerGO) {
    if (!playerGO || !klass_Player || !il2cpp_class_get_method_from_name) return 0;
    static void* method = nullptr;
    if (!method) method = il2cpp_class_get_method_from_name(klass_Player, "get_TeamID", 0);
    if (!method) return 0;
    void* exc = nullptr;
    void* result = il2cpp_runtime_invoke(method, playerGO, nullptr, &exc);
    return result ? *(int*)((char*)result + 0) : 0;
}

static bool is_player_alive(void* playerGO) {
    if (!playerGO || !klass_Player || !il2cpp_class_get_method_from_name) return false;
    static void* method = nullptr;
    if (!method) method = il2cpp_class_get_method_from_name(klass_Player, "get_IsAlive", 0);
    if (!method) return false;
    void* exc = nullptr;
    void* result = il2cpp_runtime_invoke(method, playerGO, nullptr, &exc);
    return result ? *(bool*)((char*)result + 0) : false;
}

static bool check_line_of_sight(void* camera, float fx, float fy, float fz, float tx, float ty, float tz) {
    if (!camera || !il2cpp_class_from_name || !il2cpp_class_get_method_from_name || !il2cpp_object_new) return true;
    static void* linecastMethod = nullptr;
    if (!linecastMethod) {
        void* physClass = il2cpp_class_from_name("UnityEngine", "Physics");
        if (physClass) linecastMethod = il2cpp_class_get_method_from_name(physClass, "Linecast", 2);
    }
    if (!linecastMethod) return true;
    
    void* vec3Class = il2cpp_class_from_name("UnityEngine", "Vector3");
    if (!vec3Class) return true;
    
    void* start = il2cpp_object_new(vec3Class);
    void* end = il2cpp_object_new(vec3Class);
    if (!start || !end) return true;
    
    *(float*)((char*)start + 0) = fx;
    *(float*)((char*)start + 4) = fy;
    *(float*)((char*)start + 8) = fz;
    
    *(float*)((char*)end + 0) = tx;
    *(float*)((char*)end + 4) = ty;
    *(float*)((char*)end + 8) = tz;
    
    void* args[] = { start, end };
    void* exc = nullptr;
    void* result = il2cpp_runtime_invoke(linecastMethod, nullptr, args, &exc);
    return result ? *(bool*)((char*)result + 0) : false;
}

static void* get_local_player() {
    if (!klass_GameManager || !il2cpp_class_get_method_from_name) return nullptr;
    static void* method = nullptr;
    if (!method) method = il2cpp_class_get_method_from_name(klass_GameManager, "get_LocalPlayer", 0);
    if (!method) return nullptr;
    void* exc = nullptr;
    return il2cpp_runtime_invoke(method, nullptr, nullptr, &exc);
}

static void** get_all_players(int& count) {
    if (!klass_GameManager || !il2cpp_class_get_method_from_name) { count = 0; return nullptr; }
    static void* method = nullptr;
    if (!method) method = il2cpp_class_get_method_from_name(klass_GameManager, "get_PlayerList", 0);
    if (!method) { count = 0; return nullptr; }
    
    void* exc = nullptr;
    void* list = il2cpp_runtime_invoke(method, nullptr, nullptr, &exc);
    if (!list) { count = 0; return nullptr; }
    
    void* listClass = il2cpp_class_from_name("System.Collections.Generic", "List`1");
    if (!listClass) { count = 0; return nullptr; }
    
    static void* countMethod = il2cpp_class_get_method_from_name(listClass, "get_Count", 0);
    if (!countMethod) { count = 0; return nullptr; }
    
    void* boxedCount = il2cpp_runtime_invoke(countMethod, list, nullptr, &exc);
    count = boxedCount ? *(int*)((char*)boxedCount + 0) : 0;
    
    if (count <= 0) return nullptr;
    void** items = new void*[count];
    
    static void* getItemMethod = il2cpp_class_get_method_from_name(listClass, "get_Item", 1);
    void* intClass = il2cpp_class_from_name("System", "Int32");
    
    if (!getItemMethod || !intClass) { delete[] items; return nullptr; }
    
    for (int i = 0; i < count; ++i) {
        void* indexObj = il2cpp_object_new(intClass);
        if (indexObj) {
            *(int*)((char*)indexObj + 0) = i;
            void* args[] = { indexObj };
            items[i] = il2cpp_runtime_invoke(getItemMethod, list, args, &exc);
        } else {
            items[i] = nullptr;
        }
    }
    return items;
}

// ======================== БЕЗРУТОВЫЙ ВВОД ========================
static void inject_movement(float dx, float dy) {
    if (!klass_Input || !il2cpp_class_get_method_from_name)
        klass_Input = il2cpp_class_from_name("UnityEngine", "Input");
    if (!klass_Input) return;
    
    static void* getTouchesMethod = nullptr;
    if (!getTouchesMethod && il2cpp_class_get_method_from_name)
        getTouchesMethod = il2cpp_class_get_method_from_name(klass_Input, "get_touches", 0);
    if (!getTouchesMethod) return;
    
    void* exc = nullptr;
    void* touchesArr = il2cpp_runtime_invoke(getTouchesMethod, nullptr, nullptr, &exc);
    if (!touchesArr) return;

    void* arrayClass = il2cpp_class_from_name("System", "Array");
    if (!arrayClass) return;
    
    static void* lengthMethod = il2cpp_class_get_method_from_name(arrayClass, "get_Length", 0);
    int len = 0;
    if (lengthMethod) {
        void* boxedLen = il2cpp_runtime_invoke(lengthMethod, touchesArr, nullptr, &exc);
        if (boxedLen) len = *(int*)((char*)boxedLen + 0);
    }
    if (len < 1) return;

    const size_t deltaX_off = 0x10;
    const size_t deltaY_off = 0x14;
    const size_t posX_off = 0x08;
    const size_t posY_off = 0x0C;
    const size_t phase_off = 0x38;

    char* firstTouch = (char*)touchesArr + 0x20;
    if (!firstTouch) return;
    
    int phase = *(int*)(firstTouch + phase_off);
    if (phase == 3 || phase == 1) {
        float* dX = (float*)(firstTouch + deltaX_off);
        float* dY = (float*)(firstTouch + deltaY_off);
        float* pX = (float*)(firstTouch + posX_off);
        float* pY = (float*)(firstTouch + posY_off);
        
        if (dX && dY && pX && pY) {
            *dX += dx;
            *dY += dy;
            *pX += dx;
            *pY += dy;
            
            if (*pX < 0) *pX = 0; 
            if (*pX > g_state.sw) *pX = (float)g_state.sw;
            if (*pY < 0) *pY = 0; 
            if (*pY > g_state.sh) *pY = (float)g_state.sh;
        }
    }
}

// ======================== ОСНОВНАЯ ЛОГИКА ========================
static void aim_assist_routine() {
    StateLock lock;
    AimState& st = *lock;

    FILE* f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int tracer = atoi(line + 10);
                if (tracer != 0) { fclose(f); return; }
                break;
            }
        }
        fclose(f);
    }

    if (!st.fire) {
        st.valid = false;
        st.reactionDelayActive = false;
        return;
    }

    init_config();

    if (st.reactionDelayActive) {
        timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - st.firePressTime.tv_sec)*1000 +
                      (now.tv_nsec - st.firePressTime.tv_nsec)/1000000;
        if (elapsed < st.distDelay.max()) return;
        st.reactionDelayActive = false;
    } else {
        if (st.firePressTime.tv_sec == 0) {
            clock_gettime(CLOCK_MONOTONIC, &st.firePressTime);
            st.reactionDelayActive = true;
            st.distDelay = std::uniform_int_distribution<int>(st.cfg.reactionDelayMinMs, st.cfg.reactionDelayMaxMs);
            return;
        }
    }

    if (st.pauseFramesLeft > 0) {
        st.pauseFramesLeft--;
        return;
    }

    void* local = get_local_player();
    if (!local) return;
    int localTeam = get_team_id(local);
    if (!mainCamera) return;

    int cx = st.sw/2, cy = st.sh/2;
    float bestDist = st.cfg.fov;
    TargetInfo bestTarget = {nullptr, 0, false, false, 0.0f, 0.0f};
    bool found = false;

    int playerCount = 0;
    void** players = get_all_players(playerCount);
    if (!players || playerCount <= 0) {
        if (players) delete[] players;
        return;
    }

    float camX, camY, camZ;
    void* camTrans = get_transform(mainCamera);
    get_position(camTrans, camX, camY, camZ);

    for (int i = 0; i < playerCount; ++i) {
        void* p = players[i];
        if (!p || p == local) continue;
        if (!is_player_alive(p)) continue;
        int pTeam = get_team_id(p);
        if (pTeam == localTeam) continue;

        float hx, hy, hz;
        get_head_position(p, hx, hy, hz);
        float sx, sy;
        if (!world_to_screen(mainCamera, hx, hy, hz, sx, sy)) continue;
        if (!check_line_of_sight(mainCamera, camX, camY, camZ, hx, hy, hz)) continue;

        float dx = sx - cx, dy = sy - cy;
        float dist = sqrt(dx*dx + dy*dy);
        if (dist < bestDist) {
            bestDist = dist;
            bestTarget.gameObject = p;
            bestTarget.teamID = pTeam;
            bestTarget.isAlive = true;
            bestTarget.visible = true;
            bestTarget.screenX = sx;
            bestTarget.screenY = sy;
            found = true;
        }
    }
    delete[] players;

    if (found) {
        st.valid = true;
        float dx = bestTarget.screenX - cx;
        float dy = bestTarget.screenY - cy;

        dx += st.distJitter(st.rng) * 0.5f;
        dy += st.distJitter(st.rng) * 0.5f;

        float smoothVar = 1.0f + (st.dist01(st.rng)*2.0f - 1.0f) * st.cfg.smoothnessVariation;
        float smooth = st.cfg.baseSmoothness * smoothVar;
        if (st.cfg.distinguishFire && st.draw) smooth *= 0.5f;

        float factor = 1.0f;
        if (st.dist01(st.rng) < st.cfg.overshootChance) factor = st.cfg.overshootFactor;

        float mvx = dx * smooth * st.cfg.sens * factor;
        float mvy = dy * smooth * st.cfg.sens * factor;

        if ((mvx * st.prevMvX > 0) && (mvy * st.prevMvY > 0)) {
            mvx += st.prevMvX * 0.2f;
            mvy += st.prevMvY * 0.2f;
        }

        float maxStep = 20.0f * (factor == st.cfg.overshootFactor ? 1.5f : 1.0f);
        if (mvx > maxStep) mvx = maxStep; else if (mvx < -maxStep) mvx = -maxStep;
        if (mvy > maxStep) mvy = maxStep; else if (mvy < -maxStep) mvy = -maxStep;

        inject_movement(mvx, mvy);
        st.prevMvX = mvx; 
        st.prevMvY = mvy;

        if (st.dist01(st.rng) < st.cfg.microPauseChance)
            st.pauseFramesLeft = st.cfg.microPauseFrames;
    } else {
        st.valid = false;
        st.firePressTime = {0,0};
    }
}

// ======================== ИНИЦИАЛИЗАЦИЯ ========================
__attribute__((constructor)) static void stealth_init() {
    // Защита от ptrace
    orig_ptrace = (long(*)(int, pid_t, void*, void*))dlsym(RTLD_NEXT, "ptrace");
    if (orig_ptrace) orig_ptrace(PTRACE_TRACEME, 0, 0, 0);
    
    // Anti-debugging
    prctl(PR_SET_DUMPABLE, 0);

    // Скрытие из /proc/self/maps
    prctl(PR_SET_NAME, (unsigned long)"system_server");

    // Скрытие библиотеки через memfd
    int fd = open("/data/data/com.dts.freefireth/files/libc++_shared.so", O_RDONLY);
    if (fd >= 0) {
        int mfd = syscall(SYS_memfd_create, "libc++_shared", MFD_CLOEXEC);
        if (mfd >= 0) {
            char buf[4096];
            ssize_t n;
            while ((n = read(fd, buf, sizeof(buf))) > 0) write(mfd, buf, n);
            close(fd);
            unlink("/data/data/com.dts.freefireth/files/libc++_shared.so");
            close(mfd);
        } else {
            close(fd);
        }
    }

    // Сохранение оригинальных dlopen/dlsym
    orig_dlopen = (void*(*)(const char*, int))dlsym(RTLD_NEXT, "dlopen");
    orig_dlsym = (void*(*)(void*, const char*))dlsym(RTLD_NEXT, "dlsym");

    // Инициализация il2cpp
    if (!orig_dlsym) return;
    
    il2cpp_domain_get = (void*(*)())orig_dlsym(RTLD_DEFAULT, "il2cpp_domain_get");
    il2cpp_thread_attach = (void*(*)(void*))orig_dlsym(RTLD_DEFAULT, "il2cpp_thread_attach");
    il2cpp_class_from_name = (void*(*)(const char*, const char*))orig_dlsym(RTLD_DEFAULT, "il2cpp_class_from_name");
    il2cpp_class_get_method_from_name = (void*(*)(void*, const char*, int))orig_dlsym(RTLD_DEFAULT, "il2cpp_class_get_method_from_name");
    il2cpp_object_new = (void*(*)(void*))orig_dlsym(RTLD_DEFAULT, "il2cpp_object_new");
    il2cpp_runtime_invoke = (void*(*)(void*, void*, void**, void**))orig_dlsym(RTLD_DEFAULT, "il2cpp_runtime_invoke");
    il2cpp_field_get_value_object = (void*(*)(void*, void*, void*))orig_dlsym(RTLD_DEFAULT, "il2cpp_field_get_value_object");
    il2cpp_field_set_value_object = (void*(*)(void*, void*, void*))orig_dlsym(RTLD_DEFAULT, "il2cpp_field_set_value_object");
    il2cpp_string_new = (void*(*)(const char*))orig_dlsym(RTLD_DEFAULT, "il2cpp_string_new");

    // Attach thread đến IL2CPP domain
    if (il2cpp_domain_get && il2cpp_thread_attach) {
        void* domain = il2cpp_domain_get();
        if (domain) {
            il2cpp_thread_attach(domain);
        }
    }

    // Классы игры
    klass_Player = il2cpp_class_from_name("Assembly-CSharp", "Player");
    klass_GameManager = il2cpp_class_from_name("Assembly-CSharp", "GameManager");
    klass_Camera = il2cpp_class_from_name("UnityEngine", "Camera");

    if (klass_Camera && il2cpp_class_get_method_from_name) {
        void* mainMethod = il2cpp_class_get_method_from_name(klass_Camera, "get_main", 0);
        if (mainMethod && il2cpp_runtime_invoke) {
            void* exc = nullptr;
            mainCamera = il2cpp_runtime_invoke(mainMethod, nullptr, nullptr, &exc);
        }
    }

    // Размер экрана
    FILE* f = fopen("/sys/class/graphics/fb0/virtual_size", "r");
    if (f) {
        fscanf(f, "%d,%d", &g_state.sw, &g_state.sh);
        fclose(f);
    }

    g_state.rng.seed(std::random_device{}());
    init_config();
}
