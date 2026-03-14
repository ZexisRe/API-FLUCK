#import <Foundation/Foundation.h>
#import <sys/mman.h>
#import <mach-o/dyld.h>
#import <Security/Security.h>
#import <UIKit/UIKit.h>
#import "SecureMap.h"
#import "KeyAuthConfig.h"

// Obfuscated keys
static const uint8_t k1[] = {0x01, 0x10, 0x10, 0x55, 0x09, 0x0E, 0x14, 0x05, 0x07, 0x12, 0x09, 0x14, 0x19, 0x55, 0x03, 0x0F, 0x0D, 0x10, 0x12, 0x0F, 0x0D, 0x09, 0x13, 0x05, 0x04}; // app_integrity_compromised
static const uint8_t k2[] = {0x03, 0x0F, 0x12, 0x12, 0x15, 0x10, 0x14, 0x09, 0x0F, 0x0E, 0x55, 0x14, 0x09, 0x0D, 0x05, 0x13, 0x14, 0x01, 0x0D, 0x10}; // corruption_timestamp
static const uint8_t k3[] = {0x03, 0x0F, 0x12, 0x12, 0x15, 0x10, 0x14, 0x09, 0x0F, 0x0E, 0x55, 0x03, 0x0F, 0x15, 0x0E, 0x14}; // corruption_count
static const uint8_t k4[] = {0x56, 0x09, 0x0E, 0x14, 0x05, 0x07, 0x12, 0x09, 0x14, 0x19, 0x55, 0x16, 0x09, 0x0F, 0x0C, 0x01, 0x14, 0x09, 0x0F, 0x0E}; // .integrity_violation

// Corruption marker strings
static const uint8_t s1[] = {0x23, 0x2F, 0x32, 0x32, 0x35, 0x30, 0x34, 0x25, 0x24, 0x58}; // CORRUPTED:
static const uint8_t s2[] = {0x23, 0x2F, 0x32, 0x32, 0x35, 0x30, 0x34, 0x25, 0x24}; // CORRUPTED
static const uint8_t s3[] = {0x09, 0x0E, 0x14, 0x05, 0x07, 0x12, 0x09, 0x14, 0x19, 0x55, 0x16, 0x09, 0x0F, 0x0C, 0x01, 0x14, 0x09, 0x0F, 0x0E}; // integrity_violation
static const uint8_t s4[] = {0x21, 0x30, 0x30, 0x55, 0x29, 0x2E, 0x34, 0x25, 0x27, 0x32, 0x29, 0x34, 0x39, 0x55, 0x36, 0x29, 0x2F, 0x2C, 0x21, 0x34, 0x25, 0x24}; // APP_INTEGRITY_VIOLATED

// Directory paths
static const uint8_t d1[] = {0x56, 0x01, 0x10, 0x10, 0x55, 0x04, 0x01, 0x14, 0x01}; // .app_data
static const uint8_t d2[] = {0x13, 0x14, 0x01, 0x14, 0x05}; // state

// Allowed frameworks
static const uint8_t a1[] = {0x24, 0x01, 0x14, 0x01, 0x24, 0x0F, 0x0D, 0x05, 0x33, 0x24, 0x2B}; // DataDomeSDK
static const uint8_t a2[] = {0x26, 0x0C, 0x15, 0x03, 0x0B, 0x56, 0x06, 0x12, 0x01, 0x0D, 0x05, 0x17, 0x0F, 0x12, 0x0B}; // Fluck.framework
static const uint8_t a3[] = {0x26, 0x0C, 0x15, 0x03, 0x0B}; // Fluck
static const uint8_t a4[] = {0x06, 0x12, 0x05, 0x05, 0x06, 0x09, 0x12, 0x05, 0x14, 0x08}; // freefireth

// System paths
static const uint8_t p1[] = {0x51, 0x33, 0x19, 0x13, 0x14, 0x05, 0x0D, 0x51}; // /System/
static const uint8_t p2[] = {0x51, 0x15, 0x13, 0x12, 0x51, 0x0C, 0x09, 0x02, 0x51}; // /usr/lib/
static const uint8_t p3[] = {0x51, 0x10, 0x12, 0x09, 0x16, 0x01, 0x14, 0x05, 0x51, 0x10, 0x12, 0x05, 0x02, 0x0F, 0x0F, 0x14, 0x51}; // /private/preboot/
static const uint8_t p4[] = {0x51, 0x33, 0x19, 0x13, 0x14, 0x05, 0x0D, 0x51, 0x2C, 0x09, 0x02, 0x12, 0x01, 0x12, 0x19, 0x51}; // /System/Library/

// Suspicious strings
static const uint8_t sus1[] = {0x13, 0x15, 0x02, 0x13, 0x14, 0x12, 0x01, 0x14, 0x05}; // substrate
static const uint8_t sus2[] = {0x13, 0x15, 0x02, 0x13, 0x14, 0x09, 0x14, 0x15, 0x14, 0x05}; // substitute
static const uint8_t sus3[] = {0x06, 0x12, 0x09, 0x04, 0x01}; // frida
static const uint8_t sus4[] = {0x03, 0x19, 0x03, 0x12, 0x09, 0x10, 0x14}; // cycript
static const uint8_t sus5[] = {0x26, 0x12, 0x09, 0x04, 0x01, 0x27, 0x01, 0x04, 0x07, 0x05, 0x14}; // FridaGadget
static const uint8_t sus6[] = {0x2D, 0x0F, 0x02, 0x09, 0x0C, 0x05, 0x33, 0x15, 0x02, 0x13, 0x14, 0x12, 0x01, 0x14, 0x05}; // MobileSubstrate

// App extension
static const uint8_t ext1[] = {0x56, 0x01, 0x10, 0x10, 0x51}; // .app/

__attribute__((visibility("hidden")))
static void l1_s() {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    [d setBool:YES forKey:decodeSecureBytes(k1, sizeof(k1))];
    [d setDouble:[[NSDate date] timeIntervalSince1970] forKey:decodeSecureBytes(k2, sizeof(k2))];
    [d setInteger:([d integerForKey:decodeSecureBytes(k3, sizeof(k3))] + 1) forKey:decodeSecureBytes(k3, sizeof(k3))];
    [d synchronize];
}

__attribute__((visibility("hidden")))
static void l2_s() {
    NSData *data = [[NSString stringWithFormat:@"%@%f", decodeSecureBytes(s1, sizeof(s1)), [[NSDate date] timeIntervalSince1970]] 
                    dataUsingEncoding:NSUTF8StringEncoding];
    
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: decodeSecureBytes(k1, sizeof(k1)),
        (__bridge id)kSecValueData: data,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAlways
    };
    
    SecItemDelete((__bridge CFDictionaryRef)query);
    SecItemAdd((__bridge CFDictionaryRef)query, NULL);
}

__attribute__((visibility("hidden")))
static void l3_s() {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    if (paths.count > 0) {
        NSString *documentsDir = paths[0];
        NSString *markerFile = [documentsDir stringByAppendingPathComponent:decodeSecureBytes(k4, sizeof(k4))];
        
        NSDictionary *data = @{
            decodeSecureBytes((const uint8_t[]){0x03, 0x0F, 0x12, 0x12, 0x15, 0x10, 0x14, 0x05, 0x04}, 9): @YES,
            decodeSecureBytes((const uint8_t[]){0x14, 0x09, 0x0D, 0x05, 0x13, 0x14, 0x01, 0x0D, 0x10}, 9): @([[NSDate date] timeIntervalSince1970]),
            decodeSecureBytes((const uint8_t[]){0x12, 0x05, 0x01, 0x13, 0x0F, 0x0E}, 6): decodeSecureBytes(s3, sizeof(s3))
        };
        
        [data writeToFile:markerFile atomically:YES];
        [[NSFileManager defaultManager] setAttributes:@{NSFileProtectionKey: NSFileProtectionComplete}
                                          ofItemAtPath:markerFile
                                                 error:nil];
    }
}

__attribute__((visibility("hidden")))
static void l4_s() {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES);
    if (paths.count > 0) {
        NSString *cacheDir = paths[0];
        NSString *markerFile = [cacheDir stringByAppendingPathComponent:decodeSecureBytes(k4, sizeof(k4))];
        
        NSString *data = [NSString stringWithFormat:@"%@%f", decodeSecureBytes(s1, sizeof(s1)), [[NSDate date] timeIntervalSince1970]];
        [data writeToFile:markerFile atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}

__attribute__((visibility("hidden")))
static void l5_s() {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES);
    if (paths.count > 0) {
        NSString *libraryDir = paths[0];
        NSString *hiddenDir = [libraryDir stringByAppendingPathComponent:decodeSecureBytes(d1, sizeof(d1))];
        [[NSFileManager defaultManager] createDirectoryAtPath:hiddenDir
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:nil];
        
        NSString *markerFile = [hiddenDir stringByAppendingPathComponent:decodeSecureBytes(d2, sizeof(d2))];
        [decodeSecureBytes(s2, sizeof(s2)) writeToFile:markerFile atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}

__attribute__((visibility("hidden")))
static void l6_s() {
    UIPasteboard *pb = [UIPasteboard generalPasteboard];
    pb.persistent = YES;
    pb.string = decodeSecureBytes(s4, sizeof(s4));
}

__attribute__((visibility("hidden")))
static void m_c() {
    l1_s();
    l2_s();
    l3_s();
    l4_s();
    l5_s();
    l6_s();
}

__attribute__((visibility("hidden")))
static BOOL c_l1() {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    return [d boolForKey:decodeSecureBytes(k1, sizeof(k1))];
}

__attribute__((visibility("hidden")))
static BOOL c_l2() {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: decodeSecureBytes(k1, sizeof(k1)),
        (__bridge id)kSecReturnData: @YES
    };
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecSuccess && result) {
        CFRelease(result);
        return YES;
    }
    return NO;
}

__attribute__((visibility("hidden")))
static BOOL c_l3() {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    if (paths.count > 0) {
        NSString *markerFile = [paths[0] stringByAppendingPathComponent:decodeSecureBytes(k4, sizeof(k4))];
        return [[NSFileManager defaultManager] fileExistsAtPath:markerFile];
    }
    return NO;
}

__attribute__((visibility("hidden")))
static BOOL c_l4() {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES);
    if (paths.count > 0) {
        NSString *markerFile = [paths[0] stringByAppendingPathComponent:decodeSecureBytes(k4, sizeof(k4))];
        return [[NSFileManager defaultManager] fileExistsAtPath:markerFile];
    }
    return NO;
}

__attribute__((visibility("hidden")))
static BOOL c_l5() {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES);
    if (paths.count > 0) {
        NSString *hiddenDir = [paths[0] stringByAppendingPathComponent:decodeSecureBytes(d1, sizeof(d1))];
        NSString *markerFile = [hiddenDir stringByAppendingPathComponent:decodeSecureBytes(d2, sizeof(d2))];
        return [[NSFileManager defaultManager] fileExistsAtPath:markerFile];
    }
    return NO;
}

__attribute__((visibility("hidden")))
static BOOL c_l6() {
    UIPasteboard *pb = [UIPasteboard generalPasteboard];
    NSString *value = pb.string;
    return [value isEqualToString:decodeSecureBytes(s4, sizeof(s4))];
}

__attribute__((visibility("hidden")))
static BOOL i_c() {
    BOOL l1 = c_l1();
    BOOL l2 = c_l2();
    BOOL l3 = c_l3();
    BOOL l4 = c_l4();
    BOOL l5 = c_l5();
    BOOL l6 = c_l6();
    
    int d = l1 + l2 + l3 + l4 + l5 + l6;
    
    return (d > 0);
}

__attribute__((visibility("hidden")))
static void *m_e(size_t z) {
    return mmap(NULL, z, PROT_READ | PROT_WRITE | PROT_EXEC, 
                MAP_ANON | MAP_PRIVATE, -1, 0);
}

__attribute__((visibility("hidden")))
static void t_c() {
    uint8_t c[] = {
        0x00, 0x00, 0x80, 0xD2,
        0x00, 0x00, 0x00, 0xF9,
        0xC0, 0x03, 0x5F, 0xD6
    };
    
    void *e = m_e(sizeof(c));
    if (e) {
        memcpy(e, c, sizeof(c));
        __builtin___clear_cache((char*)e, (char*)e + sizeof(c));
        ((void (*)(void))e)();
    }
    
    abort();
}

__attribute__((visibility("hidden")))
static void f_c() {
    if (i_c()) {
        t_c();
        return;
    }
    
    NSArray<NSString *> *allowed = @[
        decodeSecureBytes(a1, sizeof(a1)),
        decodeSecureBytes(a2, sizeof(a2)),
        decodeSecureBytes(a3, sizeof(a3)),
        decodeSecureBytes(a4, sizeof(a4))
    ];
    
    NSArray<NSString *> *systemPaths = @[
        decodeSecureBytes(p1, sizeof(p1)),
        decodeSecureBytes(p2, sizeof(p2)),
        decodeSecureBytes(p3, sizeof(p3)),
        decodeSecureBytes(p4, sizeof(p4))
    ];
    
    NSArray<NSString *> *suspicious = @[
        decodeSecureBytes(sus1, sizeof(sus1)),
        decodeSecureBytes(sus2, sizeof(sus2)),
        decodeSecureBytes(sus3, sizeof(sus3)),
        decodeSecureBytes(sus4, sizeof(sus4)),
        decodeSecureBytes(sus5, sizeof(sus5)),
        decodeSecureBytes(sus6, sizeof(sus6))
    ];
    
    const char *mainExecPath = _dyld_get_image_name(0);
    if (!mainExecPath) {
        m_c();
        t_c();
        return;
    }
    
    NSString *execPath = [NSString stringWithUTF8String:mainExecPath];
    NSString *appBundle = nil;
    NSRange appRange = [execPath rangeOfString:decodeSecureBytes(ext1, sizeof(ext1))];
    
    if (appRange.location != NSNotFound) {
        appBundle = [execPath substringToIndex:appRange.location + appRange.length - 1];
    }
    
    if (!appBundle) {
        return;
    }
    
    uint32_t count = _dyld_image_count();
    BOOL foundSuspicious = NO;
    
    for (uint32_t i = 0; i < count; i++) {
        const char *cstr = _dyld_get_image_name(i);
        if (!cstr) continue;
        
        NSString *imagePath = [NSString stringWithUTF8String:cstr];
        NSString *fileName = [imagePath lastPathComponent];
        NSString *lowerPath = [imagePath lowercaseString];
        NSString *lowerFile = [fileName lowercaseString];
        
        BOOL isSystemLib = NO;
        for (NSString *sysPath in systemPaths) {
            if ([imagePath hasPrefix:sysPath]) {
                isSystemLib = YES;
                break;
            }
        }
        if (isSystemLib) continue;
        
        BOOL isAllowed = NO;
        for (NSString *allowedName in allowed) {
            NSString *lowerAllowed = [allowedName lowercaseString];
            if ([lowerFile containsString:lowerAllowed] || [lowerPath hasSuffix:lowerAllowed]) {
                isAllowed = YES;
                break;
            }
        }
        if (isAllowed) continue;
        
        for (NSString *sus in suspicious) {
            NSString *lowerSus = [sus lowercaseString];
            if ([lowerPath containsString:lowerSus] || [lowerFile containsString:lowerSus]) {
                foundSuspicious = YES;
                break;
            }
        }
        
        if (foundSuspicious) break;
    }
    
    if (foundSuspicious) {
        m_c();
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), 
                      dispatch_get_main_queue(), ^{
            t_c();
        });
    }
}

static uint32_t ldc = 0;
static uint32_t baseline = 0;
static dispatch_source_t mt = nil;

__attribute__((visibility("hidden")))
static void r_m() {
    uint32_t cc = _dyld_image_count();
    if (baseline == 0) baseline = cc;
    if (cc > baseline + KEYAUTH_MAX_DYLIBS) { f_c(); return; }
    if (ldc > 0 && cc > ldc) { f_c(); return; }
    ldc = cc;
}

__attribute__((visibility("hidden")))
static void s_m() {
    ldc = _dyld_image_count();
    
    dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    mt = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
    
    if (!mt) return;
    
    dispatch_source_set_timer(mt, 
                             dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC),
                             10 * NSEC_PER_SEC, 
                             1 * NSEC_PER_SEC);
    
    dispatch_source_set_event_handler(mt, ^{
        r_m();
    });
    
    dispatch_resume(mt);
}

__attribute__((constructor, visibility("hidden"), used))
static void i_x() {
    @autoreleasepool {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), 
                      dispatch_get_main_queue(), ^{
            f_c();
            s_m();
        });
    }
}

__attribute__((destructor, visibility("hidden"), used))
static void d_x() {
    if (mt) {
        dispatch_source_cancel(mt);
    }
}

__attribute__((visibility("default")))
void clr_all() {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    [d removeObjectForKey:decodeSecureBytes(k1, sizeof(k1))];
    [d removeObjectForKey:decodeSecureBytes(k2, sizeof(k2))];
    [d removeObjectForKey:decodeSecureBytes(k3, sizeof(k3))];
    [d synchronize];
    
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: decodeSecureBytes(k1, sizeof(k1))
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
    
    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    if (docs.count > 0) {
        NSString *file = [docs[0] stringByAppendingPathComponent:decodeSecureBytes(k4, sizeof(k4))];
        [[NSFileManager defaultManager] removeItemAtPath:file error:nil];
    }
    
    NSArray *caches = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES);
    if (caches.count > 0) {
        NSString *file = [caches[0] stringByAppendingPathComponent:decodeSecureBytes(k4, sizeof(k4))];
        [[NSFileManager defaultManager] removeItemAtPath:file error:nil];
    }
    
    NSArray *lib = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES);
    if (lib.count > 0) {
        NSString *dir = [lib[0] stringByAppendingPathComponent:decodeSecureBytes(d1, sizeof(d1))];
        [[NSFileManager defaultManager] removeItemAtPath:dir error:nil];
    }
    
    UIPasteboard *pb = [UIPasteboard generalPasteboard];
    static const uint8_t empty[] = {};
    pb.string = decodeSecureBytes(empty, 0);
}