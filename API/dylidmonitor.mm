// DyldMonitor.mm
#import "dylidmonitor.h"
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/utsname.h>
#import "SecureMap.h"

// ============================================
// ENCRYPTED STRING DATA
// ============================================

// "https://fluckv2.org/server.php"
static const uint8_t encrypted_SERVER_URL[] = {
    0x08, 0x14, 0x14, 0x10, 0x13, 0x58, 0x51, 0x51, 0x06, 0x0C, 0x15, 0x03,
    0x0B, 0x16, 0x43, 0x56, 0x0F, 0x12, 0x07, 0x51, 0x13, 0x05, 0x12, 0x16,
    0x05, 0x12, 0x56, 0x10, 0x08, 0x10
};

// "@IamGayBecauseYouAreSexy"
static const uint8_t encrypted_SECRET_PASSWORD[] = {
    0x5D, 0x29, 0x01, 0x0D, 0x27, 0x01, 0x19, 0x22, 0x05, 0x03, 0x01, 0x15,
    0x13, 0x05, 0x39, 0x0F, 0x15, 0x21, 0x12, 0x05, 0x33, 0x05, 0x18, 0x19
};

// "MobileSubstrate"
static const uint8_t encrypted_STR_MOBSUB[] = {
    0x2D, 0x0F, 0x02, 0x09, 0x0C, 0x05, 0x33, 0x15, 0x02, 0x13, 0x14, 0x12, 0x01, 0x14, 0x05
};

// "CydiaSubstrate"
static const uint8_t encrypted_STR_CYDSUB[] = {
    0x23, 0x19, 0x04, 0x09, 0x01, 0x33, 0x15, 0x02, 0x13, 0x14, 0x12, 0x01, 0x14, 0x05
};

// "libsubstrate"
static const uint8_t encrypted_STR_LIBSUB[] = {
    0x0C, 0x09, 0x02, 0x13, 0x15, 0x02, 0x13, 0x14, 0x12, 0x01, 0x14, 0x05
};

// "Liberty"
static const uint8_t encrypted_STR_LIBERTY[] = {
    0x2C, 0x09, 0x02, 0x05, 0x12, 0x14, 0x19
};

// "FlyJB"
static const uint8_t encrypted_STR_FLYJB[] = {
    0x26, 0x0C, 0x19, 0x2A, 0x22
};

// "A-Bypass"
static const uint8_t encrypted_STR_ABYPASS[] = {
    0x21, 0x54, 0x22, 0x19, 0x10, 0x01, 0x13, 0x13
};

// "Shadow"
static const uint8_t encrypted_STR_SHADOW[] = {
    0x33, 0x08, 0x01, 0x04, 0x0F, 0x17
};

// "vnodebypass"
static const uint8_t encrypted_STR_VNODE[] = {
    0x16, 0x0E, 0x0F, 0x04, 0x05, 0x02, 0x19, 0x10, 0x01, 0x13, 0x13
};

// "libhooker"
static const uint8_t encrypted_STR_LIBHOOK[] = {
    0x0C, 0x09, 0x02, 0x08, 0x0F, 0x0F, 0x0B, 0x05, 0x12
};

// "substitute"
static const uint8_t encrypted_STR_SUBSTITUTE[] = {
    0x13, 0x15, 0x02, 0x13, 0x14, 0x09, 0x14, 0x15, 0x14, 0x05
};

// "libprefs"
static const uint8_t encrypted_STR_LIBPREFS[] = {
    0x0C, 0x09, 0x02, 0x10, 0x12, 0x05, 0x06, 0x13
};

// "/Library/MobileSubstrate"
static const uint8_t encrypted_PATH_MOBSUB[] = {
    0x51, 0x2C, 0x09, 0x02, 0x12, 0x01, 0x12, 0x19, 0x51, 0x2D, 0x0F, 0x02, 0x09, 0x0C, 0x05, 0x33, 0x15, 0x02, 0x13, 0x14, 0x12, 0x01, 0x14, 0x05
};

// "/usr/lib/substrate"
static const uint8_t encrypted_PATH_USRLIB[] = {
    0x51, 0x15, 0x13, 0x12, 0x51, 0x0C, 0x09, 0x02, 0x51, 0x13, 0x15, 0x02, 0x13, 0x14, 0x12, 0x01, 0x14, 0x05
};

// "/var/jb"
static const uint8_t encrypted_PATH_VARJB[] = {
    0x51, 0x16, 0x01, 0x12, 0x51, 0x0A, 0x02
};

// "/cores/binpack"
static const uint8_t encrypted_PATH_CORES[] = {
    0x51, 0x03, 0x0F, 0x12, 0x05, 0x13, 0x51, 0x02, 0x09, 0x0E, 0x10, 0x01, 0x03, 0x0B
};

// "/var/lib/cydia"
static const uint8_t encrypted_PATH_CYDIA[] = {
    0x51, 0x16, 0x01, 0x12, 0x51, 0x0C, 0x09, 0x02, 0x51, 0x03, 0x19, 0x04, 0x09, 0x01
};

// "/etc/apt"
static const uint8_t encrypted_PATH_APT[] = {
    0x51, 0x05, 0x14, 0x03, 0x51, 0x01, 0x10, 0x14
};

// "/private/var/lib/apt"
static const uint8_t encrypted_PATH_PRIVAPT[] = {
    0x51, 0x10, 0x12, 0x09, 0x16, 0x01, 0x14, 0x05, 0x51, 0x16, 0x01, 0x12, 0x51, 0x0C, 0x09, 0x02, 0x51, 0x01, 0x10, 0x14
};

// "/bin/bash"
static const uint8_t encrypted_PATH_BASH[] = {
    0x51, 0x02, 0x09, 0x0E, 0x51, 0x02, 0x01, 0x13, 0x08
};

// "/usr/sbin/sshd"
static const uint8_t encrypted_PATH_SSHD[] = {
    0x51, 0x15, 0x13, 0x12, 0x51, 0x13, 0x02, 0x09, 0x0E, 0x51, 0x13, 0x13, 0x08, 0x04
};

// "/usr/bin/ssh"
static const uint8_t encrypted_PATH_SSH[] = {
    0x51, 0x15, 0x13, 0x12, 0x51, 0x02, 0x09, 0x0E, 0x51, 0x13, 0x13, 0x08
};

// "/var/cache/apt"
static const uint8_t encrypted_PATH_CACHE[] = {
    0x51, 0x16, 0x01, 0x12, 0x51, 0x03, 0x01, 0x03, 0x08, 0x05, 0x51, 0x01, 0x10, 0x14
};

// "/var/lib/dpkg"
static const uint8_t encrypted_PATH_DPKG[] = {
    0x51, 0x16, 0x01, 0x12, 0x51, 0x0C, 0x09, 0x02, 0x51, 0x04, 0x10, 0x0B, 0x07
};

// "/var/tmp/cydia.log"
static const uint8_t encrypted_PATH_CYDLOG[] = {
    0x51, 0x16, 0x01, 0x12, 0x51, 0x14, 0x0D, 0x10, 0x51, 0x03, 0x19, 0x04, 0x09, 0x01, 0x56, 0x0C, 0x0F, 0x07
};

// "/private/var/containers/Bundle/Application/"
static const uint8_t encrypted_PATH_BUNDLE1[] = {
    0x51, 0x10, 0x12, 0x09, 0x16, 0x01, 0x14, 0x05, 0x51, 0x16, 0x01, 0x12, 0x51, 0x03, 0x0F, 0x0E, 0x14, 0x01, 0x09, 0x0E, 0x05, 0x12, 0x13, 0x51, 0x22, 0x15, 0x0E, 0x04, 0x0C, 0x05, 0x51, 0x21, 0x10, 0x10, 0x0C, 0x09, 0x03, 0x01, 0x14, 0x09, 0x0F, 0x0E, 0x51
};

// "/var/containers/Bundle/Application/"
static const uint8_t encrypted_PATH_BUNDLE2[] = {
    0x51, 0x16, 0x01, 0x12, 0x51, 0x03, 0x0F, 0x0E, 0x14, 0x01, 0x09, 0x0E, 0x05, 0x12, 0x13, 0x51, 0x22, 0x15, 0x0E, 0x04, 0x0C, 0x05, 0x51, 0x21, 0x10, 0x10, 0x0C, 0x09, 0x03, 0x01, 0x14, 0x09, 0x0F, 0x0E, 0x51
};

// "No UDID provided"
static const uint8_t encrypted_ERR_NOUDID[] = {
    0x2E, 0x0F, 0x6F, 0x35, 0x24, 0x29, 0x24, 0x6F, 0x10, 0x12, 0x0F, 0x16, 0x09, 0x04, 0x05, 0x04
};

// "Failed to create JSON"
static const uint8_t encrypted_ERR_JSON[] = {
    0x26, 0x01, 0x09, 0x0C, 0x05, 0x04, 0x6F, 0x14, 0x0F, 0x6F, 0x03, 0x12, 0x05, 0x01, 0x14, 0x05, 0x6F, 0x2A, 0x33, 0x2F, 0x2E
};

// "Network error"
static const uint8_t encrypted_ERR_NETWORK[] = {
    0x2E, 0x05, 0x14, 0x17, 0x0F, 0x12, 0x0B, 0x6F, 0x05, 0x12, 0x12, 0x0F, 0x12
};

// "Unknown"
static const uint8_t encrypted_STR_UNKNOWN[] = {
    0x35, 0x0E, 0x0B, 0x0E, 0x0F, 0x17, 0x0E
};

// "CFBundleShortVersionString"
static const uint8_t encrypted_KEY_APPVER[] = {
    0x23, 0x26, 0x22, 0x15, 0x0E, 0x04, 0x0C, 0x05, 0x33, 0x08, 0x0F, 0x12, 0x14, 0x36, 0x05, 0x12, 0x13, 0x09, 0x0F, 0x0E, 0x33, 0x14, 0x12, 0x09, 0x0E, 0x07
};

// "CFBundleVersion"
static const uint8_t encrypted_KEY_APPBUILD[] = {
    0x23, 0x26, 0x22, 0x15, 0x0E, 0x04, 0x0C, 0x05, 0x36, 0x05, 0x12, 0x13, 0x09, 0x0F, 0x0E
};

// "application/json"
static const uint8_t encrypted_CONTENT_TYPE[] = {
    0x01, 0x10, 0x10, 0x0C, 0x09, 0x03, 0x01, 0x14, 0x09, 0x0F, 0x0E, 0x51, 0x0A, 0x13, 0x0F, 0x0E
};

// "Content-Type"
static const uint8_t encrypted_HEADER_CT[] = {
    0x23, 0x0F, 0x0E, 0x14, 0x05, 0x0E, 0x14, 0x54, 0x34, 0x19, 0x10, 0x05
};

// "POST"
static const uint8_t encrypted_METHOD_POST[] = {
    0x30, 0x2F, 0x33, 0x34
};

// ============================================
// DECRYPTION FUNCTIONS
// ============================================

static NSString* _dyldDecryptSecretPassword() {
    static NSString *cached = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cached = decodeSecureBytes(encrypted_SECRET_PASSWORD, sizeof(encrypted_SECRET_PASSWORD));
    });
    return cached;
}

static NSString* _dyldDecryptServerURL() {
    static NSString *cached = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cached = decodeSecureBytes(encrypted_SERVER_URL, sizeof(encrypted_SERVER_URL));
    });
    return cached;
}

static NSArray* _dyldDecryptSuspiciousPrefixes() {
    static NSArray *cached = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cached = @[
            decodeSecureBytes(encrypted_STR_MOBSUB, sizeof(encrypted_STR_MOBSUB)),
            decodeSecureBytes(encrypted_STR_CYDSUB, sizeof(encrypted_STR_CYDSUB)),
            decodeSecureBytes(encrypted_STR_LIBSUB, sizeof(encrypted_STR_LIBSUB)),
            decodeSecureBytes(encrypted_STR_LIBERTY, sizeof(encrypted_STR_LIBERTY)),
            decodeSecureBytes(encrypted_STR_FLYJB, sizeof(encrypted_STR_FLYJB)),
            decodeSecureBytes(encrypted_STR_ABYPASS, sizeof(encrypted_STR_ABYPASS)),
            decodeSecureBytes(encrypted_STR_SHADOW, sizeof(encrypted_STR_SHADOW)),
            decodeSecureBytes(encrypted_STR_VNODE, sizeof(encrypted_STR_VNODE)),
            decodeSecureBytes(encrypted_STR_LIBHOOK, sizeof(encrypted_STR_LIBHOOK)),
            decodeSecureBytes(encrypted_STR_SUBSTITUTE, sizeof(encrypted_STR_SUBSTITUTE)),
            decodeSecureBytes(encrypted_STR_LIBPREFS, sizeof(encrypted_STR_LIBPREFS))
        ];
    });
    return cached;
}

static NSArray* _dyldDecryptJailbreakPaths() {
    static NSArray *cached = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cached = @[
            decodeSecureBytes(encrypted_PATH_MOBSUB, sizeof(encrypted_PATH_MOBSUB)),
            decodeSecureBytes(encrypted_PATH_USRLIB, sizeof(encrypted_PATH_USRLIB)),
            decodeSecureBytes(encrypted_PATH_VARJB, sizeof(encrypted_PATH_VARJB)),
            decodeSecureBytes(encrypted_PATH_CORES, sizeof(encrypted_PATH_CORES)),
            decodeSecureBytes(encrypted_PATH_CYDIA, sizeof(encrypted_PATH_CYDIA)),
            decodeSecureBytes(encrypted_PATH_APT, sizeof(encrypted_PATH_APT)),
            decodeSecureBytes(encrypted_PATH_PRIVAPT, sizeof(encrypted_PATH_PRIVAPT)),
            decodeSecureBytes(encrypted_PATH_BASH, sizeof(encrypted_PATH_BASH)),
            decodeSecureBytes(encrypted_PATH_SSHD, sizeof(encrypted_PATH_SSHD)),
            decodeSecureBytes(encrypted_PATH_SSH, sizeof(encrypted_PATH_SSH)),
            decodeSecureBytes(encrypted_PATH_CACHE, sizeof(encrypted_PATH_CACHE)),
            decodeSecureBytes(encrypted_PATH_DPKG, sizeof(encrypted_PATH_DPKG)),
            decodeSecureBytes(encrypted_PATH_CYDLOG, sizeof(encrypted_PATH_CYDLOG))
        ];
    });
    return cached;
}

// ============================================
// DYLD MONITOR IMPLEMENTATION
// ============================================

@interface DyldMonitor()
@property (nonatomic, strong) NSArray<NSString *> *cachedDyldList;
@property (nonatomic, assign) NSTimeInterval lastScanTime;
@end

@implementation DyldMonitor

+ (instancetype)shared {
    static DyldMonitor *instance = nil;
    static dispatch_once_t token;
    dispatch_once(&token, ^{
        instance = [[DyldMonitor alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _lastScanTime = 0;
        _cachedDyldList = @[];
        [self scanDyldList];
    }
    return self;
}

- (NSArray<NSString *> *)getLoadedDylibs {
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if (now - _lastScanTime < 5.0 && _cachedDyldList.count > 0) {
        return _cachedDyldList;
    }
    
    return [self scanDyldList];
}

- (NSArray<NSString *> *)scanDyldList {
    NSMutableArray<NSString *> *dylibs = [NSMutableArray array];
    
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (imageName) {
            NSString *dylibPath = [NSString stringWithUTF8String:imageName];
            if (dylibPath) {
                [dylibs addObject:dylibPath];
            }
        }
    }
    
    _cachedDyldList = [dylibs copy];
    _lastScanTime = [[NSDate date] timeIntervalSince1970];
    
    return _cachedDyldList;
}

- (NSArray<NSString *> *)getAppBundleDylibs {
    NSArray<NSString *> *allDylibs = [self getLoadedDylibs];
    NSMutableArray<NSString *> *appBundleDylibs = [NSMutableArray array];
    
    NSString *bundlePath1 = decodeSecureBytes(encrypted_PATH_BUNDLE1, sizeof(encrypted_PATH_BUNDLE1));
    NSString *bundlePath2 = decodeSecureBytes(encrypted_PATH_BUNDLE2, sizeof(encrypted_PATH_BUNDLE2));
    
    for (NSString *dylib in allDylibs) {
        if ([dylib containsString:bundlePath1] || [dylib containsString:bundlePath2]) {
            [appBundleDylibs addObject:dylib];
        }
    }
    
    return [appBundleDylibs copy];
}

- (NSArray<NSString *> *)getSuspiciousDylibs {
    NSArray<NSString *> *allDylibs = [self getLoadedDylibs];
    NSMutableArray<NSString *> *suspicious = [NSMutableArray array];
    
    NSArray *suspiciousPrefixes = _dyldDecryptSuspiciousPrefixes();
    NSArray *jailbreakPaths = _dyldDecryptJailbreakPaths();
    
    for (NSString *dylib in allDylibs) {
        NSString *dylibLower = [dylib lowercaseString];
        
        // Check suspicious prefixes
        for (NSString *prefix in suspiciousPrefixes) {
            NSString *prefixLower = [prefix lowercaseString];
            if ([dylibLower containsString:prefixLower]) {
                [suspicious addObject:dylib];
                break;
            }
        }
        
        // Check for jailbreak paths
        for (NSString *jbPath in jailbreakPaths) {
            if ([dylib containsString:jbPath]) {
                [suspicious addObject:dylib];
                break;
            }
        }
    }
    
    return [suspicious copy];
}

- (BOOL)isInjected {
    return [self getSuspiciousDylibs].count > 0;
}

- (NSString *)sha256:(NSString *)input {
    if (!input) return @"";
    
    const char *cstr = [input UTF8String];
    if (!cstr) return @"";
    
    NSData *data = [NSData dataWithBytes:cstr length:strlen(cstr)];
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, hash);
    
    NSMutableString *output = [NSMutableString string];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", hash[i]];
    }
    
    return output;
}

- (void)sendDyldListToServer:(NSString *)udid completion:(void(^)(BOOL success, NSString *error))completion {
    [self sendDyldListToServerWithInfo:udid licenseKey:nil completion:completion];
}

- (void)sendDyldListToServerWithInfo:(NSString *)udid 
                         licenseKey:(NSString *)licenseKey 
                         completion:(void(^)(BOOL success, NSString *error))completion {
    
    if (!udid || udid.length == 0) {
        if (completion) {
            NSString *errMsg = decodeSecureBytes(encrypted_ERR_NOUDID, sizeof(encrypted_ERR_NOUDID));
            completion(NO, errMsg);
        }
        return;
    }
    
    NSArray<NSString *> *appBundleDylibs = [self getAppBundleDylibs];
    NSArray<NSString *> *suspicious = [self getSuspiciousDylibs];
    NSArray<NSString *> *allDylibs = [self getLoadedDylibs];
    
    NSTimeInterval timestamp = [[NSDate date] timeIntervalSince1970];
    NSInteger ts = (NSInteger)timestamp;
    
    NSString *challengeInput = [NSString stringWithFormat:@"%@%ld%@", udid, (long)ts, _dyldDecryptSecretPassword()];
    NSString *challenge = [self sha256:challengeInput];
    
    struct utsname info;
    uname(&info);
    NSString *deviceModel = [NSString stringWithCString:info.machine encoding:NSUTF8StringEncoding];
    
    NSString *unknownStr = decodeSecureBytes(encrypted_STR_UNKNOWN, sizeof(encrypted_STR_UNKNOWN));
    NSString *systemVersion = unknownStr;
    NSString *deviceName = unknownStr;
    
    if (NSClassFromString(@"UIDevice")) {
        UIDevice *device = [UIDevice currentDevice];
        systemVersion = [device systemVersion] ?: unknownStr;
        deviceName = [device name] ?: unknownStr;
    }
    
    NSString *appVersionKey = decodeSecureBytes(encrypted_KEY_APPVER, sizeof(encrypted_KEY_APPVER));
    NSString *appBuildKey = decodeSecureBytes(encrypted_KEY_APPBUILD, sizeof(encrypted_KEY_APPBUILD));
    NSString *appVersion = [[NSBundle mainBundle] objectForInfoDictionaryKey:appVersionKey] ?: unknownStr;
    NSString *appBuild = [[NSBundle mainBundle] objectForInfoDictionaryKey:appBuildKey] ?: unknownStr;
    
    NSMutableDictionary *payload = [@{
        @"password": challenge ?: @"",
        @"udid": udid ?: @"",
        @"timestamp": @(ts),
        @"dyld_list": appBundleDylibs ?: @[],
        @"suspicious_count": @(suspicious.count),
        @"suspicious_dylibs": suspicious ?: @[],
        @"device_info": @{
            @"model": deviceModel ?: unknownStr,
            @"system_version": systemVersion,
            @"device_name": deviceName,
            @"app_version": appVersion,
            @"app_build": appBuild,
            @"is_injected": @([self isInjected]),
            @"total_dylibs": @(allDylibs.count),
            @"app_bundle_dylibs": @(appBundleDylibs.count),
            @"process_name": [[NSProcessInfo processInfo] processName] ?: unknownStr,
            @"process_id": @(getpid())
        }
    } mutableCopy];
    
    if (licenseKey && licenseKey.length > 0) {
        payload[@"license_key"] = licenseKey;
    }
    
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
    if (!jsonData) {
        if (completion) {
            NSString *errMsg = decodeSecureBytes(encrypted_ERR_JSON, sizeof(encrypted_ERR_JSON));
            completion(NO, errMsg);
        }
        return;
    }
    
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:_dyldDecryptServerURL()]];
    NSString *methodPost = decodeSecureBytes(encrypted_METHOD_POST, sizeof(encrypted_METHOD_POST));
    NSString *contentType = decodeSecureBytes(encrypted_CONTENT_TYPE, sizeof(encrypted_CONTENT_TYPE));
    NSString *headerCT = decodeSecureBytes(encrypted_HEADER_CT, sizeof(encrypted_HEADER_CT));
    
    [request setHTTPMethod:methodPost];
    [request setValue:contentType forHTTPHeaderField:headerCT];
    [request setHTTPBody:jsonData];
    [request setTimeoutInterval:15];
    
    [[[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error || !data) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) {
                    NSString *errMsg = decodeSecureBytes(encrypted_ERR_NETWORK, sizeof(encrypted_ERR_NETWORK));
                    completion(NO, errMsg);
                }
            });
            return;
        }
        
        NSError *jsonError;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(YES, nil);
        });
        
    }] resume];
}

@end