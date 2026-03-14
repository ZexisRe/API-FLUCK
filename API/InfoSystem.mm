// InfoSystem.mm
#import "infosystem.h"
#import <UIKit/UIKit.h>
#import <sys/utsname.h>
#import <sys/sysctl.h>
#import <mach-o/dyld.h>
#import <CommonCrypto/CommonDigest.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <netinet/in.h>
#import <ifaddrs.h>
#import <arpa/inet.h>
#import "SecureMap.h"

// ============================================
// ENCRYPTED STRING DATA (Embedded in this file)
// ============================================

// Encrypted: "https://fluckv2.org/server.php"
static const uint8_t encrypted_SERVER_URL[] = {
    0x08, 0x14, 0x14, 0x10, 0x13, 0x58, 0x51, 0x51, 0x06, 0x0C, 0x15, 0x03,
    0x0B, 0x16, 0x43, 0x56, 0x0F, 0x12, 0x07, 0x51, 0x13, 0x05, 0x12, 0x16,
    0x05, 0x12, 0x56, 0x10, 0x08, 0x10
};

// Encrypted: "@IamGayBecauseYouAreSexy"
static const uint8_t encrypted_SECRET_PASSWORD[] = {
    0x5D, 0x29, 0x01, 0x0D, 0x27, 0x01, 0x19, 0x22, 0x05, 0x03, 0x01, 0x15,
    0x13, 0x05, 0x39, 0x0F, 0x15, 0x21, 0x12, 0x05, 0x33, 0x05, 0x18, 0x19
};

// ============================================
// LOCAL DECRYPTION FUNCTIONS
// ============================================

static NSString* _infoDecryptServerURL() {
    static NSString *cached = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cached = decodeSecureBytes(encrypted_SERVER_URL, sizeof(encrypted_SERVER_URL));
    });
    return cached;
}

static NSString* _infoDecryptSecretPassword() {
    static NSString *cached = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cached = decodeSecureBytes(encrypted_SECRET_PASSWORD, sizeof(encrypted_SECRET_PASSWORD));
    });
    return cached;
}

// ============================================
// ORIGINAL CODE CONTINUES HERE
// ============================================

@interface InfoSystem()
@property (nonatomic, strong) NSDateFormatter *dateFormatter;
@end

@implementation InfoSystem

+ (instancetype)shared {
    static InfoSystem *instance = nil;
    static dispatch_once_t token;
    dispatch_once(&token, ^{
        instance = [[InfoSystem alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _dateFormatter = [[NSDateFormatter alloc] init];
        [_dateFormatter setDateFormat:@"yyyy-MM-dd HH:mm:ss"];
    }
    return self;
}

- (NSDictionary *)collectDeviceInfo {
    struct utsname info;
    uname(&info);
    
    NSMutableDictionary *deviceInfo = [NSMutableDictionary dictionary];
    
    // Basic device info
    deviceInfo[@"machine"] = [NSString stringWithCString:info.machine encoding:NSUTF8StringEncoding] ?: @"Unknown";
    deviceInfo[@"nodename"] = [NSString stringWithCString:info.nodename encoding:NSUTF8StringEncoding] ?: @"Unknown";
    deviceInfo[@"release"] = [NSString stringWithCString:info.release encoding:NSUTF8StringEncoding] ?: @"Unknown";
    deviceInfo[@"version"] = [NSString stringWithCString:info.version encoding:NSUTF8StringEncoding] ?: @"Unknown";
    deviceInfo[@"sysname"] = [NSString stringWithCString:info.sysname encoding:NSUTF8StringEncoding] ?: @"Unknown";
    
    // Runtime UIKit availability check
    if (NSClassFromString(@"UIDevice")) {
        UIDevice *device = [UIDevice currentDevice];
        deviceInfo[@"system_name"] = device.systemName ?: @"Unknown";
        deviceInfo[@"system_version"] = device.systemVersion ?: @"Unknown";
        deviceInfo[@"device_name"] = device.name ?: @"Unknown";
        deviceInfo[@"model"] = device.model ?: @"Unknown";
        deviceInfo[@"localized_model"] = device.localizedModel ?: @"Unknown";
        deviceInfo[@"user_interface_idiom"] = @(device.userInterfaceIdiom);
        
        // Battery info
        device.batteryMonitoringEnabled = YES;
        deviceInfo[@"battery_level"] = @(device.batteryLevel);
        deviceInfo[@"battery_state"] = @(device.batteryState);
        deviceInfo[@"proximity_monitoring"] = @(device.proximityMonitoringEnabled);
    }
    
    // Process info
    NSProcessInfo *processInfo = [NSProcessInfo processInfo];
    deviceInfo[@"process_name"] = processInfo.processName ?: @"Unknown";
    deviceInfo[@"process_id"] = @(getpid());
    deviceInfo[@"host_name"] = processInfo.hostName ?: @"Unknown";
    deviceInfo[@"operating_system"] = @(processInfo.operatingSystem);
    deviceInfo[@"operating_system_version"] = processInfo.operatingSystemVersionString ?: @"Unknown";
    deviceInfo[@"physical_memory"] = @(processInfo.physicalMemory);
    deviceInfo[@"processor_count"] = @(processInfo.processorCount);
    deviceInfo[@"active_processor_count"] = @(processInfo.activeProcessorCount);
    deviceInfo[@"system_uptime"] = @(processInfo.systemUptime);
    
    // Disk space
    NSDictionary *fileAttrs = [[NSFileManager defaultManager] attributesOfFileSystemForPath:NSHomeDirectory() error:nil];
    deviceInfo[@"total_disk_space"] = fileAttrs[NSFileSystemSize] ?: @0;
    deviceInfo[@"free_disk_space"] = fileAttrs[NSFileSystemFreeSize] ?: @0;
    
    // Time info
    deviceInfo[@"local_time"] = [self.dateFormatter stringFromDate:[NSDate date]];
    deviceInfo[@"timezone"] = [[NSTimeZone systemTimeZone] name] ?: @"Unknown";
    deviceInfo[@"timezone_offset"] = @([[NSTimeZone systemTimeZone] secondsFromGMT]);
    
    // Jailbreak detection
    deviceInfo[@"is_jailbroken"] = @([self checkJailbreak]);
    
    return [deviceInfo copy];
}

- (NSDictionary *)collectAppInfo {
    NSBundle *mainBundle = [NSBundle mainBundle];
    NSDictionary *infoDict = [mainBundle infoDictionary];
    
    NSMutableDictionary *appInfo = [NSMutableDictionary dictionary];
    
    // Basic app info
    appInfo[@"bundle_identifier"] = [mainBundle bundleIdentifier] ?: @"Unknown";
    appInfo[@"app_version"] = infoDict[@"CFBundleShortVersionString"] ?: @"Unknown";
    appInfo[@"app_build"] = infoDict[@"CFBundleVersion"] ?: @"Unknown";
    appInfo[@"app_name"] = infoDict[@"CFBundleName"] ?: @"Unknown";
    appInfo[@"executable_name"] = infoDict[@"CFBundleExecutable"] ?: @"Unknown";
    appInfo[@"minimum_os_version"] = infoDict[@"MinimumOSVersion"] ?: @"Unknown";
    
    // Paths
    appInfo[@"bundle_path"] = [mainBundle bundlePath] ?: @"Unknown";
    appInfo[@"executable_path"] = [mainBundle executablePath] ?: @"Unknown";
    appInfo[@"resource_path"] = [mainBundle resourcePath] ?: @"Unknown";
    
    // File info
    NSArray *bundleFiles = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:[mainBundle bundlePath] error:nil];
    appInfo[@"bundle_files_count"] = @(bundleFiles.count);
    
    // Dyld info
    uint32_t dyldCount = _dyld_image_count();
    appInfo[@"dyld_count"] = @(dyldCount);
    
    // Collect first 20 dylibs (avoid too much data)
    NSMutableArray *firstDylibs = [NSMutableArray array];
    for (uint32_t i = 0; i < MIN(dyldCount, 20); i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (imageName) {
            NSString *dylibPath = [NSString stringWithUTF8String:imageName];
            if (dylibPath) {
                [firstDylibs addObject:dylibPath];
            }
        }
    }
    appInfo[@"first_dylibs"] = firstDylibs;
    
    // Executable hash
    NSString *executablePath = [mainBundle executablePath];
    NSString *executableHash = [self fileSHA256:executablePath];
    appInfo[@"executable_hash"] = executableHash ?: @"Unknown";
    
    // Info.plist hash
    NSString *infoPlistPath = [[mainBundle bundlePath] stringByAppendingPathComponent:@"Info.plist"];
    NSString *infoPlistHash = [self fileSHA256:infoPlistPath];
    appInfo[@"infoplist_hash"] = infoPlistHash ?: @"Unknown";
    
    return [appInfo copy];
}

- (NSDictionary *)collectNetworkInfo {
    NSMutableDictionary *networkInfo = [NSMutableDictionary dictionary];
    
    // Carrier info (if available)
    if (NSClassFromString(@"CTTelephonyNetworkInfo")) {
        @try {
            CTTelephonyNetworkInfo *telephonyInfo = [[CTTelephonyNetworkInfo alloc] init];
            CTCarrier *carrier = [telephonyInfo subscriberCellularProvider];
            
            if (carrier) {
                networkInfo[@"carrier_name"] = carrier.carrierName ?: @"Unknown";
                networkInfo[@"carrier_country"] = carrier.isoCountryCode ?: @"Unknown";
                networkInfo[@"carrier_code"] = carrier.mobileNetworkCode ?: @"Unknown";
                networkInfo[@"carrier_allows_voip"] = @(carrier.allowsVOIP);
            }
            
            // Current radio technology
            NSString *radioTech = telephonyInfo.currentRadioAccessTechnology;
            networkInfo[@"radio_technology"] = radioTech ?: @"Unknown";
        } @catch (NSException *exception) {
            networkInfo[@"carrier_error"] = exception.reason ?: @"Unknown";
        }
    }
    
    // Network status using SystemConfiguration
    struct sockaddr_in zeroAddress;
    bzero(&zeroAddress, sizeof(zeroAddress));
    zeroAddress.sin_len = sizeof(zeroAddress);
    zeroAddress.sin_family = AF_INET;
    
    SCNetworkReachabilityRef reachability = SCNetworkReachabilityCreateWithAddress(kCFAllocatorDefault, (const struct sockaddr *)&zeroAddress);
    if (reachability) {
        SCNetworkReachabilityFlags flags;
        if (SCNetworkReachabilityGetFlags(reachability, &flags)) {
            networkInfo[@"is_reachable"] = @((flags & kSCNetworkReachabilityFlagsReachable) != 0);
            networkInfo[@"is_wwan"] = @((flags & kSCNetworkReachabilityFlagsIsWWAN) != 0);
            networkInfo[@"connection_required"] = @((flags & kSCNetworkReachabilityFlagsConnectionRequired) != 0);
            networkInfo[@"intervention_required"] = @((flags & kSCNetworkReachabilityFlagsInterventionRequired) != 0);
        }
        CFRelease(reachability);
    }
    
    // IP addresses
    NSMutableArray *ipAddresses = [NSMutableArray array];
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) == 0) {
        struct ifaddrs *temp = interfaces;
        while (temp != NULL) {
            if (temp->ifa_addr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                struct sockaddr_in *addr = (struct sockaddr_in *)temp->ifa_addr;
                inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
                [ipAddresses addObject:@{
                    @"interface": [NSString stringWithUTF8String:temp->ifa_name] ?: @"Unknown",
                    @"ip": [NSString stringWithUTF8String:ip] ?: @"Unknown"
                }];
            }
            temp = temp->ifa_next;
        }
        freeifaddrs(interfaces);
    }
    networkInfo[@"ip_addresses"] = ipAddresses;
    
    // Host info
    networkInfo[@"host_name"] = [[NSProcessInfo processInfo] hostName] ?: @"Unknown";
    
    return [networkInfo copy];
}

- (NSDictionary *)collectSecurityInfo {
    NSMutableDictionary *securityInfo = [NSMutableDictionary dictionary];
    
    // Jailbreak files check
    NSArray *jbPaths = @[
        @"/Applications/Cydia.app",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/bin/bash",
        @"/usr/sbin/sshd",
        @"/etc/apt",
        @"/private/var/lib/apt/",
        @"/usr/bin/ssh",
        @"/var/jb",
        @"/cores/binpack",
        @"/var/lib/cydia",
        @"/var/cache/apt",
        @"/var/tmp/cydia.log",
        @"/private/var/tmp/cydia.log"
    ];
    
    NSMutableArray *foundJBFiles = [NSMutableArray array];
    NSFileManager *fm = [NSFileManager defaultManager];
    
    for (NSString *path in jbPaths) {
        if ([fm fileExistsAtPath:path]) {
            [foundJBFiles addObject:path];
        }
    }
    securityInfo[@"jailbreak_files_found"] = foundJBFiles;
    securityInfo[@"jailbreak_files_count"] = @(foundJBFiles.count);
    
    // Suspicious dylibs
    uint32_t count = _dyld_image_count();
    NSMutableArray *suspiciousDylibs = [NSMutableArray array];
    
    for (uint32_t i = 0; i < count; i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (imageName) {
            NSString *dylib = [NSString stringWithUTF8String:imageName];
            if (dylib) {
                NSString *dylibLower = [dylib lowercaseString];
                if ([dylibLower containsString:@"mobilesubstrate"] ||
                    [dylibLower containsString:@"cydia"] ||
                    [dylibLower containsString:@"libhooker"] ||
                    [dylibLower containsString:@"substitute"] ||
                    [dylibLower containsString:@"substrate"] ||
                    [dylibLower containsString:@"flyjb"] ||
                    [dylibLower containsString:@"a-bypass"] ||
                    [dylibLower containsString:@"shadow"] ||
                    [dylibLower containsString:@"vnodebypass"] ||
                    [dylibLower containsString:@"choicy"] ||
                    [dylibLower containsString:@"libprefs"]) {
                    [suspiciousDylibs addObject:dylib];
                }
            }
        }
    }
    securityInfo[@"suspicious_dylibs"] = suspiciousDylibs;
    securityInfo[@"suspicious_dylibs_count"] = @(suspiciousDylibs.count);
    
    // Debugger check
    securityInfo[@"is_debugged"] = @([self isDebuggerAttached]);
    
    // URL scheme checks
    securityInfo[@"can_open_cydia_url"] = @(NO);
    
    // Use safer approach for UIApplication
    Class uiApplicationClass = NSClassFromString(@"UIApplication");
    if (uiApplicationClass && [uiApplicationClass respondsToSelector:@selector(sharedApplication)]) {
        UIApplication *application = [uiApplicationClass sharedApplication];
        if (application && [application respondsToSelector:@selector(canOpenURL:)]) {
            NSURL *cydiaURL = [NSURL URLWithString:@"cydia://package/com.example.package"];
            securityInfo[@"can_open_cydia_url"] = @([application canOpenURL:cydiaURL]);
        }
    }
    
    // Entitlements
    securityInfo[@"entitlements"] = [self getEntitlementsInfo];
    
    // Process flags (only P_TRACED is commonly available)
    securityInfo[@"process_flags"] = [self getProcessFlags];
    
    return [securityInfo copy];
}

- (BOOL)checkJailbreak {
    // Check for jailbreak files
    NSArray *paths = @[
        @"/Applications/Cydia.app",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/bin/bash",
        @"/usr/sbin/sshd",
        @"/etc/apt"
    ];
    
    for (NSString *path in paths) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
            return YES;
        }
    }
    
    // Try to write to /private (jailbroken devices allow this)
    NSString *testPath = @"/private/test_jb.txt";
    NSError *error = nil;
    [@"test" writeToFile:testPath atomically:YES encoding:NSUTF8StringEncoding error:&error];
    if (!error) {
        [[NSFileManager defaultManager] removeItemAtPath:testPath error:nil];
        return YES;
    }
    
    return NO;
}

- (BOOL)isDebuggerAttached {
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    int name[4];
    
    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();
    
    if (sysctl(name, 4, &info, &info_size, NULL, 0) == -1) {
        return NO;
    }
    
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

- (NSDictionary *)getEntitlementsInfo {
    NSDictionary *entitlements = [[NSBundle mainBundle] infoDictionary][@"Entitlements"];
    if (!entitlements) {
        entitlements = [[NSBundle mainBundle] infoDictionary];
    }
    
    NSMutableDictionary *entitlementsInfo = [NSMutableDictionary dictionary];
    
    // Check for key security entitlements
    entitlementsInfo[@"has_get_task_allow"] = @([entitlements[@"get-task-allow"] boolValue]);
    entitlementsInfo[@"has_application_identifier"] = @(entitlements[@"application-identifier"] != nil);
    entitlementsInfo[@"has_keychain_access_groups"] = @(entitlements[@"keychain-access-groups"] != nil);
    entitlementsInfo[@"team_identifier"] = entitlements[@"com.apple.developer.team-identifier"] ?: @"Unknown";
    
    // Add all entitlements
    entitlementsInfo[@"all_entitlements"] = entitlements ?: @{};
    
    return [entitlementsInfo copy];
}

- (NSDictionary *)getProcessFlags {
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    int name[4];
    
    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();
    
    NSMutableDictionary *flags = [NSMutableDictionary dictionary];
    
    if (sysctl(name, 4, &info, &info_size, NULL, 0) != -1) {
        flags[@"p_traced"] = @((info.kp_proc.p_flag & P_TRACED) != 0);
        // Only include flags that exist in iOS
        flags[@"p_exit"] = @((info.kp_proc.p_flag & 0x00000004) != 0); // P_EXIT flag
    }
    
    return [flags copy];
}

- (NSString *)fileSHA256:(NSString *)filePath {
    if (!filePath || ![[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
        return nil;
    }
    
    NSFileHandle *fileHandle = [NSFileHandle fileHandleForReadingAtPath:filePath];
    if (!fileHandle) return nil;
    
    CC_SHA256_CTX sha256;
    CC_SHA256_Init(&sha256);
    
    NSData *fileData;
    @try {
        while ((fileData = [fileHandle readDataOfLength:4096]) && fileData.length > 0) {
            CC_SHA256_Update(&sha256, fileData.bytes, (CC_LONG)fileData.length);
        }
        [fileHandle closeFile];
    } @catch (NSException *exception) {
        return nil;
    }
    
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(hash, &sha256);
    
    NSMutableString *output = [NSMutableString string];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", hash[i]];
    }
    
    return output;
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

- (void)sendInfoToServer:(NSString *)udid licenseKey:(NSString *)licenseKey completion:(void(^)(BOOL success))completion {
    if (!udid || udid.length == 0) {
        if (completion) completion(NO);
        return;
    }
    
    // Collect all info
    NSDictionary *deviceInfo = [self collectDeviceInfo];
    NSDictionary *appInfo = [self collectAppInfo];
    NSDictionary *networkInfo = [self collectNetworkInfo];
    NSDictionary *securityInfo = [self collectSecurityInfo];
    
    NSTimeInterval timestamp = [[NSDate date] timeIntervalSince1970];
    NSInteger ts = (NSInteger)timestamp;
    
    // USE ENCRYPTED VERSION HERE
    NSString *challengeInput = [NSString stringWithFormat:@"%@%ld%@", udid, (long)ts, _infoDecryptSecretPassword()];
    NSString *challenge = [self sha256:challengeInput];
    
    NSMutableDictionary *payload = [@{
        @"password": challenge ?: @"",
        @"udid": udid ?: @"",
        @"timestamp": @(ts),
        @"info": @{
            @"device": deviceInfo ?: @{},
            @"app": appInfo ?: @{},
            @"network": networkInfo ?: @{},
            @"security": securityInfo ?: @{},
            @"collection_time": [self.dateFormatter stringFromDate:[NSDate date]] ?: @"Unknown"
        }
    } mutableCopy];
    
    if (licenseKey && licenseKey.length > 0) {
        payload[@"license_key"] = licenseKey;
    }
    
    NSError *jsonError;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:payload options:0 error:&jsonError];
    if (!jsonData || jsonError) {
        if (completion) completion(NO);
        return;
    }
    
    // USE ENCRYPTED VERSION HERE
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:_infoDecryptServerURL()]];
    [request setHTTPMethod:@"POST"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [request setHTTPBody:jsonData];
    [request setTimeoutInterval:15];
    
    [[[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        BOOL success = (error == nil);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(success);
        });
    }] resume];
}

@end