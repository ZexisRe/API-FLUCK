
// LicenseManager.mm
#import "LicenseManager.h"
#import "KeychainHelper.h"
#import <objc/runtime.h>

@interface LicenseManager()
@property (nonatomic, assign) BOOL isAuthorized;
@property (nonatomic, strong) NSString *licenseKey;
@property (nonatomic, strong) NSString *deviceUDID;
@property (nonatomic, assign) NSTimeInterval remainingTime;
@property (nonatomic, strong) NSDate *expiryDate;
@end

@implementation LicenseManager

+ (instancetype)shared {
    static LicenseManager *instance = nil;
    static dispatch_once_t token;
    dispatch_once(&token, ^{
        instance = [[LicenseManager alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        [self loadLicenseInfo];
    }
    return self;
}

- (void)loadLicenseInfo {
    // Load key from keychain
    self.licenseKey = [KeychainHelper load:@"key"];
    self.isAuthorized = (self.licenseKey != nil && self.licenseKey.length > 0);
    
    if (self.isAuthorized) {
        // Load expiry from keychain
        NSString *expiryTimestamp = [KeychainHelper load:@"expiry_timestamp"];
        
        if (expiryTimestamp) {
            NSTimeInterval expirySeconds = [expiryTimestamp doubleValue];
            self.expiryDate = [NSDate dateWithTimeIntervalSince1970:expirySeconds];
            NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
            self.remainingTime = expirySeconds - now;
            
            if (self.remainingTime < 0) {
                self.remainingTime = 0;
                self.isAuthorized = NO; // Expired
            }
        } else {
            // No expiry (lifetime license)
            self.remainingTime = -1; // Special value for lifetime
            self.expiryDate = nil;
        }
        
        // Get UDID from KeyAuthSystem
        Class authClass = objc_getClass("KeyAuthSystem");
        if (authClass) {
            SEL sharedSel = NSSelectorFromString(@"shared");
            if ([authClass respondsToSelector:sharedSel]) {
                #pragma clang diagnostic push
                #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                id authSystem = [authClass performSelector:sharedSel];
                SEL udidSel = NSSelectorFromString(@"udid");
                if ([authSystem respondsToSelector:udidSel]) {
                    self.deviceUDID = [authSystem performSelector:udidSel];
                }
                #pragma clang diagnostic pop
            }
        }
    }
}

- (NSString *)truncatedLicenseKey {
    if (!self.licenseKey || self.licenseKey.length <= 8) {
        return self.licenseKey ?: @"";
    }
    
    return [NSString stringWithFormat:@"%@...%@", 
            [self.licenseKey substringToIndex:4],
            [self.licenseKey substringFromIndex:self.licenseKey.length - 4]];
}

- (NSString *)formattedRemainingTime {
    if (self.remainingTime < 0) {
        return @"Lifetime";
    }
    
    if (self.remainingTime <= 0) {
        return @"Expired";
    }
    
    int days = self.remainingTime / 86400;
    int hours = (self.remainingTime - (days * 86400)) / 3600;
    int minutes = (self.remainingTime - (days * 86400) - (hours * 3600)) / 60;
    
    if (days > 0) {
        return [NSString stringWithFormat:@"%dd %02dh", days, hours];
    } else if (hours > 0) {
        return [NSString stringWithFormat:@"%02dh %02dm", hours, minutes];
    } else {
        return [NSString stringWithFormat:@"%02dm %02ds", minutes, (int)self.remainingTime % 60];
    }
}

- (UIColor *)statusColor {
    if (!self.isAuthorized) {
        return [UIColor systemRedColor];
    }
    
    if (self.remainingTime < 0) {
        return [UIColor systemGreenColor]; // Lifetime
    }
    
    if (self.remainingTime < 3600) { // Less than 1 hour
        return [UIColor systemOrangeColor];
    } else if (self.remainingTime < 86400) { // Less than 1 day
        return [UIColor systemYellowColor];
    } else {
        return [UIColor systemGreenColor];
    }
}

- (NSString *)statusText {
    if (!self.isAuthorized) {
        return @"✗ Not Authorized";
    }
    
    NSString *truncatedKey = [self truncatedLicenseKey];
    NSString *remainingTime = [self formattedRemainingTime];
    
    if ([remainingTime isEqualToString:@"Expired"]) {
        return [NSString stringWithFormat:@"✗ %@ (Expired)", truncatedKey];
    }
    
    return [NSString stringWithFormat:@"✓ %@ (%@)", truncatedKey, remainingTime];
}

- (void)updateRemainingTime {
    if (self.expiryDate) {
        NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
        self.remainingTime = [self.expiryDate timeIntervalSince1970] - now;
        
        if (self.remainingTime < 0) {
            self.remainingTime = 0;
            self.isAuthorized = NO;
        }
    }
}

@end