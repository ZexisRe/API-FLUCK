#import <Foundation/Foundation.h>

// PackageValidator - internal. Use KeyAuthSystem from KeyAuth.h
@interface PackageValidator : NSObject

+ (instancetype)shared;
- (void)validatePackageWithCompletion:(void(^)(BOOL valid, NSString *error, NSDictionary *packageData))completion;
- (NSString *)getPackageVersion;
- (NSString *)getAppID;
/** Display name from KeyAuthConfig (e.g. "Free Fire MAX") for UI titleLabel */
- (NSString *)getAppDisplayName;

@end