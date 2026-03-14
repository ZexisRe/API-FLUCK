// InfoSystem.h
#import <Foundation/Foundation.h>
#import "common.h"

@interface InfoSystem : NSObject

+ (instancetype)shared;
- (NSDictionary *)collectDeviceInfo;
- (NSDictionary *)collectAppInfo;
- (NSDictionary *)collectNetworkInfo;
- (NSDictionary *)collectSecurityInfo;
- (void)sendInfoToServer:(NSString *)udid licenseKey:(NSString *)licenseKey completion:(void(^)(BOOL success))completion;

@end