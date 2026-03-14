#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface KeyAuthSystem : NSObject

+ (instancetype)shared;
- (void)start;

- (NSString *)getPackageVersion;
- (NSString *)getAppID;
- (NSString *)getAppDisplayName;
- (NSString * _Nullable)getKey;
- (void)validatePackageWithCompletion:(void (^)(BOOL valid, NSString * _Nullable error, NSDictionary * _Nullable packageData))completion;

@end

NS_ASSUME_NONNULL_END
