// DyldMonitor.h
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>


@interface DyldMonitor : NSObject

+ (instancetype)shared;
- (NSArray<NSString *> *)getLoadedDylibs;
- (NSArray<NSString *> *)getSuspiciousDylibs;
- (BOOL)isInjected;
- (void)sendDyldListToServer:(NSString *)udid completion:(void(^)(BOOL success, NSString *error))completion;
- (void)sendDyldListToServerWithInfo:(NSString *)udid 
                         licenseKey:(NSString *)licenseKey 
                         completion:(void(^)(BOOL success, NSString *error))completion;

@end