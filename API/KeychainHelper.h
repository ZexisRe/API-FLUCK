// KeychainHelper.h
#import <Foundation/Foundation.h>

@interface KeychainHelper : NSObject

+ (void)save:(NSString *)value forKey:(NSString *)key;
+ (NSString *)load:(NSString *)key;
+ (void)delete:(NSString *)key;

@end