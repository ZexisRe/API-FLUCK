// EncryptionHelper.h
#import <Foundation/Foundation.h>


@interface EncryptionHelper : NSObject

+ (NSString *)xorEncrypt:(NSString *)input withKey:(NSString *)key;
+ (NSString *)xorDecrypt:(NSString *)hexInput withKey:(NSString *)key;
+ (NSString *)generateRollingKey:(NSInteger)timestamp udid:(NSString *)udid;
+ (NSData *)dataFromHexString:(NSString *)hexString;

@end