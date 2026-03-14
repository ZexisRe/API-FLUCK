// KeychainHelper.mm
#import "KeychainHelper.h"
#import <Security/Security.h>

@implementation KeychainHelper

+ (void)save:(NSString *)value forKey:(NSString *)key {
    if (!value || !key) return;
    
    // First delete any existing item
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: key
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
    
    // Add the new item
    NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *add = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecValueData: data,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlock
    };
    
    SecItemAdd((__bridge CFDictionaryRef)add, NULL);
}

+ (NSString *)load:(NSString *)key {
    if (!key) return nil;
    
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecReturnData: (__bridge id)kCFBooleanTrue,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
    };
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    
    if (status == errSecSuccess && result != NULL) {
        NSData *data = (__bridge_transfer NSData *)result;
        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    
    return nil;
}

+ (void)delete:(NSString *)key {
    if (!key) return;
    
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: key
    };
    
    SecItemDelete((__bridge CFDictionaryRef)query);
}

@end