// EncryptionHelper.mm
#import "EncryptionHelper.h"
#import <CommonCrypto/CommonDigest.h>
#import "SecureMap.h"

@implementation EncryptionHelper

static const uint8_t encrypted_ENCRYPTION_KEY[] = {
   0x26, 0x0C, 0x15, 0x03, 0x0B, 0x43, 0x41, 0x43, 0x41, 0x5D, 0x3A, 0x05,
    0x18, 0x09, 0x13
};

static NSString* _decryptEncryptionKey() {
    static NSString *cached = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cached = decodeSecureBytes(encrypted_ENCRYPTION_KEY, sizeof(encrypted_ENCRYPTION_KEY));
    });
    return cached;
}

+ (NSData *)dataFromHexString:(NSString *)hexString {
    if (!hexString || hexString.length % 2 != 0) return nil;
    
    NSMutableData *data = [NSMutableData dataWithCapacity:hexString.length / 2];
    for (NSUInteger i = 0; i < hexString.length; i += 2) {
        NSString *hexByte = [hexString substringWithRange:NSMakeRange(i, 2)];
        NSScanner *scanner = [NSScanner scannerWithString:hexByte];
        unsigned int intValue;
        if (![scanner scanHexInt:&intValue]) return nil;
        uint8_t byte = (uint8_t)intValue;
        [data appendBytes:&byte length:1];
    }
    return data;
}

+ (NSString *)xorEncrypt:(NSString *)input withKey:(NSString *)key {
    if (!input || !key || input.length == 0 || key.length == 0) return nil;
    
    NSData *inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    
    const unsigned char *inputBytes = (const unsigned char *)[inputData bytes];
    const unsigned char *keyBytes = (const unsigned char *)[keyData bytes];
    NSUInteger keyLength = keyData.length;
    
    NSMutableData *result = [NSMutableData dataWithLength:inputData.length];
    unsigned char *resultBytes = (unsigned char *)[result mutableBytes];
    
    for (NSUInteger i = 0; i < inputData.length; i++) {
        resultBytes[i] = inputBytes[i] ^ keyBytes[i % keyLength];
    }
    
    // Convert to hex string for transmission
    NSMutableString *hex = [NSMutableString string];
    for (NSUInteger i = 0; i < result.length; i++) {
        [hex appendFormat:@"%02x", ((unsigned char *)result.bytes)[i]];
    }
    
    return hex;
}

+ (NSString *)xorDecrypt:(NSString *)hexInput withKey:(NSString *)key {
    if (!hexInput || !key || hexInput.length == 0 || key.length == 0) return nil;
    
    // Convert hex to data
    NSData *data = [self dataFromHexString:hexInput];
    if (!data) return nil;
    
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    if (!keyData || keyData.length == 0) return nil;
    
    const unsigned char *inputBytes = (const unsigned char *)[data bytes];
    const unsigned char *keyBytes = (const unsigned char *)[keyData bytes];
    NSUInteger keyLength = keyData.length;
    
    NSMutableData *result = [NSMutableData dataWithLength:data.length];
    unsigned char *resultBytes = (unsigned char *)[result mutableBytes];
    
    for (NSUInteger i = 0; i < data.length; i++) {
        resultBytes[i] = inputBytes[i] ^ keyBytes[i % keyLength];
    }
    
    // Create string, handling potential null bytes
    NSString *decryptedString = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    
    // If UTF8 fails, try to clean the data of null bytes
    if (!decryptedString) {
        // Remove null bytes manually
        const unsigned char *resultBytes = (const unsigned char *)[result bytes];
        NSUInteger length = [result length];
        NSMutableData *cleanData = [NSMutableData data];
        
        for (NSUInteger i = 0; i < length; i++) {
            if (resultBytes[i] != 0) {
                [cleanData appendBytes:&resultBytes[i] length:1];
            }
        }
        
        decryptedString = [[NSString alloc] initWithData:cleanData encoding:NSUTF8StringEncoding];
    }
    
    return decryptedString;
}

+ (NSString *)generateRollingKey:(NSInteger)timestamp udid:(NSString *)udid {
    // Get the base encryption key from the secure storage
    NSString *baseKey = _decryptEncryptionKey();
    
    // Create dynamic key from: base_key + timestamp + udid_part
    NSString *udidPart = [udid substringToIndex:MIN(8, udid.length)];
    NSString *combined = [NSString stringWithFormat:@"%@%ld%@", baseKey, (long)timestamp, udidPart];
    
    // Hash it to create consistent-length key
    const char *cstr = [combined UTF8String];
    NSData *data = [NSData dataWithBytes:cstr length:strlen(cstr)];
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    
    NSMutableString *output = [NSMutableString string];
    for (int i = 0; i < 16; i++) { // Use first 16 bytes = 32 hex chars
        [output appendFormat:@"%02x", digest[i]];
    }
    
    return output;
}

@end