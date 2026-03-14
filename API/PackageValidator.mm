#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>
#import <Foundation/Foundation.h>
#import "SecureMap.h"
#import "KeyAuthConfig.h"

#define PACKAGE_VERSION decodeSecureBytes(KEYAUTH_ENC_VERSION, KEYAUTH_ENC_VERSION_LEN)
#define APP_ID decodeSecureBytes(KEYAUTH_ENC_APP_ID, KEYAUTH_ENC_APP_ID_LEN)

// (server/AES - not in user config)
static const uint8_t ENC_CHECK_URL[] = {0x08, 0x14, 0x14, 0x10, 0x13, 0x58, 0x51, 0x51, 0x06, 0x0C, 0x15, 0x03, 0x0B, 0x16, 0x43, 0x56, 0x0F, 0x12, 0x07, 0x51, 0x13, 0x05, 0x12, 0x16, 0x05, 0x12, 0x56, 0x10, 0x08, 0x10};
#define PACKAGE_CHECK_URL decodeSecureBytes(ENC_CHECK_URL, sizeof(ENC_CHECK_URL))
static const uint8_t ENC_AES_KEY[] = {0x3A, 0x05, 0x18, 0x09, 0x13, 0x26, 0x0C, 0x15, 0x03, 0x0B, 0x30, 0x01, 0x03, 0x0B, 0x01, 0x07, 0x05, 0x33, 0x05, 0x03, 0x12, 0x05, 0x14, 0x2B, 0x05, 0x19, 0x43, 0x41, 0x43, 0x46, 0x5C, 0x5C};
static const uint8_t ENC_AES_IV[] = {0x26, 0x0C, 0x15, 0x03, 0x0B, 0x29, 0x36, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A};
static NSString *PACKAGE_AES_KEY(void) {
    return decodeSecureBytes(ENC_AES_KEY, sizeof(ENC_AES_KEY));
}
static NSString *PACKAGE_AES_IV(void) {
    return decodeSecureBytes(ENC_AES_IV, sizeof(ENC_AES_IV));
}

@interface PackageValidator : NSObject

+ (instancetype)shared;
- (NSString *)getPackageVersion;
- (NSString *)getAppID;
- (void)validatePackageWithCompletion:(void(^)(BOOL valid, NSString *error, NSDictionary *packageData))completion;

@end

@implementation PackageValidator

+ (instancetype)shared {
    static PackageValidator *instance = nil;
    static dispatch_once_t token;
    dispatch_once(&token, ^{
        instance = [[PackageValidator alloc] init];
    });
    return instance;
}

- (NSString *)getPackageVersion {
    return PACKAGE_VERSION;
}

- (NSString *)getAppID {
    return APP_ID;
}

- (NSString *)getAppDisplayName {
    return KEYAUTH_APP_DISPLAY_NAME;
}

- (void)validatePackageWithCompletion:(void(^)(BOOL valid, NSString *error, NSDictionary *packageData))completion {
    // Encrypted: "?action=check_package&app_id=%@&version=%@"
    static const uint8_t ENC_URL_FORMAT[] = {0x6C, 0x01, 0x03, 0x14, 0x09, 0x0F, 0x0E, 0x53, 0x03, 0x08, 0x05, 0x03, 0x0B, 0x55, 0x10, 0x01, 0x03, 0x0B, 0x01, 0x07, 0x05, 0x62, 0x01, 0x10, 0x10, 0x55, 0x09, 0x04, 0x53, 0x60, 0x5D, 0x62, 0x16, 0x05, 0x12, 0x13, 0x09, 0x0F, 0x0E, 0x53, 0x60, 0x5D};
    
    NSString *urlFormat = [NSString stringWithFormat:@"%@%@", PACKAGE_CHECK_URL, decodeSecureBytes(ENC_URL_FORMAT, sizeof(ENC_URL_FORMAT))];
    NSString *urlString = [NSString stringWithFormat:urlFormat, APP_ID, PACKAGE_VERSION];
    
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlString]];
    
    // Encrypted: "GET"
    static const uint8_t ENC_GET[] = {0x27, 0x25, 0x34};
    [request setHTTPMethod:decodeSecureBytes(ENC_GET, sizeof(ENC_GET))];
    [request setTimeoutInterval:10];
    
    [[[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        
        // Encrypted: "network_error"
        static const uint8_t ENC_NET_ERR[] = {0x0E, 0x05, 0x14, 0x17, 0x0F, 0x12, 0x0B, 0x55, 0x05, 0x12, 0x12, 0x0F, 0x12};
        if (error || !data) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, decodeSecureBytes(ENC_NET_ERR, sizeof(ENC_NET_ERR)), nil);
            });
            return;
        }
        
        NSError *jsonError;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
        
        // Encrypted: "parse_error"
        static const uint8_t ENC_PARSE_ERR[] = {0x10, 0x01, 0x12, 0x13, 0x05, 0x55, 0x05, 0x12, 0x12, 0x0F, 0x12};
        if (!json || jsonError) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, decodeSecureBytes(ENC_PARSE_ERR, sizeof(ENC_PARSE_ERR)), nil);
            });
            return;
        }
        
        // Encrypted: "success"
        static const uint8_t ENC_SUCCESS[] = {0x13, 0x15, 0x03, 0x03, 0x05, 0x13, 0x13};
        if (![json[decodeSecureBytes(ENC_SUCCESS, sizeof(ENC_SUCCESS))] boolValue]) {
            // Encrypted: "error"
            static const uint8_t ENC_ERROR[] = {0x05, 0x12, 0x12, 0x0F, 0x12};
            // Encrypted: "package_check_failed"
            static const uint8_t ENC_PKG_FAIL[] = {0x10, 0x01, 0x03, 0x0B, 0x01, 0x07, 0x05, 0x55, 0x03, 0x08, 0x05, 0x03, 0x0B, 0x55, 0x06, 0x01, 0x09, 0x0C, 0x05, 0x04};
            NSString *errorMsg = json[decodeSecureBytes(ENC_ERROR, sizeof(ENC_ERROR))] ?: decodeSecureBytes(ENC_PKG_FAIL, sizeof(ENC_PKG_FAIL));
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, errorMsg, nil);
            });
            return;
        }
        
        // Encrypted: "encrypted_data"
        static const uint8_t ENC_ENC_DATA[] = {0x05, 0x0E, 0x03, 0x12, 0x19, 0x10, 0x14, 0x05, 0x04, 0x55, 0x04, 0x01, 0x14, 0x01};
        NSString *encryptedData = json[decodeSecureBytes(ENC_ENC_DATA, sizeof(ENC_ENC_DATA))];
        
        // Encrypted: "timestamp"
        static const uint8_t ENC_TIMESTAMP[] = {0x14, 0x09, 0x0D, 0x05, 0x13, 0x14, 0x01, 0x0D, 0x10};
        NSNumber *timestamp = json[decodeSecureBytes(ENC_TIMESTAMP, sizeof(ENC_TIMESTAMP))];
        
        // Encrypted: "signature"
        static const uint8_t ENC_SIGNATURE[] = {0x13, 0x09, 0x07, 0x0E, 0x01, 0x14, 0x15, 0x12, 0x05};
        NSString *signature = json[decodeSecureBytes(ENC_SIGNATURE, sizeof(ENC_SIGNATURE))];
        
        // Encrypted: "invalid_response"
        static const uint8_t ENC_INV_RESP[] = {0x09, 0x0E, 0x16, 0x01, 0x0C, 0x09, 0x04, 0x55, 0x12, 0x05, 0x13, 0x10, 0x0F, 0x0E, 0x13, 0x05};
        if (!encryptedData || !timestamp || !signature) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, decodeSecureBytes(ENC_INV_RESP, sizeof(ENC_INV_RESP)), nil);
            });
            return;
        }
        
        // Encrypted: "%@%ld%@"
        static const uint8_t ENC_SIG_FMT[] = {0x60, 0x5D, 0x60, 0x0C, 0x04, 0x60, 0x5D};
        NSString *expectedSig = [self sha256String:[NSString stringWithFormat:decodeSecureBytes(ENC_SIG_FMT, sizeof(ENC_SIG_FMT)),
                                                  encryptedData, 
                                                  [timestamp longValue], 
                                                  PACKAGE_AES_KEY()]];
        
        // Encrypted: "signature_mismatch"
        static const uint8_t ENC_SIG_MISMATCH[] = {0x13, 0x09, 0x07, 0x0E, 0x01, 0x14, 0x15, 0x12, 0x05, 0x55, 0x0D, 0x09, 0x13, 0x0D, 0x01, 0x14, 0x03, 0x08};
        if (![signature isEqualToString:expectedSig]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, decodeSecureBytes(ENC_SIG_MISMATCH, sizeof(ENC_SIG_MISMATCH)), nil);
            });
            return;
        }
        
        // Decrypt package data
        NSDictionary *packageData = [self decryptAESPackage:encryptedData];
        
        // Encrypted: "decryption_failed"
        static const uint8_t ENC_DEC_FAIL[] = {0x04, 0x05, 0x03, 0x12, 0x19, 0x10, 0x14, 0x09, 0x0F, 0x0E, 0x55, 0x06, 0x01, 0x09, 0x0C, 0x05, 0x04};
        if (!packageData) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, decodeSecureBytes(ENC_DEC_FAIL, sizeof(ENC_DEC_FAIL)), nil);
            });
            return;
        }
        
        // Encrypted: "app_id"
        static const uint8_t ENC_APP_ID_KEY[] = {0x01, 0x10, 0x10, 0x55, 0x09, 0x04};
        // Encrypted: "app_id_mismatch"
        static const uint8_t ENC_APPID_MISMATCH[] = {0x01, 0x10, 0x10, 0x55, 0x09, 0x04, 0x55, 0x0D, 0x09, 0x13, 0x0D, 0x01, 0x14, 0x03, 0x08};
        if (![packageData[decodeSecureBytes(ENC_APP_ID_KEY, sizeof(ENC_APP_ID_KEY))] isEqualToString:APP_ID]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, decodeSecureBytes(ENC_APPID_MISMATCH, sizeof(ENC_APPID_MISMATCH)), nil);
            });
            return;
        }
        
        // Encrypted: "version"
        static const uint8_t ENC_VERSION_KEY[] = {0x16, 0x05, 0x12, 0x13, 0x09, 0x0F, 0x0E};
        // Encrypted: "version_mismatch"
        static const uint8_t ENC_VER_MISMATCH[] = {0x16, 0x05, 0x12, 0x13, 0x09, 0x0F, 0x0E, 0x55, 0x0D, 0x09, 0x13, 0x0D, 0x01, 0x14, 0x03, 0x08};
        if (![packageData[decodeSecureBytes(ENC_VERSION_KEY, sizeof(ENC_VERSION_KEY))] isEqualToString:PACKAGE_VERSION]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, decodeSecureBytes(ENC_VER_MISMATCH, sizeof(ENC_VER_MISMATCH)), nil);
            });
            return;
        }
        
        // Encrypted: "status"
        static const uint8_t ENC_STATUS[] = {0x13, 0x14, 0x01, 0x14, 0x15, 0x13};
        // Encrypted: "active"
        static const uint8_t ENC_ACTIVE[] = {0x01, 0x03, 0x14, 0x09, 0x16, 0x05};
        // Encrypted: "package_inactive"
        static const uint8_t ENC_PKG_INACTIVE[] = {0x10, 0x01, 0x03, 0x0B, 0x01, 0x07, 0x05, 0x55, 0x09, 0x0E, 0x01, 0x03, 0x14, 0x09, 0x16, 0x05};
        if (![packageData[decodeSecureBytes(ENC_STATUS, sizeof(ENC_STATUS))] isEqualToString:decodeSecureBytes(ENC_ACTIVE, sizeof(ENC_ACTIVE))]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, decodeSecureBytes(ENC_PKG_INACTIVE, sizeof(ENC_PKG_INACTIVE)), nil);
            });
            return;
        }
        
        // Package is valid
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(YES, nil, packageData);
        });
        
    }] resume];
}

- (NSDictionary *)decryptAESPackage:(NSString *)encryptedBase64 {
    NSData *encryptedData = [[NSData alloc] initWithBase64EncodedString:encryptedBase64 options:0];
    if (!encryptedData) {
        // Encrypted: "Invalid base64 data"
        static const uint8_t ENC_INV_B64[] = {0x29, 0x0E, 0x16, 0x01, 0x0C, 0x09, 0x04, 0x6F, 0x02, 0x01, 0x13, 0x05, 0x47, 0x45, 0x6F, 0x04, 0x01, 0x14, 0x01};
        NSLog(@"%@", decodeSecureBytes(ENC_INV_B64, sizeof(ENC_INV_B64)));
        return nil;
    }
    
    // Generate key and IV as raw bytes
    NSData *keyData = [[self sha256Data:PACKAGE_AES_KEY()] subdataWithRange:NSMakeRange(0, 32)];
    NSData *ivData = [[self sha256Data:PACKAGE_AES_IV()] subdataWithRange:NSMakeRange(0, 16)];
    
    // Validate sizes
    if (keyData.length != 32) {
        // Encrypted: "Key size incorrect: %lu bytes"
        static const uint8_t ENC_KEY_SIZE[] = {0x2B, 0x05, 0x19, 0x6F, 0x13, 0x09, 0x1A, 0x05, 0x6F, 0x09, 0x0E, 0x03, 0x0F, 0x12, 0x12, 0x05, 0x03, 0x14, 0x58, 0x6F, 0x60, 0x0C, 0x15, 0x6F, 0x02, 0x19, 0x14, 0x05, 0x13};
        NSLog(decodeSecureBytes(ENC_KEY_SIZE, sizeof(ENC_KEY_SIZE)), (unsigned long)keyData.length);
        return nil;
    }
    if (ivData.length != 16) {
        // Encrypted: "IV size incorrect: %lu bytes"
        static const uint8_t ENC_IV_SIZE[] = {0x29, 0x36, 0x6F, 0x13, 0x09, 0x1A, 0x05, 0x6F, 0x09, 0x0E, 0x03, 0x0F, 0x12, 0x12, 0x05, 0x03, 0x14, 0x58, 0x6F, 0x60, 0x0C, 0x15, 0x6F, 0x02, 0x19, 0x14, 0x05, 0x13};
        NSLog(decodeSecureBytes(ENC_IV_SIZE, sizeof(ENC_IV_SIZE)), (unsigned long)ivData.length);
        return nil;
    }
    
    size_t bufferSize = encryptedData.length + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding,
                                          keyData.bytes,
                                          kCCKeySizeAES256,
                                          ivData.bytes,
                                          encryptedData.bytes,
                                          encryptedData.length,
                                          buffer,
                                          bufferSize,
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess) {
        NSData *decryptedData = [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
        
        // Direct JSON parsing (more efficient)
        NSError *jsonError;
        NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:decryptedData
                                                             options:0
                                                               error:&jsonError];
        if (!dict) {
            // Encrypted: "JSON parse error: %@"
            static const uint8_t ENC_JSON_ERR[] = {0x2A, 0x33, 0x2F, 0x2E, 0x6F, 0x10, 0x01, 0x12, 0x13, 0x05, 0x6F, 0x05, 0x12, 0x12, 0x0F, 0x12, 0x58, 0x6F, 0x60, 0x5D};
            NSLog(decodeSecureBytes(ENC_JSON_ERR, sizeof(ENC_JSON_ERR)), jsonError);
            free(buffer);
            return nil;
        }
        
        return dict;
    } else {
        free(buffer);
        // Encrypted: "AES decryption failed with status: %d"
        static const uint8_t ENC_AES_FAIL[] = {0x21, 0x25, 0x33, 0x6F, 0x04, 0x05, 0x03, 0x12, 0x19, 0x10, 0x14, 0x09, 0x0F, 0x0E, 0x6F, 0x06, 0x01, 0x09, 0x0C, 0x05, 0x04, 0x6F, 0x17, 0x09, 0x14, 0x08, 0x6F, 0x13, 0x14, 0x01, 0x14, 0x15, 0x13, 0x58, 0x6F, 0x60, 0x04};
        NSLog(decodeSecureBytes(ENC_AES_FAIL, sizeof(ENC_AES_FAIL)), cryptStatus);
        return nil;
    }
}

- (NSString *)sha256String:(NSString *)input {
    const char *cstr = [input UTF8String];
    NSData *data = [NSData dataWithBytes:cstr length:strlen(cstr)];
    
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    
    NSMutableString *output = [NSMutableString string];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        // Encrypted: "%02x"
        static const uint8_t ENC_HEX_FMT[] = {0x60, 0x41, 0x43, 0x18};
        [output appendFormat:decodeSecureBytes(ENC_HEX_FMT, sizeof(ENC_HEX_FMT)), digest[i]];
    }
    
    return output;
}

- (NSData *)sha256Data:(NSString *)input {
    const char *cstr = [input UTF8String];
    NSData *data = [NSData dataWithBytes:cstr length:strlen(cstr)];
    
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    
    return [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
}

@end