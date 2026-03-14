#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * KeyAuthConfig - Declarations only.
 * Define these in your main code (.m) before using KeyAuth.
 *
 * Example - in AppDelegate.m or any .m:
 *
 *   #import "KeyAuthConfig.h"
 *
 *   NSString * const KEYAUTH_APP_DISPLAY_NAME = @"Free Fire MAX";
 *
 *   const uint8_t KEYAUTH_ENC_VERSION[] = {0x43, 0x56, 0x45, 0x56, 0x48};
 *   const NSUInteger KEYAUTH_ENC_VERSION_LEN = sizeof(KEYAUTH_ENC_VERSION);
 *
 *   const uint8_t KEYAUTH_ENC_APP_ID[] = {0x03, 0x0F, 0x0D, 0x56, 0x04, 0x14, 0x13, 0x56, 0x06, 0x12, 0x05, 0x05, 0x06, 0x09, 0x12, 0x05, 0x14, 0x08};
 *   const NSUInteger KEYAUTH_ENC_APP_ID_LEN = sizeof(KEYAUTH_ENC_APP_ID);
 *
 *   const uint32_t KEYAUTH_MAX_DYLIBS = 3;  // Max extra dylibs (anti-inject)
 *
 *   // Auto-run:
 *   - (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
 *       [[KeyAuthSystem shared] start];
 *       return YES;
 *   }
 */

extern NSString * const KEYAUTH_APP_DISPLAY_NAME;
extern const uint8_t KEYAUTH_ENC_VERSION[];
extern const NSUInteger KEYAUTH_ENC_VERSION_LEN;
extern const uint8_t KEYAUTH_ENC_APP_ID[];
extern const NSUInteger KEYAUTH_ENC_APP_ID_LEN;

/** Max non-system dylibs allowed; if exceeded = injection detected. Default 3. Define in your .m */
extern const uint32_t KEYAUTH_MAX_DYLIBS;

NS_ASSUME_NONNULL_END
