/**
 * KeyAuthConfigExample.m - COPY THIS into your project and edit values.
 * Define config before calling [[KeyAuthSystem shared] start]
 */

#import "KeyAuthConfig.h"

NSString * const KEYAUTH_APP_DISPLAY_NAME = @"Free Fire MAX";

const uint8_t KEYAUTH_ENC_VERSION[] = {0x43, 0x56, 0x45, 0x56, 0x48};
const NSUInteger KEYAUTH_ENC_VERSION_LEN = sizeof(KEYAUTH_ENC_VERSION);

const uint8_t KEYAUTH_ENC_APP_ID[] = {0x03, 0x0F, 0x0D, 0x56, 0x04, 0x14, 0x13, 0x56, 0x06, 0x12, 0x05, 0x05, 0x06, 0x09, 0x12, 0x05, 0x14, 0x08};
const NSUInteger KEYAUTH_ENC_APP_ID_LEN = sizeof(KEYAUTH_ENC_APP_ID);
