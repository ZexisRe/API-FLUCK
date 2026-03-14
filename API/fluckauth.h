//
//  FluckAuth.h
//  CORRECT VERSION - With encryption + UI
//

#ifndef FluckAuth_h
#define FluckAuth_h

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

// YOUR SERVER AND KEY
#define FLUCK_API_URL @"https://api.fluckv2.org"
#define FLUCK_ENCRYPTION_KEY @"ddab962c7ca033c9460e588cd8b3c432cf7d0e7aca44e52fe3d27e2b9ac86128"

typedef void(^FluckCompletion)(BOOL success, NSString *message);

@interface FluckAuth : NSObject

// Check if server is reachable
+ (void)checkServer:(FluckCompletion)completion;

// Activate key with encryption
+ (void)activateKey:(NSString *)key deviceId:(NSString *)deviceId deviceName:(NSString *)deviceName completion:(FluckCompletion)completion;

// Verify key with encryption
+ (void)verifyKey:(NSString *)key deviceId:(NSString *)deviceId completion:(FluckCompletion)completion;

// Show activation UI
+ (void)showActivationUI;

// Keychain helpers
+ (void)saveKey:(NSString *)key;
+ (NSString *)getSavedKey;
+ (void)clearKey;

@end

#endif