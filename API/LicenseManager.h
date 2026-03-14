// LicenseManager.h
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
@interface LicenseManager : NSObject

@property (nonatomic, readonly) BOOL isAuthorized;
@property (nonatomic, readonly) NSString *licenseKey;
@property (nonatomic, readonly) NSString *deviceUDID;
@property (nonatomic, readonly) NSTimeInterval remainingTime; // seconds
@property (nonatomic, readonly) NSDate *expiryDate;

+ (instancetype)shared;
- (NSString *)truncatedLicenseKey;
- (NSString *)formattedRemainingTime;
- (UIColor *)statusColor;
- (NSString *)statusText;
- (void)updateRemainingTime;

@end