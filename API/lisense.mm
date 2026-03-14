#pragma mark - Imports

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/utsname.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <objc/runtime.h>
#import <assert.h>
#include <string.h>
#import "dylidmonitor.h"
#import "infosystem.h"
#import "PackageValidator.h"
#import "KeyAuthConfig.h"
#import "EncryptionHelper.h"
#import "KeychainHelper.h"
#import "SecureMap.h"


#pragma mark - Encrypted Constants
// NOTE: Vars.ewid is set by packagemanager; ensure Vars_t Vars is defined (menuUIKIT/Vars.h)
static const uint8_t encrypted_SERVER_URL[] = {
    0x08, 0x14, 0x14, 0x10, 0x13, 0x58, 0x51, 0x51, 0x06, 0x0C, 0x15, 0x03,
    0x0B, 0x16, 0x43, 0x56, 0x0F, 0x12, 0x07, 0x51, 0x13, 0x05, 0x12, 0x16,
    0x05, 0x12, 0x56, 0x10, 0x08, 0x10
};

static const uint8_t encrypted_SECRET_PASSWORD[] = {
    0x5D, 0x29, 0x01, 0x0D, 0x27, 0x01, 0x19, 0x22, 0x05, 0x03, 0x01, 0x15,
    0x13, 0x05, 0x39, 0x0F, 0x15, 0x21, 0x12, 0x05, 0x33, 0x05, 0x18, 0x19
};


static const uint8_t encrypted_ENCRYPTION_KEY[] = {
 0x26, 0x0C, 0x15, 0x03, 0x0B, 0x43, 0x41, 0x43, 0x41, 0x5D, 0x3A, 0x05,
    0x18, 0x09, 0x13
};


static const uint8_t encrypted_KEY_ADMIN_PASSWORD[] = {
    0x5D, 0x3A, 0x25, 0x38, 0x29, 0x33, 0x34, 0x28, 0x25, 0x27, 0x2F, 0x21, 0x34
};

static const uint8_t encrypted_DYLD_SERVER_URL[] = {
    0x08, 0x14, 0x14, 0x10, 0x13, 0x58, 0x51, 0x51, 0x06, 0x0C, 0x15, 0x03,
    0x0B, 0x16, 0x43, 0x56, 0x0F, 0x12, 0x07, 0x51, 0x13, 0x05, 0x12, 0x16,
    0x05, 0x12, 0x56, 0x10, 0x08, 0x10
};

#pragma mark - Decryption

static NSString* _decryptServerURL() {
    static NSString *cached = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cached = decodeSecureBytes(encrypted_SERVER_URL, sizeof(encrypted_SERVER_URL));
    });
    return cached;
}

static NSString* _decryptSecretPassword() {
    static NSString *cached = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cached = decodeSecureBytes(encrypted_SECRET_PASSWORD, sizeof(encrypted_SECRET_PASSWORD));
    });
    return cached;
}

static NSString* _decryptEncryptionKey() {
    static NSString *cached = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cached = decodeSecureBytes(encrypted_ENCRYPTION_KEY, sizeof(encrypted_ENCRYPTION_KEY));
    });
    return cached;
}

static NSString* _decryptAdminPassword() {
    static NSString *cached = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cached = decodeSecureBytes(encrypted_KEY_ADMIN_PASSWORD, sizeof(encrypted_KEY_ADMIN_PASSWORD));
    });
    return cached;
}

static NSString* _decryptDyldURL() {
    static NSString *cached = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cached = decodeSecureBytes(encrypted_DYLD_SERVER_URL, sizeof(encrypted_DYLD_SERVER_URL));
    });
    return cached;
}

#define Iv8_Tm3 5.0
#define Mx4_Fa2 3
#define XQ7_Mn2_Kp9 1
#define At5_To6 3600
#define Cp8_Mi1 80

#pragma mark - Security

static void xF9_ab2(void) {
    abort();
    volatile int *null_ptr = NULL;
    *null_ptr = 0xDEADBEEF;
    volatile int zero = 0;
    volatile int crash = 1 / zero;
    (void)crash;
    assert(0 && "Security violation detected");
    exit(1);
}

static BOOL dG3_pq1(void) {
    int mib[4];
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();
    
    if (sysctl(mib, 4, &info, &info_size, NULL, 0) != -1) {
        if ((info.kp_proc.p_flag & P_TRACED) != 0) {
            return YES;
        }
    }
    return NO;
}

static BOOL pX4_yr2(void) {
    uint32_t count = _dyld_image_count();
    if (count > Cp8_Mi1) count = Cp8_Mi1;
    for (uint32_t i = 0; i < count; i++) {
        const char *image_name = _dyld_get_image_name(i);
        if (image_name) {
            // Avoid allocating NSString for every image: use strstr for quick scan
            if (strstr(image_name, "Charles") || strstr(image_name, "Burp") ||
                strstr(image_name, "Proxyman") || strstr(image_name, "Fiddler") ||
                strstr(image_name, "mitmproxy")) {
                return YES;
            }
        }
    }
    return NO;
}

#pragma mark - KeyAuth System

@interface KeyAuthSystem : NSObject <UITextFieldDelegate>
@property (nonatomic, strong) NSTimer *checkTimer;
@property (nonatomic, strong) NSTimer *dyldTimer;
@property (nonatomic, strong) NSTimer *infoTimer;
@property (nonatomic, strong) NSTimer *authTimeoutTimer;
@property (nonatomic, strong) NSString *udid;
@property (nonatomic, strong) NSString *currentKey;
@property (atomic, strong) NSDictionary *keyInfo;
@property (atomic, strong) NSDictionary *packageInfo;
@property (atomic, assign) BOOL isAuthenticated;
@property (atomic, assign) BOOL packageValidated;
@property (atomic, assign) NSInteger failedAttempts;
@property (atomic, assign) BOOL isShowingUI;
@property (nonatomic, strong) NSDate *authStartTime;
@property (nonatomic, strong) UIView *blurBackgroundView;
@property (nonatomic, strong) UIView *currentDialog;
@property (nonatomic, strong) UIView *authDialog;
@property (nonatomic, strong) UIView *keyInfoDialog;
@property (nonatomic, strong) UIView *loadingDialog;
@property (nonatomic, strong) NSTimer *keyInfoTimer;
@property (nonatomic, assign) CGRect originalDialogFrame;
@property (nonatomic, assign) BOOL isShowingKeyInfo;
@property (nonatomic, assign) BOOL isShowingLoading;
@property (nonatomic, assign) BOOL isShowingError;
@property (nonatomic, assign) BOOL isShowingPackageError;
@property (nonatomic, assign) BOOL isShowingCopiedAlert;
@property (nonatomic, strong) NSDate *loadingStartTime;
@property (atomic, assign) BOOL isCheckingInProgress;
+ (instancetype)shared;
- (void)start;
- (void)sD1_ly2;
- (void)sI3_nf4;
- (void)tA7_rt9;
- (BOOL)isWinterTheme;
- (BOOL)isDarkMode;
- (UIColor *)accentColor;
- (UIColor *)textColor;
- (UIColor *)pillColor;
- (UIColor *)secondaryTextColor;
- (UIColor *)backgroundColor;
- (void)dismissCurrentDialog;
- (void)showLoadingDialog:(NSString *)message;
- (void)updateLoadingMessage:(NSString *)message;
- (void)dismissLoadingDialog;
@end

@implementation KeyAuthSystem

+ (instancetype)shared {
    static KeyAuthSystem *instance = nil;
    static dispatch_once_t token;
    dispatch_once(&token, ^{ instance = [[KeyAuthSystem alloc] init]; });
    return instance;
}

- (NSDictionary *)readUIStateJSON {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths firstObject];
    NSString *path = [documentsDirectory stringByAppendingPathComponent:@"menu_ui_state.json"];
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data || data.length == 0) return @{};
    NSError *error = nil;
    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    return ([obj isKindOfClass:[NSDictionary class]]) ? (NSDictionary *)obj : @{};
}

- (UIColor *)deserializeThemeColor:(id)maybeDict {
    if (![maybeDict isKindOfClass:[NSDictionary class]]) return nil;
    NSDictionary *d = (NSDictionary *)maybeDict;
    NSNumber *r = d[@"r"], *g = d[@"g"], *b = d[@"b"], *a = d[@"a"];
    if (![r isKindOfClass:[NSNumber class]] || ![g isKindOfClass:[NSNumber class]] || ![b isKindOfClass:[NSNumber class]])
        return nil;
    CGFloat af = (a && [a isKindOfClass:[NSNumber class]]) ? [a floatValue] : 1.0f;
    return [UIColor colorWithRed:[r floatValue] green:[g floatValue] blue:[b floatValue] alpha:af];
}

- (instancetype)init {
    self = [super init];
    if (self) {
        struct utsname info;
        if (uname(&info) == 0) {
            NSString *model = [NSString stringWithCString:info.machine encoding:NSUTF8StringEncoding] ?: @"unknown";
            NSString *version = [[UIDevice currentDevice] systemVersion] ?: @"unknown";
            NSString *name = [[UIDevice currentDevice] name] ?: @"unknown";
            NSString *combined = [NSString stringWithFormat:@"%@-%@-%@", model, version, name];
            _udid = [self sha256:combined] ?: @"";
        } else {
            _udid = @"";
        }
        
        // Safe keychain access
        @try {
            _currentKey = [KeychainHelper load:@"key"] ?: nil;
            NSString *attemptsStr = [KeychainHelper load:@"attempts"];
            _failedAttempts = attemptsStr ? [attemptsStr integerValue] : 0;
        } @catch (NSException *exception) {
            _currentKey = nil;
            _failedAttempts = 0;
        }
        
        _isAuthenticated = NO;
        _packageValidated = NO;
        _isShowingUI = NO;
        _isCheckingInProgress = NO;
        
        // ===== CRITICAL: DISABLE FEATURES BY DEFAULT =====
        Vars.ewid = false;  // Features DISABLED until validated
        
        // Add keyboard notifications
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(keyboardWillShow:)
                                                     name:UIKeyboardWillShowNotification
                                                   object:nil];
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(keyboardWillHide:)
                                                     name:UIKeyboardWillHideNotification
                                                   object:nil];
        
        // Add screen capture notification for stream mode
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(screenCaptureStatusChanged:)
                                                     name:UIScreenCapturedDidChangeNotification
                                                   object:nil];
    }
    return self;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [self tA7_rt9];
    [self.keyInfoTimer invalidate];
    self.keyInfoTimer = nil;
    self.checkTimer = nil;
    self.dyldTimer = nil;
    self.infoTimer = nil;
    self.authTimeoutTimer = nil;
}

- (void)screenCaptureStatusChanged:(NSNotification *)n {
    // Ensure UI operations happen on main thread
    dispatch_async(dispatch_get_main_queue(), ^{
        // Apply stream protection to all dialogs when screen recording status changes
        if (StreamMode) {
            if (self.currentDialog && self.currentDialog.superview) {
                UpdateStreamProtectionForView(self.currentDialog);
            }
            if (self.blurBackgroundView && self.blurBackgroundView.superview) {
                UpdateStreamProtectionForView(self.blurBackgroundView);
            }
        } else {
            // Re-apply protection when stream mode is off
            if (self.currentDialog && self.currentDialog.superview) {
                UpdateStreamProtectionForView(self.currentDialog);
            }
            if (self.blurBackgroundView && self.blurBackgroundView.superview) {
                UpdateStreamProtectionForView(self.blurBackgroundView);
            }
        }
    });
}

- (void)keyboardWillShow:(NSNotification *)notification {
    if (!self.currentDialog || self.currentDialog != self.authDialog) return;
    
    NSDictionary *userInfo = notification.userInfo;
    CGRect keyboardFrame = [[userInfo objectForKey:UIKeyboardFrameEndUserInfoKey] CGRectValue];
    NSTimeInterval animationDuration = [[userInfo objectForKey:UIKeyboardAnimationDurationUserInfoKey] doubleValue];
    
    CGFloat keyboardHeight = keyboardFrame.size.height;
    CGFloat screenHeight = [UIScreen mainScreen].bounds.size.height;
    CGFloat dialogBottom = self.currentDialog.frame.origin.y + self.currentDialog.frame.size.height;
    CGFloat availableSpace = screenHeight - keyboardHeight;
    
    if (dialogBottom > availableSpace - 20) {
        CGFloat offset = dialogBottom - availableSpace + 20;
        self.originalDialogFrame = self.currentDialog.frame;
        
        [UIView animateWithDuration:animationDuration animations:^{
            CGRect newFrame = self.currentDialog.frame;
            newFrame.origin.y -= offset;
            self.currentDialog.frame = newFrame;
        }];
    }
}

- (void)keyboardWillHide:(NSNotification *)notification {
    if (!self.currentDialog || self.currentDialog != self.authDialog) return;
    
    NSDictionary *userInfo = notification.userInfo;
    NSTimeInterval animationDuration = [[userInfo objectForKey:UIKeyboardAnimationDurationUserInfoKey] doubleValue];
    
    if (!CGRectIsEmpty(self.originalDialogFrame)) {
        [UIView animateWithDuration:animationDuration animations:^{
            self.currentDialog.frame = self.originalDialogFrame;
        }];
        self.originalDialogFrame = CGRectZero;
    }
}

- (BOOL)isWinterTheme {
    NSDictionary *state = [self readUIStateJSON];
    if ([state[@"isWinterTheme"] isKindOfClass:[NSNumber class]])
        return [state[@"isWinterTheme"] boolValue];
    if ([[NSUserDefaults standardUserDefaults] objectForKey:@"IsWinterTheme"])
        return [[NSUserDefaults standardUserDefaults] boolForKey:@"IsWinterTheme"];
    return YES;
}

- (BOOL)isDarkMode {
    NSDictionary *state = [self readUIStateJSON];
    if ([state[@"darkMode"] isKindOfClass:[NSNumber class]])
        return [state[@"darkMode"] boolValue];
    if ([[NSUserDefaults standardUserDefaults] objectForKey:@"ModMenuDarkMode"])
        return [[NSUserDefaults standardUserDefaults] boolForKey:@"ModMenuDarkMode"];
    if (@available(iOS 13.0, *)) {
        UIUserInterfaceStyle style = [UITraitCollection currentTraitCollection].userInterfaceStyle;
        return style == UIUserInterfaceStyleDark;
    }
    return NO;
}

- (UIColor *)accentColor {
    // UserDefaults first (menu saves theme here), else file (menu_ui_state.json themeColor), else winter/default
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    if ([d objectForKey:@"ThemeColorR"] != nil) {
        CGFloat r = [d floatForKey:@"ThemeColorR"];
        CGFloat g = [d floatForKey:@"ThemeColorG"];
        CGFloat b = [d floatForKey:@"ThemeColorB"];
        if (r != 0 || g != 0 || b != 0)
            return [UIColor colorWithRed:r green:g blue:b alpha:1.0];
    }
    UIColor *fromFile = [self deserializeThemeColor:[self readUIStateJSON][@"themeColor"]];
    if (fromFile) return fromFile;
    if (self.isWinterTheme)
        return [UIColor colorWithRed:0.4 green:0.75 blue:0.95 alpha:1.0];
    return [UIColor systemOrangeColor];
}

- (UIColor *)textColor {
    if (self.isWinterTheme) {
        return [self isDarkMode] ? [UIColor colorWithRed:0.95 green:0.97 blue:1.0 alpha:1.0] : [UIColor colorWithRed:0.20 green:0.25 blue:0.35 alpha:1.0];
    }
    return [self isDarkMode] ? [UIColor whiteColor] : [UIColor blackColor];
}

- (UIColor *)secondaryTextColor {
    if (self.isWinterTheme) {
        return [self isDarkMode] ? [UIColor colorWithRed:0.65 green:0.72 blue:0.80 alpha:1.0] : [UIColor colorWithRed:0.45 green:0.55 blue:0.65 alpha:1.0];
    }
    return [UIColor colorWithWhite:0.5 alpha:1.0];
}

- (UIColor *)pillColor {
    if (self.isWinterTheme) {
        return [self isDarkMode] ? [UIColor colorWithRed:0.12 green:0.18 blue:0.25 alpha:1.0] : [UIColor colorWithRed:0.94 green:0.96 blue:0.98 alpha:1.0];
    }
    if ([self isDarkMode]) {
        UIColor *theme = [self accentColor];
        CGFloat r, g, b, a;
        [theme getRed:&r green:&g blue:&b alpha:&a];
        return [UIColor colorWithRed:r * 0.15 green:g * 0.15 blue:b * 0.15 alpha:1.0];
    }
    return [UIColor colorWithWhite:0.96 alpha:1.0];
}

- (BOOL)isLiquidTheme {
    NSDictionary *state = [self readUIStateJSON];
    if ([state[@"licenseUITheme"] isKindOfClass:[NSString class]])
        return [state[@"licenseUITheme"] isEqualToString:@"liquid"];
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    if ([ud objectForKey:@"LicenseUITheme"] == nil)
        return YES; // Liquid is default when no preference saved
    return [ud boolForKey:@"LicenseUITheme"];
}

- (UIColor *)backgroundColor {
    if (self.isWinterTheme) {
        return [self isDarkMode] ? [UIColor colorWithRed:0.08 green:0.12 blue:0.18 alpha:1.0] : [UIColor colorWithRed:0.98 green:0.99 blue:1.0 alpha:1.0];
    }
    if ([self isDarkMode]) {
        UIColor *theme = [self accentColor];
        CGFloat r, g, b, a;
        [theme getRed:&r green:&g blue:&b alpha:&a];
        return [UIColor colorWithRed:r * 0.05 green:g * 0.05 blue:b * 0.05 alpha:1.0];
    }
    UIColor *theme = [self accentColor];
    CGFloat r, g, b, a;
    [theme getRed:&r green:&g blue:&b alpha:&a];
    return [UIColor colorWithRed:0.95 + r * 0.05 green:0.95 + g * 0.05 blue:0.95 + b * 0.05 alpha:1.0];
}

- (void)applyLiquidGlassToDialog:(UIView *)dialog {
    if (@available(iOS 13.0, *)) {
        UIBlurEffect *blurEffect = [UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemUltraThinMaterial];
        UIVisualEffectView *blurView = [[UIVisualEffectView alloc] initWithEffect:blurEffect];
        blurView.frame = dialog.bounds;
        blurView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        blurView.layer.cornerRadius = 28;
        blurView.layer.masksToBounds = YES;
        [dialog insertSubview:blurView atIndex:0];
        UIView *tintView = [[UIView alloc] initWithFrame:dialog.bounds];
        tintView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        tintView.backgroundColor = [[self accentColor] colorWithAlphaComponent:0.04];
        tintView.layer.cornerRadius = 28;
        tintView.layer.masksToBounds = YES;
        tintView.userInteractionEnabled = NO;
        [dialog insertSubview:tintView atIndex:1];
    }
    dialog.layer.borderWidth = 0.5;
    dialog.layer.borderColor = [[self accentColor] colorWithAlphaComponent:0.25].CGColor;
}

- (void)dismissCurrentDialog {
    if (!self.currentDialog) {
        // Still remove blur if dialog is nil
        UIWindow *window = [self getKeyWindow];
        if (window) {
            UIView *blurByTag = [window viewWithTag:99999];
            if (blurByTag) {
                [blurByTag removeFromSuperview];
            }
        }
        if (self.blurBackgroundView) {
            [self.blurBackgroundView removeFromSuperview];
            self.blurBackgroundView = nil;
        }
        // Reset flag
        self.isShowingKeyInfo = NO;
        return;
    }
    
    // Invalidate key info timer if exists
    if (self.keyInfoTimer) {
        [self.keyInfoTimer invalidate];
        self.keyInfoTimer = nil;
    }
    
    UIWindow *window = [self getKeyWindow];
    if (!window) return;
    
    UIView *dialogToDismiss = self.currentDialog;
    UIView *blurToDismiss = self.blurBackgroundView;
    
    // Clear references immediately to prevent double dismissal
    self.currentDialog = nil;
    self.authDialog = nil;
    self.keyInfoDialog = nil;
    self.blurBackgroundView = nil;
    self.originalDialogFrame = CGRectZero;
    self.isShowingKeyInfo = NO;
    self.isShowingError = NO;
    self.isShowingPackageError = NO;
    self.isShowingCopiedAlert = NO;
    
    const NSInteger kLiquidKeyInfoTag = 88888;
    if (dialogToDismiss.tag == kLiquidKeyInfoTag) {
        // Dismiss liquid key-info with one-by-one out animation (same style as when it appeared)
        NSArray *contentViews = [dialogToDismiss.subviews copy];
        if (contentViews.count == 0) {
            [dialogToDismiss removeFromSuperview];
            if (blurToDismiss) [blurToDismiss removeFromSuperview];
            UIView *blurByTag = [window viewWithTag:99999];
            if (blurByTag) [blurByTag removeFromSuperview];
            return;
        }
        NSTimeInterval stagger = 0.1;
        NSTimeInterval lastDelay = (contentViews.count - 1) * stagger + 0.35;
        for (NSInteger i = 0; i < contentViews.count; i++) {
            UIView *v = contentViews[i];
            [UIView animateWithDuration:0.4 delay:(double)i * stagger options:UIViewAnimationOptionCurveEaseIn animations:^{
                v.alpha = 0;
                v.transform = CGAffineTransformMakeTranslation(-64, 0);
            } completion:nil];
        }
        [UIView animateWithDuration:0.4 delay:lastDelay options:0 animations:^{
            if (blurToDismiss) blurToDismiss.alpha = 0;
        } completion:^(BOOL finished) {
            [dialogToDismiss removeFromSuperview];
            if (blurToDismiss) [blurToDismiss removeFromSuperview];
            UIView *blurByTag = [window viewWithTag:99999];
            if (blurByTag) [blurByTag removeFromSuperview];
        }];
    } else {
        [UIView animateWithDuration:0.5 animations:^{
            if (blurToDismiss) blurToDismiss.alpha = 0;
            dialogToDismiss.alpha = 0;
            dialogToDismiss.transform = CGAffineTransformMakeScale(0.8, 0.8);
        } completion:^(BOOL finished) {
            [dialogToDismiss removeFromSuperview];
            if (blurToDismiss) [blurToDismiss removeFromSuperview];
            UIView *blurByTag = [window viewWithTag:99999];
            if (blurByTag) [blurByTag removeFromSuperview];
        }];
    }
}

- (UIWindow *)getKeyWindow {
    // Ensure we're on main thread for UI operations
    if (![NSThread isMainThread]) {
        __block UIWindow *result = nil;
        dispatch_sync(dispatch_get_main_queue(), ^{
            result = [self getKeyWindow];
        });
        return result;
    }
    
    UIWindow *window = [UIApplication sharedApplication].keyWindow;
    if (!window) {
        if (@available(iOS 13.0, *)) {
            for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
                if (scene.activationState == UISceneActivationStateForegroundActive) {
                    for (UIWindow *w in scene.windows) {
                        if (w.isKeyWindow) {
                            window = w;
                            break;
                        }
                    }
                }
                if (window) break;
            }
        }
    }
    if (!window) {
        NSArray *windows = [UIApplication sharedApplication].windows;
        if (windows && windows.count > 0) {
            window = windows.lastObject;
        }
    }
    return window;
}

- (void)addBlurBackground {
    UIWindow *window = [self getKeyWindow];
    if (!window) return;
    
    // Liquid theme: transparent glass — clear window so no white shows through
    if ([self isLiquidTheme]) {
        window.backgroundColor = [UIColor clearColor];
    }
    
    // Remove existing blur first
    if (self.blurBackgroundView) {
        [self.blurBackgroundView removeFromSuperview];
        self.blurBackgroundView = nil;
    }
    
    // Remove blur by tag
    UIView *existingBlur = [window viewWithTag:99999];
    if (existingBlur) {
        [existingBlur removeFromSuperview];
    }
    
    // Liquid: true liquid glass (adaptive ultra-thin, like iOS 26); Default: dark/light blur
    BOOL isDark = [self isDarkMode];
    UIBlurEffect *blurEffect = nil;
    if ([self isLiquidTheme]) {
        if (@available(iOS 13.0, *)) {
            blurEffect = [UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemUltraThinMaterial];
        } else {
            blurEffect = [UIBlurEffect effectWithStyle:isDark ? UIBlurEffectStyleDark : UIBlurEffectStyleLight];
        }
    } else {
        blurEffect = [UIBlurEffect effectWithStyle:isDark ? UIBlurEffectStyleDark : UIBlurEffectStyleLight];
    }
    UIVisualEffectView *blurView = [[UIVisualEffectView alloc] initWithEffect:blurEffect];
    blurView.frame = [UIScreen mainScreen].bounds;
    blurView.alpha = 0;
    blurView.tag = 99999;
    blurView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.blurBackgroundView = blurView;
    [window addSubview:blurView];
    
    // Apply stream mode protection
    UpdateStreamProtectionForView(blurView);
    
    [UIView animateWithDuration:0.6 animations:^{
        blurView.alpha = 1.0;
    }];
}

- (NSString *)sha256:(NSString *)input {
    if (!input || input.length == 0) return @"";
    
    const char *cstr = [input UTF8String];
    if (!cstr) return @"";
    
    size_t len = strlen(cstr);
    if (len == 0) return @"";
    
    NSData *data = [NSData dataWithBytes:cstr length:len];
    if (!data || data.length == 0) return @"";
    
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, hash);
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", hash[i]];
    }
    return output;
}

- (void)start {
    // ===== STEP 1: DISABLE FEATURES IMMEDIATELY =====
    Vars.ewid = false;
    
    // Security check on startup
    if (dG3_pq1() || pX4_yr2()) {
        Vars.ewid = false;  // SECURITY BREACH - DISABLE
        dispatch_async(dispatch_get_main_queue(), ^{
            xF9_ab2();
        });
        return;
    }
    
    // ===== STEP 2: CHECK IF KEY EXISTS IN KEYCHAIN FIRST =====
    // Reload key from keychain to ensure we have latest value
    NSString *savedKey = [KeychainHelper load:@"key"];
    self.currentKey = savedKey;
    
    // ===== STEP 3: IF NO KEY - SHOW AUTH UI DIRECTLY (NO LOADING/INFO) =====
    if (!self.currentKey || self.currentKey.length == 0) {
        // NO KEY EXISTS - Show auth UI directly, skip loading/info
        Vars.ewid = false;
        dispatch_async(dispatch_get_main_queue(), ^{
            // Make sure no dialogs are showing
            if (self.currentDialog && self.currentDialog != self.authDialog) {
                [self dismissCurrentDialog];
            }
            if (self.loadingDialog) {
                [self dismissLoadingDialog];
            }
            // Show auth UI after cleanup - it will stay until valid key is entered
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                // Only show if not already showing
                if (!self.isShowingUI) {
                    [self showAuthUI];
                }
            });
        });
        return;
    }
    
    // ===== STEP 4: KEY EXISTS - SHOW LOADING AND VALIDATE =====
    // Show loading dialog only if key exists
    if (!self.isShowingLoading) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self showLoadingDialog:@"正在驗證套件..."];
        });
    }
    
    // ===== STEP 5: CHECK PACKAGE FIRST =====
    [[PackageValidator shared] validatePackageWithCompletion:^(BOOL valid, NSString *error, NSDictionary *packageData) {
        
        if (!valid) {
            // ===== PACKAGE VALIDATION FAILED =====
            Vars.ewid = false;
            
            NSString *errorMsg = @"無法驗證應用程式套件";
            if ([error isEqualToString:@"package_not_found"]) {
                errorMsg = @"此版本不受支援";
            } else if ([error isEqualToString:@"package_inactive"]) {
                errorMsg = @"應用程式維護中";
            } else if ([error isEqualToString:@"version_mismatch"]) {
                errorMsg = @"版本不匹配，請更新";
            } else if ([error isEqualToString:@"app_id_mismatch"]) {
                errorMsg = @"應用程式ID不匹配";
            } else if ([error isEqualToString:@"signature_mismatch"]) {
                errorMsg = @"簽名驗證失敗";
            } else if ([error isEqualToString:@"network_error"]) {
                errorMsg = @"網路連接失敗";
            } else if ([error isEqualToString:@"decryption_failed"]) {
                errorMsg = @"解密失敗";
            }
            
            dispatch_async(dispatch_get_main_queue(), ^{
                [self dismissLoadingDialog];
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                    [self showPackageErrorDialog:errorMsg];
                });
            });
            return;
        }
        
        // ===== STEP 6: PACKAGE VALID, NOW CHECK LICENSE =====
        self.packageValidated = YES;
        self.packageInfo = packageData;
        
        // Update loading message
        dispatch_async(dispatch_get_main_queue(), ^{
            [self updateLoadingMessage:@"正在驗證金鑰..."];
        });
        
        // Security check before license validation
        if (dG3_pq1() || pX4_yr2()) {
            Vars.ewid = false;
            dispatch_async(dispatch_get_main_queue(), ^{
                [self dismissLoadingDialog];
                xF9_ab2();
            });
            return;
        }
        
        // Validate the existing key
        [self validateKey:self.currentKey completion:^(BOOL valid, NSString *reason, NSDictionary *info) {
            if (valid) {
                // ===== STEP 7: LICENSE VALID - ENABLE FEATURES =====
                self.isAuthenticated = YES;
                self.keyInfo = info;
                Vars.ewid = true;  // ✅ FEATURES ENABLED
                
                // Calculate remaining time: ensure loading shows for at least 2 seconds
                // Total display time: 6 seconds, so info shows for remaining time
                dispatch_async(dispatch_get_main_queue(), ^{
                    NSTimeInterval elapsed = [[NSDate date] timeIntervalSinceDate:self.loadingStartTime];
                    NSTimeInterval minLoadingTime = 2.0; // Minimum 2 seconds loading
                    NSTimeInterval remainingLoadingTime = MAX(0, minLoadingTime - elapsed);
                    NSTimeInterval totalDisplayTime = 6.0; // Total 6 seconds
                    NSTimeInterval infoDisplayTime = totalDisplayTime - minLoadingTime; // Info shows for 4 seconds
                    
                    // Wait for minimum loading time, then show info
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, remainingLoadingTime * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                        [self dismissLoadingDialog];
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                            [self showKeyInfoWithDuration:infoDisplayTime];
                        });
                    });
                });
                [self sB6_mq8];  // This will check BOTH package and license
                
            } else {
                // ===== LICENSE INVALID - INSTANT APPLY: BANNED/SERVER/ERROR → CRASH; OTHERWISE SHOW AUTH =====
                Vars.ewid = false;
                BOOL fatal = ([reason containsString:@"banned"] || [reason containsString:@"network"] || [reason containsString:@"server"]
                             || [reason containsString:@"invalid_response"] || [reason containsString:@"missing_var"]);
                if (fatal) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [self dismissLoadingDialog];
                        [self tA7_rt9];
                        xF9_ab2();
                    });
                } else {
                    // Invalid key (e.g. wrong key, expired) - clear and show auth UI
                    [KeychainHelper delete:@"key"];
                    self.currentKey = nil;
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [self dismissLoadingDialog];
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                            [self showAuthUI];
                        });
                    });
                }
            }
        }];
    }];
}

- (void)validateKey:(NSString *)key completion:(void(^)(BOOL valid, NSString *reason, NSDictionary *info))completion {
    if (!key || key.length == 0) {
        Vars.ewid = false;  // ❌ NO KEY
        if (completion) completion(NO, @"no_key", nil);
        return;
    }
    
    // Security check before validation
    if (dG3_pq1() || pX4_yr2()) {
        Vars.ewid = false;  // ❌ SECURITY BREACH
        if (completion) completion(NO, @"security_breach", nil);
        dispatch_async(dispatch_get_main_queue(), ^{
            xF9_ab2();
        });
        return;
    }
    
    // Validate udid exists to prevent crashes
    if (!self.udid || self.udid.length == 0) {
        Vars.ewid = false;  // ❌ NO UDID
        if (completion) completion(NO, @"no_udid", nil);
        return;
    }
    
    NSTimeInterval timestamp = [[NSDate date] timeIntervalSince1970];
    NSInteger ts = (NSInteger)timestamp;
    
    // USE ENCRYPTED VERSION HERE
    // Use local copies to prevent crashes if self is deallocated
    NSString *udidCopy = [self.udid copy];
    NSString *secretPassword = _decryptSecretPassword();
    if (!udidCopy || !secretPassword) {
        Vars.ewid = false;
        if (completion) completion(NO, @"internal_error", nil);
        return;
    }
    
    NSString *challengeInput = [NSString stringWithFormat:@"%@%ld%@", udidCopy, (long)ts, secretPassword];
    NSString *challenge = [self sha256:challengeInput];
    
    // Prepare payload - use local copies (app_id/package_id so server can enforce package restriction)
    if (!challenge) {
        Vars.ewid = false;
        if (completion) completion(NO, @"challenge_error", nil);
        return;
    }
    
    NSMutableDictionary *payload = [NSMutableDictionary dictionaryWithDictionary:@{
        @"password": challenge,
        @"udid": udidCopy,
        @"timestamp": @(ts),
        @"license_key": key
    }];
    NSString *appId = [[NSBundle mainBundle] bundleIdentifier];
    if (appId.length) payload[@"app_id"] = appId;
    if (self.packageInfo[@"package_id"]) payload[@"package_id"] = self.packageInfo[@"package_id"];
    
    // Convert to JSON string
    NSError *jsonError;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:payload options:0 error:&jsonError];
    if (jsonError || !jsonData) {
        Vars.ewid = false;  // ❌ JSON ERROR
        if (completion) completion(NO, @"json_error", nil);
        return;
    }
    
    NSString *jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    if (!jsonString) {
        Vars.ewid = false;
        if (completion) completion(NO, @"encoding_error", nil);
        return;
    }
    
    // Encrypt the entire payload - use local copy of udid
    NSString *rollingKey = [EncryptionHelper generateRollingKey:ts udid:udidCopy];
    if (!rollingKey) {
        Vars.ewid = false;
        if (completion) completion(NO, @"rolling_key_error", nil);
        return;
    }
    
    NSString *encryptedPayload = [EncryptionHelper xorEncrypt:jsonString withKey:rollingKey];
    
    if (!encryptedPayload) {
        Vars.ewid = false;  // ❌ ENCRYPTION FAILED
        if (completion) completion(NO, @"encryption_failed", nil);
        return;
    }
    
    // Send encrypted request - USE ENCRYPTED VERSION HERE
    NSDictionary *encryptedRequest = @{
        @"data": encryptedPayload,
        @"timestamp": @(ts),
        @"udid": self.udid,
        @"format": @"full_encrypted"
    };
    
    NSData *requestData = [NSJSONSerialization dataWithJSONObject:encryptedRequest options:0 error:&jsonError];
    if (jsonError || !requestData) {
        Vars.ewid = false;  // ❌ REQUEST ERROR
        if (completion) completion(NO, @"request_error", nil);
        return;
    }
    
    // USE ENCRYPTED VERSION HERE
    // Validate server URL exists
    NSString *serverURL = _decryptServerURL();
    if (!serverURL) {
        Vars.ewid = false;
        if (completion) completion(NO, @"server_url_error", nil);
        return;
    }
    
    NSURL *url = [NSURL URLWithString:serverURL];
    if (!url) {
        Vars.ewid = false;
        if (completion) completion(NO, @"invalid_url", nil);
        return;
    }
    
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    [request setHTTPMethod:@"POST"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [request setHTTPBody:requestData];
    [request setTimeoutInterval:10]; // 10 second timeout to prevent hanging
    
    __weak KeyAuthSystem *weakSelf = self;
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        KeyAuthSystem *strongSelf = weakSelf;
        if (!strongSelf) {
            // Object deallocated, safe to exit
            return;
        }
        
        // Handle network errors gracefully instead of crashing
        if (error) {
            Vars.ewid = false;  // ❌ NETWORK ERROR
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, @"network_error", nil);
            });
            return;
        }
        
        if (!data || data.length == 0) {
            Vars.ewid = false;  // ❌ NO DATA
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, @"no_data", nil);
            });
            return;
        }
        
        NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
        if (httpResponse.statusCode != 200) {
            Vars.ewid = false;  // ❌ SERVER ERROR
            dispatch_async(dispatch_get_main_queue(), ^{
                KeyAuthSystem *strongSelf2 = weakSelf;
                if (strongSelf2 && completion) completion(NO, @"server_error", nil);
            });
            return;
        }
        
        NSError *jsonError;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
        
        if (!json || jsonError) {
            Vars.ewid = false;  // ❌ PARSE ERROR
            dispatch_async(dispatch_get_main_queue(), ^{
                KeyAuthSystem *strongSelf3 = weakSelf;
                if (strongSelf3 && completion) completion(NO, @"server_error", nil);
            });
            return;
        }
        
        // ALWAYS check for 'var' in response - more strict validation
        BOOL hasValidVar = NO;
        NSString *varValue = nil;
        
        // Check if response is encrypted
        if (json[@"data"] && json[@"timestamp"] && json[@"format"]) {
            // Decrypt the response
            // Validate all required fields exist before accessing
            id timestampObj = json[@"timestamp"];
            id dataObj = json[@"data"];
            
            if (!timestampObj || !dataObj || ![dataObj isKindOfClass:[NSString class]]) {
                Vars.ewid = false;
                dispatch_async(dispatch_get_main_queue(), ^{
                    KeyAuthSystem *strongSelf4 = weakSelf;
                    if (strongSelf4 && completion) completion(NO, @"invalid_response_format", nil);
                });
                return;
            }
            
            NSInteger serverTs = [timestampObj integerValue];
            NSString *udidForDecrypt = strongSelf.udid ?: @"";
            if (udidForDecrypt.length == 0) {
                Vars.ewid = false;
                dispatch_async(dispatch_get_main_queue(), ^{
                    KeyAuthSystem *strongSelf4 = weakSelf;
                    if (strongSelf4 && completion) completion(NO, @"no_udid", nil);
                });
                return;
            }
            
            NSString *rollingKey = [EncryptionHelper generateRollingKey:serverTs udid:udidForDecrypt];
            if (!rollingKey) {
                Vars.ewid = false;
                dispatch_async(dispatch_get_main_queue(), ^{
                    KeyAuthSystem *strongSelf4 = weakSelf;
                    if (strongSelf4 && completion) completion(NO, @"rolling_key_error", nil);
                });
                return;
            }
            
            NSString *decryptedData = [EncryptionHelper xorDecrypt:(NSString *)dataObj withKey:rollingKey];
            
            if (!decryptedData) {
                Vars.ewid = false;  // ❌ DECRYPTION FAILED
                dispatch_async(dispatch_get_main_queue(), ^{
                    KeyAuthSystem *strongSelf4 = weakSelf;
                    if (strongSelf4 && completion) completion(NO, @"decryption_failed", nil);
                });
                return;
            }
            
            // Parse decrypted JSON
            NSData *decryptedJsonData = [decryptedData dataUsingEncoding:NSUTF8StringEncoding];
            NSDictionary *decryptedJson = [NSJSONSerialization JSONObjectWithData:decryptedJsonData options:0 error:&jsonError];
            
            if (!decryptedJson || jsonError) {
                Vars.ewid = false;  // ❌ INVALID RESPONSE
                dispatch_async(dispatch_get_main_queue(), ^{
                    KeyAuthSystem *strongSelf5 = weakSelf;
                    if (strongSelf5 && completion) completion(NO, @"invalid_response", nil);
                });
                return;
            }
            
            // Process the decrypted response
            varValue = decryptedJson[@"var"];
            NSString *reason = decryptedJson[@"reason"] ?: @"unknown";
            
            // STRICT CHECK: Must have "var" field
            if (!varValue) {
                Vars.ewid = false;  // ❌ MISSING VAR
                dispatch_async(dispatch_get_main_queue(), ^{
                    KeyAuthSystem *strongSelf6 = weakSelf;
                    if (strongSelf6 && completion) completion(NO, @"missing_var_field", nil);
                });
                return;
            }
            
            hasValidVar = [varValue isEqualToString:@"momo"];
            
            dispatch_async(dispatch_get_main_queue(), ^{
                KeyAuthSystem *strongSelf7 = weakSelf;
                if (!strongSelf7) return;
                
                if (hasValidVar) {
                    // ===== SUCCESS: ENABLE FEATURES =====
                    Vars.ewid = true;  // ✅ FEATURES ENABLED
                    
                    NSDictionary *info = @{
                        @"key": key,
                        @"udid": strongSelf7.udid,
                        @"timestamp": decryptedJson[@"timestamp"] ?: @"",
                        @"signature": decryptedJson[@"signature"] ?: @"",
                        @"response_time": [NSDate date]
                    };
                    if (completion) completion(YES, @"valid", info);
                } else {
                    // ===== INVALID VAR: DISABLE FEATURES =====
                    Vars.ewid = false;  // ❌ FEATURES DISABLED
                    if (completion) completion(NO, reason, nil);
                }
            });
            
        } else if (json[@"var"] && json[@"timestamp"]) {
            // Old format (backward compatibility)
            KeyAuthSystem *strongSelf9 = weakSelf;
            if (!strongSelf9) return;
            
            // Validate fields exist and are correct type
            id varObj = json[@"var"];
            id timestampObj = json[@"timestamp"];
            
            if (!varObj || ![varObj isKindOfClass:[NSString class]]) {
                Vars.ewid = false;
                dispatch_async(dispatch_get_main_queue(), ^{
                    KeyAuthSystem *strongSelf8 = weakSelf;
                    if (strongSelf8 && completion) completion(NO, @"invalid_response", nil);
                });
                return;
            }
            
            NSString *encryptedVar = (NSString *)varObj;
            NSString *serverTimestamp = [timestampObj stringValue];
            
            if (!encryptedVar || encryptedVar.length == 0 || !serverTimestamp || serverTimestamp.length == 0) {
                Vars.ewid = false;  // ❌ INVALID RESPONSE
                dispatch_async(dispatch_get_main_queue(), ^{
                    KeyAuthSystem *strongSelf8 = weakSelf;
                    if (strongSelf8 && completion) completion(NO, @"invalid_response", nil);
                });
                return;
            }
            
            // Validate udid exists
            NSString *udidForDecrypt = strongSelf9.udid ?: @"";
            if (udidForDecrypt.length == 0) {
                Vars.ewid = false;
                dispatch_async(dispatch_get_main_queue(), ^{
                    if (completion) completion(NO, @"no_udid", nil);
                });
                return;
            }
            
            NSString *rollingKey = [EncryptionHelper generateRollingKey:[serverTimestamp integerValue] udid:udidForDecrypt];
            if (!rollingKey) {
                Vars.ewid = false;
                dispatch_async(dispatch_get_main_queue(), ^{
                    if (completion) completion(NO, @"rolling_key_error", nil);
                });
                return;
            }
            
            NSString *decryptedVar = [EncryptionHelper xorDecrypt:encryptedVar withKey:rollingKey];
            NSString *reason = json[@"reason"] ?: @"unknown";
            
            // STRICT CHECK: Must have decrypted "var" field
            if (!decryptedVar) {
                Vars.ewid = false;  // ❌ MISSING VAR
                dispatch_async(dispatch_get_main_queue(), ^{
                    KeyAuthSystem *strongSelf10 = weakSelf;
                    if (strongSelf10 && completion) completion(NO, @"missing_var_field", nil);
                });
                return;
            }
            
            hasValidVar = [decryptedVar isEqualToString:@"momo"];
            varValue = decryptedVar;
            
            dispatch_async(dispatch_get_main_queue(), ^{
                KeyAuthSystem *strongSelf11 = weakSelf;
                if (!strongSelf11) return;
                
                if (hasValidVar) {
                    // ===== SUCCESS: ENABLE FEATURES =====
                    Vars.ewid = true;  // ✅ FEATURES ENABLED
                    
                    NSDictionary *info = @{
                        @"key": key,
                        @"udid": strongSelf11.udid,
                        @"timestamp": json[@"timestamp"] ?: @"",
                        @"response_time": [NSDate date]
                    };
                    if (completion) completion(YES, @"valid", info);
                } else {
                    // ===== INVALID VAR: DISABLE FEATURES =====
                    Vars.ewid = false;  // ❌ FEATURES DISABLED
                    if (completion) completion(NO, reason, nil);
                }
            });
        } else {
            // ===== NO VALID FORMAT: DISABLE FEATURES =====
            Vars.ewid = false;  // ❌ FEATURES DISABLED
            dispatch_async(dispatch_get_main_queue(), ^{
                KeyAuthSystem *strongSelf12 = weakSelf;
                if (strongSelf12 && completion) completion(NO, @"invalid_response_format", nil);
            });
        }
    }];
    
    // Store task reference to allow cancellation if needed
    [task resume];
}

- (void)sB6_mq8 {
    // Main queue; invalidate existing timers before creating new ones.
    __weak KeyAuthSystem *weakSelf = self;
    dispatch_async(dispatch_get_main_queue(), ^{
        KeyAuthSystem *strongSelf = weakSelf;
        if (!strongSelf) return;
        // Invalidate existing timers synchronously (we're on main)
        if (strongSelf.checkTimer) {
            [strongSelf.checkTimer invalidate];
            strongSelf.checkTimer = nil;
        }
        if (strongSelf.dyldTimer) {
            [strongSelf.dyldTimer invalidate];
            strongSelf.dyldTimer = nil;
        }
        if (strongSelf.infoTimer) {
            [strongSelf.infoTimer invalidate];
            strongSelf.infoTimer = nil;
        }
        strongSelf.isCheckingInProgress = NO;
#if XQ7_Mn2_Kp9
        // Create timers with timerWithTimeInterval (does NOT add to run loop), then add ONCE.
        // Do NOT use scheduledTimer + addTimer — that can double-add and cause crashes.
        strongSelf.checkTimer = [NSTimer timerWithTimeInterval:Iv8_Tm3
                                                       target:strongSelf
                                                     selector:@selector(bC5_nk7)
                                                     userInfo:nil
                                                      repeats:YES];
        [[NSRunLoop mainRunLoop] addTimer:strongSelf.checkTimer forMode:NSRunLoopCommonModes];

        strongSelf.dyldTimer = [NSTimer timerWithTimeInterval:30.0
                                                       target:strongSelf
                                                     selector:@selector(sD1_ly2)
                                                     userInfo:nil
                                                      repeats:YES];
        [[NSRunLoop mainRunLoop] addTimer:strongSelf.dyldTimer forMode:NSRunLoopCommonModes];

        strongSelf.infoTimer = [NSTimer timerWithTimeInterval:60.0
                                                       target:strongSelf
                                                     selector:@selector(sI3_nf4)
                                                     userInfo:nil
                                                      repeats:YES];
        [[NSRunLoop mainRunLoop] addTimer:strongSelf.infoTimer forMode:NSRunLoopCommonModes];

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            KeyAuthSystem *s = weakSelf;
            if (s) {
                [s sD1_ly2];
                [s sI3_nf4];
            }
        });
#endif
    });
}

- (void)bC5_nk7 {
    if ([UIApplication sharedApplication].applicationState != UIApplicationStateActive) {
        return;
    }
    if (self.isCheckingInProgress) return;
    if (!self.isAuthenticated || !self.currentKey) {
        dispatch_async(dispatch_get_main_queue(), ^{ Vars.ewid = false; });
        return;
    }
    NSString *keyToValidate = [self.currentKey copy];
    if (!keyToValidate || keyToValidate.length == 0) {
        dispatch_async(dispatch_get_main_queue(), ^{ Vars.ewid = false; });
        return;
    }
    self.isCheckingInProgress = YES;
    __weak KeyAuthSystem *weakSelf = self;
    // Stale guard: if check never completes (e.g. network hang), reset flag after 18s so next cycle can run
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(18 * NSEC_PER_SEC)), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        KeyAuthSystem *s = weakSelf;
        if (s && s.isCheckingInProgress) s.isCheckingInProgress = NO;
    });
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        KeyAuthSystem *strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        // Security checks on background (avoid blocking main thread / UI)
        if (dG3_pq1() || pX4_yr2()) {
            strongSelf.isCheckingInProgress = NO;
            dispatch_async(dispatch_get_main_queue(), ^{
                Vars.ewid = false;
                [strongSelf tA7_rt9];
                xF9_ab2();
            });
            return;
        }
        // Package + license validation (network) — completions may run on background or session queue
        [[PackageValidator shared] validatePackageWithCompletion:^(BOOL packageValid, NSString *packageError, NSDictionary *packageData) {
            KeyAuthSystem *s1 = weakSelf;
            if (!s1) return;
            if (!packageValid) {
                s1.isCheckingInProgress = NO;
                dispatch_async(dispatch_get_main_queue(), ^{
                    Vars.ewid = false;
                    [s1 tA7_rt9];
                    xF9_ab2();
                });
                return;
            }
            if (!s1.currentKey || s1.currentKey.length == 0) {
                s1.isCheckingInProgress = NO;
                dispatch_async(dispatch_get_main_queue(), ^{ Vars.ewid = false; });
                return;
            }
            [s1 validateKey:keyToValidate completion:^(BOOL licenseValid, NSString *reason, NSDictionary *info) {
                KeyAuthSystem *s2 = weakSelf;
                if (!s2) return;
                s2.isCheckingInProgress = NO;
                if (!licenseValid) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        Vars.ewid = false;
                        [s2 tA7_rt9];
                        xF9_ab2();
                    });
                } else {
                    dispatch_async(dispatch_get_main_queue(), ^{ Vars.ewid = true; });
                }
            }];
        }];
    });
}

- (void)tA7_rt9 {
    // Always invalidate timers on main thread to prevent crashes
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.checkTimer) {
            [self.checkTimer invalidate];
            self.checkTimer = nil;
        }
        if (self.dyldTimer) {
            [self.dyldTimer invalidate];
            self.dyldTimer = nil;
        }
        if (self.infoTimer) {
            [self.infoTimer invalidate];
            self.infoTimer = nil;
        }
        if (self.authTimeoutTimer) {
            [self.authTimeoutTimer invalidate];
            self.authTimeoutTimer = nil;
        }
        if (self.keyInfoTimer) {
            [self.keyInfoTimer invalidate];
            self.keyInfoTimer = nil;
        }
        // Reset checking flag when stopping timers
        self.isCheckingInProgress = NO;
    });
}

- (void)sD1_ly2 {
    if (!self.currentKey) return;
    // Run off main thread so timer callback returns immediately (avoids main-thread stall/crash)
    __weak KeyAuthSystem *weakSelf = self;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        KeyAuthSystem *s = weakSelf;
        if (!s || !s.currentKey) return;
        [[DyldMonitor shared] sendDyldListToServerWithInfo:s.udid
                                                licenseKey:s.currentKey
                                                completion:^(BOOL success, NSString *error) {}];
    });
}

- (void)sI3_nf4 {
    if (!self.currentKey) return;
    __weak KeyAuthSystem *weakSelf = self;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        KeyAuthSystem *s = weakSelf;
        if (!s || !s.currentKey) return;
        [[InfoSystem shared] sendInfoToServer:s.udid
                                 licenseKey:s.currentKey
                                 completion:^(BOOL success) {}];
    });
}

#pragma mark - Auth / Dialogs

- (void)showAuthUI {
    if (self.isShowingUI) return;
    
    self.isShowingUI = YES;
    
    Vars.ewid = false;
    self.authStartTime = [NSDate date];
    [self startAuthTimeoutTimer];
    
    dispatch_async(dispatch_get_main_queue(), ^{
        // Security check before showing UI
        if (dG3_pq1() || pX4_yr2()) {
            Vars.ewid = false;
            dispatch_async(dispatch_get_main_queue(), ^{
                xF9_ab2();
            });
            return;
        }
        
        // Dismiss any existing dialog
        [self dismissCurrentDialog];
        
        // Add blur background
        [self addBlurBackground];
        
        UIWindow *window = [self getKeyWindow];
        if (!window) return;
        
        CGFloat dialogWidth = 260;
        CGFloat dialogHeight = 200;
        
        UIView *dialog = [[UIView alloc] initWithFrame:CGRectMake(
            ([UIScreen mainScreen].bounds.size.width - dialogWidth) / 2,
            ([UIScreen mainScreen].bounds.size.height - dialogHeight) / 2,
            dialogWidth, dialogHeight)];
        if ([self isLiquidTheme]) {
            dialog.backgroundColor = [UIColor clearColor];
            dialog.layer.cornerRadius = 28;
            dialog.layer.masksToBounds = YES;
            [self applyLiquidGlassToDialog:dialog];
        } else {
            dialog.backgroundColor = [self pillColor];
            dialog.layer.cornerRadius = 28;
            dialog.layer.masksToBounds = YES;
        }
        dialog.layer.shadowColor = [UIColor blackColor].CGColor;
        dialog.layer.shadowOpacity = 0.5;
        dialog.layer.shadowRadius = 25;
        dialog.layer.shadowOffset = CGSizeMake(0, 12);
        dialog.alpha = 0;
        dialog.transform = CGAffineTransformMakeScale(0.85, 0.85);
        
        self.currentDialog = dialog;
        self.authDialog = dialog;
        
        UILabel *titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(0, 16, dialogWidth, 28)];
        titleLabel.text = KEYAUTH_APP_DISPLAY_NAME;
        titleLabel.font = [UIFont systemFontOfSize:24 weight:UIFontWeightBold];
        titleLabel.textColor = [self accentColor];
        titleLabel.textAlignment = NSTextAlignmentCenter;
        [dialog addSubview:titleLabel];
        
        NSString *packageVersionInfo = @"";
        if (self.packageInfo) {
            packageVersionInfo = [NSString stringWithFormat:@"版本: %@\n", self.packageInfo[@"version"]];
        }
        UILabel *messageLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, 42, dialogWidth - 32, 40)];
        messageLabel.text = [NSString stringWithFormat:@"%@請輸入您的金鑰", packageVersionInfo];
        messageLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightRegular];
        messageLabel.textColor = [self secondaryTextColor];
        messageLabel.numberOfLines = 2;
        messageLabel.textAlignment = NSTextAlignmentCenter;
        [dialog addSubview:messageLabel];
        
        // Text field - more oval/curved shape
        UITextField *keyTextField = [[UITextField alloc] initWithFrame:CGRectMake(14, 82, dialogWidth - 28, 36)];
        keyTextField.placeholder = @"金鑰";
        keyTextField.autocapitalizationType = UITextAutocapitalizationTypeNone;
        keyTextField.autocorrectionType = UITextAutocorrectionTypeNo;
        keyTextField.keyboardType = UIKeyboardTypeDefault;
        keyTextField.returnKeyType = UIReturnKeyDone;
        keyTextField.backgroundColor = [self backgroundColor];
        keyTextField.textColor = [self textColor];
        keyTextField.font = [UIFont systemFontOfSize:15 weight:UIFontWeightRegular];
        keyTextField.layer.cornerRadius = 18; // Much more curve - oval shape (half of height)
        keyTextField.layer.borderWidth = 1.5;
        keyTextField.layer.borderColor = [[self accentColor] colorWithAlphaComponent:0.4].CGColor;
        keyTextField.leftView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 12, 36)];
        keyTextField.leftViewMode = UITextFieldViewModeAlways;
        keyTextField.rightView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 12, 36)];
        keyTextField.rightViewMode = UITextFieldViewModeAlways;
        
        // Add delegate to handle return key
        keyTextField.delegate = self;
        objc_setAssociatedObject(keyTextField, "dialog", dialog, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        
        // Auto-paste from clipboard if available
        NSString *clipboardText = [UIPasteboard generalPasteboard].string;
        if (clipboardText && clipboardText.length > 0) {
            // Check if it looks like a key (alphanumeric, reasonable length)
            NSCharacterSet *alphanumeric = [NSCharacterSet alphanumericCharacterSet];
            NSCharacterSet *clipboardSet = [NSCharacterSet characterSetWithCharactersInString:clipboardText];
            if ([alphanumeric isSupersetOfSet:clipboardSet] && clipboardText.length >= 8 && clipboardText.length <= 100) {
                keyTextField.text = clipboardText;
            }
        }
        
        [dialog addSubview:keyTextField];
        
        // Buttons - slightly smaller
        CGFloat buttonWidth = (dialogWidth - 40) / 2;
        
        UIButton *contactBtn = [[UIButton alloc] initWithFrame:CGRectMake(12, 124, buttonWidth, 38)];
        contactBtn.backgroundColor = [[self accentColor] colorWithAlphaComponent:0.15];
        contactBtn.layer.cornerRadius = 19; // More curve - oval shape
        [contactBtn setTitle:@"網站" forState:UIControlStateNormal];
        [contactBtn setTitleColor:[self textColor] forState:UIControlStateNormal];
        contactBtn.titleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightSemibold];
        [contactBtn addTarget:self action:@selector(contactButtonTapped:) forControlEvents:UIControlEventTouchUpInside];
        objc_setAssociatedObject(contactBtn, "textField", keyTextField, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [dialog addSubview:contactBtn];
        
        UIButton *loginBtn = [[UIButton alloc] initWithFrame:CGRectMake(28 + buttonWidth, 124, buttonWidth, 38)];
        loginBtn.backgroundColor = [self accentColor];
        loginBtn.layer.cornerRadius = 19; // More curve - oval shape
        [loginBtn setTitle:@"登入" forState:UIControlStateNormal];
        [loginBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        loginBtn.titleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightBold];
        [loginBtn addTarget:self action:@selector(loginButtonTapped:) forControlEvents:UIControlEventTouchUpInside];
        objc_setAssociatedObject(loginBtn, "textField", keyTextField, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [dialog addSubview:loginBtn];
        
        [window addSubview:dialog];
        
        // Apply stream mode protection using UpdateStreamProtectionForView
        UpdateStreamProtectionForView(dialog);
        if (self.blurBackgroundView) {
            UpdateStreamProtectionForView(self.blurBackgroundView);
        }
        
        // Better animation with spring effect (slower for liquid)
        [UIView animateWithDuration:0.65 delay:0 usingSpringWithDamping:0.72 initialSpringVelocity:0.4 options:UIViewAnimationOptionCurveEaseOut animations:^{
            dialog.alpha = 1.0;
            dialog.transform = CGAffineTransformIdentity;
        } completion:^(BOOL finished) {
            [keyTextField becomeFirstResponder];
        }];
    });
}

- (void)contactButtonTapped:(UIButton *)sender {
    UIPasteboard.generalPasteboard.string = @"fluckv2.org";
    
    [self dismissCurrentDialog];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [self showCopiedAlert];
    });
}

- (void)loginButtonTapped:(UIButton *)sender {
    UITextField *textField = objc_getAssociatedObject(sender, "textField");
    NSString *enteredKey = [textField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            
    if (enteredKey.length == 0) {
        Vars.ewid = false;
        UINotificationFeedbackGenerator *feedback = [[UINotificationFeedbackGenerator alloc] init];
        [feedback notificationOccurred:UINotificationFeedbackTypeError];
        return;
    }
    
    [textField resignFirstResponder];
    [self dismissCurrentDialog];
    
    // Store the entered key
    self.currentKey = enteredKey;
    
    // Show loading dialog - FIRST TIME KEY ENTRY
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [self showLoadingDialog:@"正在驗證套件..."];
    });
    
    // ===== STEP 1: VALIDATE PACKAGE FIRST =====
    [[PackageValidator shared] validatePackageWithCompletion:^(BOOL valid, NSString *error, NSDictionary *packageData) {
        
        if (!valid) {
            // ===== PACKAGE VALIDATION FAILED =====
            Vars.ewid = false;
            
            NSString *errorMsg = @"無法驗證應用程式套件";
            if ([error isEqualToString:@"package_not_found"]) {
                errorMsg = @"此版本不受支援";
            } else if ([error isEqualToString:@"package_inactive"]) {
                errorMsg = @"應用程式維護中";
            } else if ([error isEqualToString:@"version_mismatch"]) {
                errorMsg = @"版本不匹配，請更新";
            } else if ([error isEqualToString:@"app_id_mismatch"]) {
                errorMsg = @"應用程式ID不匹配";
            } else if ([error isEqualToString:@"signature_mismatch"]) {
                errorMsg = @"簽名驗證失敗";
            } else if ([error isEqualToString:@"network_error"]) {
                errorMsg = @"網路連接失敗";
            } else if ([error isEqualToString:@"decryption_failed"]) {
                errorMsg = @"解密失敗";
            }
            
            dispatch_async(dispatch_get_main_queue(), ^{
                [self dismissLoadingDialog];
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                    [self showPackageErrorDialog:errorMsg];
                });
            });
            return;
        }
        
        // ===== STEP 2: PACKAGE VALID, NOW VALIDATE KEY =====
        self.packageValidated = YES;
        self.packageInfo = packageData;
        
        // Update loading message
        dispatch_async(dispatch_get_main_queue(), ^{
            [self updateLoadingMessage:@"正在驗證金鑰..."];
        });
        
        // Security check before license validation
        if (dG3_pq1() || pX4_yr2()) {
            Vars.ewid = false;
            dispatch_async(dispatch_get_main_queue(), ^{
                [self dismissLoadingDialog];
                xF9_ab2();
            });
            return;
        }
        
        // ===== STEP 3: VALIDATE THE ENTERED KEY =====
        [self validateKey:enteredKey completion:^(BOOL valid, NSString *reason, NSDictionary *info) {
            if (valid) {
                // ===== STEP 4: KEY VALID - SAVE AND ENABLE FEATURES =====
                Vars.ewid = true;
                
                UINotificationFeedbackGenerator *feedback = [[UINotificationFeedbackGenerator alloc] init];
                [feedback notificationOccurred:UINotificationFeedbackTypeSuccess];
                
                // Save key to keychain
                [KeychainHelper save:enteredKey forKey:@"key"];
                [KeychainHelper save:@"0" forKey:@"attempts"];
                self.isAuthenticated = YES;
                self.failedAttempts = 0;
                self.isShowingUI = NO;
                self.keyInfo = info;
                
                [self.authTimeoutTimer invalidate];
                
                [self sB6_mq8];
        
                // Calculate remaining time: ensure loading shows for at least 2 seconds
                // Total display time: 6 seconds, so info shows for remaining time
                dispatch_async(dispatch_get_main_queue(), ^{
                    NSTimeInterval elapsed = [[NSDate date] timeIntervalSinceDate:self.loadingStartTime];
                    NSTimeInterval minLoadingTime = 2.0; // Minimum 2 seconds loading
                    NSTimeInterval remainingLoadingTime = MAX(0, minLoadingTime - elapsed);
                    NSTimeInterval totalDisplayTime = 6.0; // Total 6 seconds
                    NSTimeInterval infoDisplayTime = totalDisplayTime - minLoadingTime; // Info shows for 4 seconds
                    
                    // Wait for minimum loading time, then show info
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, remainingLoadingTime * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                        [self dismissLoadingDialog];
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                            [self showKeyInfoWithDuration:infoDisplayTime];
                        });
                    });
                });
                
            } else {
                // ===== KEY INVALID - INSTANT APPLY FOR BANNED/SERVER/NETWORK =====
                Vars.ewid = false;
                BOOL fatal = ([reason containsString:@"banned"] || [reason containsString:@"network"] || [reason containsString:@"server"]);
                if (fatal) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [self dismissLoadingDialog];
                        [self tA7_rt9];
                        xF9_ab2();
                    });
                    return;
                }
                // Dismiss loading and show auth for other errors (invalid key, expired, etc.)
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self dismissLoadingDialog];
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                        [self showAuthUI];
                    });
                });
                
                UINotificationFeedbackGenerator *feedback = [[UINotificationFeedbackGenerator alloc] init];
                [feedback notificationOccurred:UINotificationFeedbackTypeError];
                
                self.failedAttempts++;
                [KeychainHelper save:[NSString stringWithFormat:@"%ld", (long)self.failedAttempts] forKey:@"attempts"];
                
                if (self.failedAttempts >= Mx4_Fa2) {
                    xF9_ab2();
                } else {
                    NSString *errorMsg = [self formatError:reason];
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                        [self showErrorDialog:@"金鑰無效" message:errorMsg];
                    });
                }
            }
        }];
    }];
}

- (void)showCopiedAlert {
    // Prevent double showing
    if (self.isShowingCopiedAlert) {
        return;
    }
    
    // Dismiss any existing dialogs first
    if (self.currentDialog) {
        [self dismissCurrentDialog];
    }
    if (self.loadingDialog) {
        [self dismissLoadingDialog];
    }
    
    // Set flag
    self.isShowingCopiedAlert = YES;
    
    // Wait a bit for dismissal to complete
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [self showCopiedAlertInternal];
    });
}

- (void)showCopiedAlertInternal {
    [self addBlurBackground];
    
    UIWindow *window = [self getKeyWindow];
    if (!window) {
        self.isShowingCopiedAlert = NO;
        return;
    }
    
    CGFloat dialogWidth = 260;
    CGFloat dialogHeight = 150;
    
    UIView *dialog = [[UIView alloc] initWithFrame:CGRectMake(
        ([UIScreen mainScreen].bounds.size.width - dialogWidth) / 2,
        ([UIScreen mainScreen].bounds.size.height - dialogHeight) / 2,
        dialogWidth, dialogHeight)];
    if ([self isLiquidTheme]) {
        dialog.backgroundColor = [UIColor clearColor];
        dialog.layer.cornerRadius = 28;
        dialog.layer.masksToBounds = YES;
        [self applyLiquidGlassToDialog:dialog];
    } else {
        dialog.backgroundColor = [self pillColor];
        dialog.layer.cornerRadius = 28;
        dialog.layer.masksToBounds = YES;
    }
    dialog.layer.shadowColor = [UIColor blackColor].CGColor;
    dialog.layer.shadowOpacity = 0.5;
    dialog.layer.shadowRadius = 25;
    dialog.layer.shadowOffset = CGSizeMake(0, 12);
    dialog.alpha = 0;
    dialog.transform = CGAffineTransformMakeScale(0.85, 0.85);
    
    self.currentDialog = dialog;
    
    UILabel *titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(0, 18, dialogWidth, 24)];
    titleLabel.text = @"已複製網站";
    titleLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightBold];
    titleLabel.textColor = [self textColor];
    titleLabel.textAlignment = NSTextAlignmentCenter;
    [dialog addSubview:titleLabel];
    
    UILabel *messageLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, 48, dialogWidth - 32, 40)];
    messageLabel.text = @"請訪問 fluckv2.org";
    messageLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightRegular];
    messageLabel.textColor = [self accentColor];
    messageLabel.numberOfLines = 0;
    messageLabel.textAlignment = NSTextAlignmentCenter;
    [dialog addSubview:messageLabel];
    
    UIButton *okBtn = [[UIButton alloc] initWithFrame:CGRectMake((dialogWidth - 90) / 2, 100, 90, 32)];
    okBtn.backgroundColor = [self accentColor];
    okBtn.layer.cornerRadius = 16; // More curve
    [okBtn setTitle:@"確定" forState:UIControlStateNormal];
    [okBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    okBtn.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightBold];
    [okBtn addTarget:self action:@selector(okButtonTapped:) forControlEvents:UIControlEventTouchUpInside];
    [dialog addSubview:okBtn];
    
    [window addSubview:dialog];
    
    // Apply stream mode protection using UpdateStreamProtectionForView
    UpdateStreamProtectionForView(dialog);
    if (self.blurBackgroundView) {
        UpdateStreamProtectionForView(self.blurBackgroundView);
    }
    
    // Better animation with spring
    [UIView animateWithDuration:0.6 delay:0 usingSpringWithDamping:0.72 initialSpringVelocity:0.4 options:UIViewAnimationOptionCurveEaseOut animations:^{
        dialog.alpha = 1.0;
        dialog.transform = CGAffineTransformIdentity;
    } completion:nil];
}

- (void)okButtonTapped:(UIButton *)sender {
    self.isShowingCopiedAlert = NO;
    [self dismissCurrentDialog];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        self.isShowingUI = NO;
        [self showAuthUI];
    });
}

- (void)showErrorDialog:(NSString *)title message:(NSString *)message {
    // Prevent double showing
    if (self.isShowingError) {
        return;
    }
    
    // Dismiss any existing dialogs first
    if (self.currentDialog) {
        [self dismissCurrentDialog];
    }
    if (self.loadingDialog) {
        [self dismissLoadingDialog];
    }
    
    // Set flag
    self.isShowingError = YES;
    
    // Wait a bit for dismissal to complete
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [self showErrorDialogInternal:title message:message];
    });
}

- (void)showErrorDialogInternal:(NSString *)title message:(NSString *)message {
    [self addBlurBackground];
    
    UIWindow *window = [self getKeyWindow];
    if (!window) {
        self.isShowingError = NO;
        return;
    }
    
    CGFloat dialogWidth = 300;
    CGFloat dialogHeight = 200;
    
    UIView *dialog = [[UIView alloc] initWithFrame:CGRectMake(
        ([UIScreen mainScreen].bounds.size.width - dialogWidth) / 2,
        ([UIScreen mainScreen].bounds.size.height - dialogHeight) / 2,
        dialogWidth, dialogHeight)];
    if ([self isLiquidTheme]) {
        dialog.backgroundColor = [UIColor clearColor];
        dialog.layer.cornerRadius = 28;
        dialog.layer.masksToBounds = YES;
        [self applyLiquidGlassToDialog:dialog];
    } else {
        dialog.backgroundColor = [self pillColor];
        dialog.layer.cornerRadius = 28;
        dialog.layer.masksToBounds = YES;
    }
    dialog.layer.shadowColor = [UIColor blackColor].CGColor;
    dialog.layer.shadowOpacity = 0.5;
    dialog.layer.shadowRadius = 30;
    dialog.layer.shadowOffset = CGSizeMake(0, 15);
    dialog.alpha = 0;
    dialog.transform = CGAffineTransformMakeScale(0.8, 0.8);
    
    self.currentDialog = dialog;
    
    UILabel *titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(0, 20, dialogWidth, 28)];
    titleLabel.text = title;
    titleLabel.font = [UIFont systemFontOfSize:18 weight:UIFontWeightBold];
    titleLabel.textColor = [self textColor];
    titleLabel.textAlignment = NSTextAlignmentCenter;
    [dialog addSubview:titleLabel];
    
    UILabel *messageLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 55, dialogWidth - 40, 80)];
    messageLabel.text = message;
    messageLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightRegular];
    messageLabel.textColor = [self secondaryTextColor];
    messageLabel.numberOfLines = 0;
    messageLabel.textAlignment = NSTextAlignmentCenter;
    [dialog addSubview:messageLabel];
    
    UIButton *retryBtn = [[UIButton alloc] initWithFrame:CGRectMake((dialogWidth - 100) / 2, 150, 100, 36)];
    retryBtn.backgroundColor = [self accentColor];
    retryBtn.layer.cornerRadius = 18;
    [retryBtn setTitle:@"重試" forState:UIControlStateNormal];
    [retryBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    retryBtn.titleLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightBold];
    [retryBtn addTarget:self action:@selector(retryButtonTapped:) forControlEvents:UIControlEventTouchUpInside];
    [dialog addSubview:retryBtn];
    
    [window addSubview:dialog];
    
    // Apply stream mode protection using UpdateStreamProtectionForView
    UpdateStreamProtectionForView(dialog);
    if (self.blurBackgroundView) {
        UpdateStreamProtectionForView(self.blurBackgroundView);
    }
    
    [UIView animateWithDuration:0.5 animations:^{
        dialog.alpha = 1.0;
        dialog.transform = CGAffineTransformIdentity;
    }];
}

- (void)retryButtonTapped:(UIButton *)sender {
    self.isShowingError = NO;
    [self dismissCurrentDialog];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        self.isShowingUI = NO;
        [self showAuthUI];
    });
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    UIView *dialog = objc_getAssociatedObject(textField, "dialog");
    if (dialog == self.authDialog) {
        // Find login button and trigger it
        for (UIView *subview in dialog.subviews) {
            if ([subview isKindOfClass:[UIButton class]]) {
                UIButton *btn = (UIButton *)subview;
                if ([btn.titleLabel.text isEqualToString:@"登入"]) {
                    [btn sendActionsForControlEvents:UIControlEventTouchUpInside];
                    break;
                }
            }
        }
    }
    [textField resignFirstResponder];
    return YES;
}

- (void)startAuthTimeoutTimer {
    // Invalidate existing timer
    if (self.authTimeoutTimer) {
        [self.authTimeoutTimer invalidate];
        self.authTimeoutTimer = nil;
    }
    
    // Create new timer that checks every second
    self.authTimeoutTimer = [NSTimer scheduledTimerWithTimeInterval:1.0
                                                           target:self
                                                         selector:@selector(checkAuthTimeout)
                                                         userInfo:nil
                                                          repeats:YES];
    [[NSRunLoop mainRunLoop] addTimer:self.authTimeoutTimer forMode:NSRunLoopCommonModes];
}

- (void)checkAuthTimeout {
    if (self.isAuthenticated) {
        // User is authenticated, stop timer
        [self.authTimeoutTimer invalidate];
        return;
    }
    
    // Only check timeout if auth UI is actually showing
    if (!self.isShowingUI || !self.authDialog) {
        // Auth UI not showing, stop timer
        [self.authTimeoutTimer invalidate];
        return;
    }
    
    NSTimeInterval elapsed = [[NSDate date] timeIntervalSinceDate:self.authStartTime];
    if (elapsed >= At5_To6) {
        // 1 hour has passed without valid key, crash the app
        Vars.ewid = false;  // ❌ TIMEOUT
        [self.authTimeoutTimer invalidate];
        xF9_ab2();
    }
}

- (void)showKeyInfo {
    [self showKeyInfoWithDuration:9.0]; // Default duration — more time to read info
}

- (void)showKeyInfoWithDuration:(NSTimeInterval)duration {
    // Prevent double showing
    if (self.isShowingKeyInfo) {
        return;
    }
    
    // Invalidate any existing timer first
    if (self.keyInfoTimer) {
        [self.keyInfoTimer invalidate];
        self.keyInfoTimer = nil;
    }
    
    // Dismiss loading dialog if exists
    if (self.loadingDialog) {
        [self dismissLoadingDialog];
    }
    
    // Dismiss any existing dialog first
    [self dismissCurrentDialog];
    
    // Set flag to prevent double showing
    self.isShowingKeyInfo = YES;
    
    // Wait a bit for dismissal to complete
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        // Double check no dialog exists
        if (self.currentDialog || self.loadingDialog) {
            if (self.loadingDialog) {
                [self dismissLoadingDialog];
            }
            if (self.currentDialog) {
                [self dismissCurrentDialog];
            }
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                [self showKeyInfoInternalWithDuration:duration];
            });
        } else {
            [self showKeyInfoInternalWithDuration:duration];
        }
    });
}

- (void)showKeyInfoInternal {
    [self showKeyInfoInternalWithDuration:9.0];
}

- (void)showKeyInfoLiquidWithDuration:(NSTimeInterval)duration {
    [self addBlurBackground];
    UIWindow *window = [self getKeyWindow];
    if (!window) return;
    
    CGFloat screenW = [UIScreen mainScreen].bounds.size.width;
    CGFloat screenH = [UIScreen mainScreen].bounds.size.height;
    CGFloat contentWidth = screenW * 0.52;
    CGFloat inset = 32;
    CGFloat w = contentWidth - inset;
    
    // Content-only container on LEFT — no box, no border, just content that slides in one by one
    UIView *container = [[UIView alloc] initWithFrame:CGRectMake(0, 0, contentWidth, screenH)];
    container.backgroundColor = [UIColor clearColor];
    container.userInteractionEnabled = YES;
    container.tag = 88888; // Liquid key-info: dismiss with one-by-one out animation
    self.currentDialog = container;
    self.keyInfoDialog = container;
    
    // Consistent typography and line heights for proper alignment
    static const CGFloat kLineH = 22;
    static const CGFloat kSectionH = 24;
    static const CGFloat kTitleH = 26;
    static const CGFloat kSpacing = 8;
    
    UIFont *titleFont = [UIFont systemFontOfSize:26 weight:UIFontWeightBold];
    UIFont *subtitleFont = [UIFont systemFontOfSize:18 weight:UIFontWeightSemibold];
    UIFont *sectionFont = [UIFont systemFontOfSize:17 weight:UIFontWeightSemibold];
    UIFont *bodyFont = [UIFont systemFontOfSize:16 weight:UIFontWeightRegular];
    
    CGFloat y = 48;
    NSMutableArray *animateViews = [NSMutableArray array];
    
    UILabel *titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(inset, y, w, 32)];
    titleLabel.text = KEYAUTH_APP_DISPLAY_NAME;
    titleLabel.font = titleFont;
    titleLabel.textColor = [self accentColor];
    titleLabel.textAlignment = NSTextAlignmentLeft;
    [container addSubview:titleLabel];
    [animateViews addObject:titleLabel];
    y += 32 + kSpacing;
    
    UILabel *successLabel = [[UILabel alloc] initWithFrame:CGRectMake(inset, y, w, kLineH)];
    successLabel.text = @"授權驗證成功";
    successLabel.font = subtitleFont;
    successLabel.textColor = [self accentColor];
    successLabel.textAlignment = NSTextAlignmentLeft;
    [container addSubview:successLabel];
    [animateViews addObject:successLabel];
    y += kLineH + kSpacing;
    
    NSString *keyDisplay = self.currentKey ?: @"";
    NSString *udidDisplay = [self.udid substringToIndex:MIN(12, self.udid.length)];
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    [formatter setDateFormat:@"yyyy-MM-dd HH:mm"];
    NSString *currentTime = [formatter stringFromDate:[NSDate date]];
    
    if (self.packageInfo) {
        UILabel *pkgTitle = [[UILabel alloc] initWithFrame:CGRectMake(inset, y, w, kSectionH)];
        pkgTitle.text = @"套件資訊";
        pkgTitle.font = sectionFont;
        pkgTitle.textColor = [self textColor];
        pkgTitle.textAlignment = NSTextAlignmentLeft;
        [container addSubview:pkgTitle];
        [animateViews addObject:pkgTitle];
        y += kSectionH + 4;
        NSString *appName = self.packageInfo[@"app_name"];
        if (appName.length > 18) appName = [[appName substringToIndex:15] stringByAppendingString:@"..."];
        NSString *creator = self.packageInfo[@"creator"];
        if (creator.length > 18) creator = [[creator substringToIndex:15] stringByAppendingString:@"..."];
        for (NSString *line in @[
            [NSString stringWithFormat:@"應用: %@", appName],
            [NSString stringWithFormat:@"版本: %@", self.packageInfo[@"version"] ?: @"-"],
            [NSString stringWithFormat:@"創建者: %@", creator ?: @"-"]
        ]) {
            UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(inset, y, w, kLineH)];
            l.text = line;
            l.font = bodyFont;
            l.textColor = [self secondaryTextColor];
            l.textAlignment = NSTextAlignmentLeft;
            [container addSubview:l];
            [animateViews addObject:l];
            y += kLineH + 4;
        }
        y += kSpacing;
    }
    
    UILabel *keyTitle = [[UILabel alloc] initWithFrame:CGRectMake(inset, y, w, kSectionH)];
    keyTitle.text = @"金鑰資訊";
    keyTitle.font = sectionFont;
    keyTitle.textColor = [self textColor];
    keyTitle.textAlignment = NSTextAlignmentLeft;
    [container addSubview:keyTitle];
    [animateViews addObject:keyTitle];
    y += kSectionH + 4;
    
    NSString *shortKey = keyDisplay.length > 22 ? [[keyDisplay substringToIndex:19] stringByAppendingString:@"..."] : keyDisplay;
    for (NSString *line in @[
        [NSString stringWithFormat:@"金鑰: %@", shortKey],
        [NSString stringWithFormat:@"設備: %@...", udidDisplay],
        [NSString stringWithFormat:@"時間: %@", currentTime],
        @"狀態: 已綁定此設備"
    ]) {
        UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(inset, y, w, kLineH)];
        l.text = line;
        l.font = bodyFont;
        l.textColor = [line hasPrefix:@"狀態"] ? [self accentColor] : [self secondaryTextColor];
        l.textAlignment = NSTextAlignmentLeft;
        [container addSubview:l];
        [animateViews addObject:l];
        y += kLineH + 4;
    }
    
    CGFloat slideFrom = -72;
    UIColor *accent = [self accentColor];
    for (UIView *v in animateViews) {
        if ([v isKindOfClass:[UILabel class]]) {
            v.layer.shadowColor = accent.CGColor;
            v.layer.shadowRadius = 3;
            v.layer.shadowOpacity = 0.38f;
            v.layer.shadowOffset = CGSizeZero;
        }
        v.alpha = 0;
        v.transform = CGAffineTransformMakeTranslation(slideFrom, 0);
    }
    
    [window addSubview:container];
    UpdateStreamProtectionForView(container);
    if (self.blurBackgroundView) UpdateStreamProtectionForView(self.blurBackgroundView);
    
    // Staggered slide-in from left, then brief "present" pop (scale) so selected text is emphasized
    for (NSInteger i = 0; i < animateViews.count; i++) {
        UIView *v = animateViews[i];
        NSTimeInterval delay = 0.12 + (double)i * 0.16;
        [UIView animateWithDuration:0.68 delay:delay usingSpringWithDamping:0.78 initialSpringVelocity:0.35 options:0 animations:^{
            v.alpha = 1;
            v.transform = CGAffineTransformIdentity;
        } completion:^(BOOL finished) {
            if (!finished) return;
            // Present pop: briefly scale up then back so it reads as "selected / presented"
            [UIView animateWithDuration:0.12 animations:^{
                v.transform = CGAffineTransformMakeScale(1.06f, 1.06f);
            } completion:^(BOOL done) {
                [UIView animateWithDuration:0.18 delay:0.05 options:0 animations:^{
                    v.transform = CGAffineTransformIdentity;
                } completion:nil];
            }];
        }];
    }
    
    __weak KeyAuthSystem *weakSelf = self;
    __weak UIView *weakContainer = container;
    
    // Little glow pulse animation on text (repeat until dismiss)
    NSTimeInterval pulseDur = 1.5;
    __block void (^runPulse)(void);
    __weak void (^weakPulse)(void);
    runPulse = ^{
        if (!weakSelf || weakSelf.currentDialog != weakContainer) return;
        [UIView animateWithDuration:pulseDur delay:0 options:UIViewAnimationOptionCurveEaseInOut animations:^{
            for (UIView *v in animateViews) {
                if ([v isKindOfClass:[UILabel class]]) v.layer.shadowOpacity = 0.48f;
            }
        } completion:^(BOOL finished) {
            if (!weakSelf || weakSelf.currentDialog != weakContainer) return;
            [UIView animateWithDuration:pulseDur delay:0 options:UIViewAnimationOptionCurveEaseInOut animations:^{
                for (UIView *v in animateViews) {
                    if ([v isKindOfClass:[UILabel class]]) v.layer.shadowOpacity = 0.28f;
                }
            } completion:^(BOOL done) {
                if (weakSelf && weakSelf.currentDialog == weakContainer && weakPulse) weakPulse();
            }];
        }];
    };
    weakPulse = runPulse;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if (weakSelf && weakSelf.currentDialog == weakContainer && runPulse) runPulse();
    });
    
    self.keyInfoTimer = [NSTimer scheduledTimerWithTimeInterval:duration repeats:NO block:^(NSTimer *timer) {
        KeyAuthSystem *strongSelf = weakSelf;
        UIView *strongPanel = weakContainer;
        if (strongSelf && strongPanel && strongSelf.currentDialog == strongPanel) {
            [strongSelf dismissCurrentDialog];
        }
        if (strongSelf) strongSelf.keyInfoTimer = nil;
    }];
}

- (void)showKeyInfoInternalWithDuration:(NSTimeInterval)duration {
    if ([self isLiquidTheme]) {
        [self showKeyInfoLiquidWithDuration:duration];
        return;
    }
    [self addBlurBackground];
    
    UIWindow *window = [self getKeyWindow];
    if (!window) return;
    
        NSString *keyDisplay = self.currentKey;
        NSString *udidDisplay = [self.udid substringToIndex:MIN(12, self.udid.length)];
        
        NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
        [formatter setDateFormat:@"yyyy-MM-dd HH:mm"];
        NSString *currentTime = [formatter stringFromDate:[NSDate date]];
        
    CGFloat dialogWidth = 300; // Smaller width
    CGFloat contentHeight = 0;
        
    // Calculate height based on content - more compact
        if (self.packageInfo) {
        contentHeight += 100; // Package info section - reduced
    }
    contentHeight += 120; // Key info section - reduced
    contentHeight += 50; // Padding and title - reduced
    
    CGFloat dialogHeight = MAX(280, contentHeight); // Smaller minimum height
    
    UIView *dialog = [[UIView alloc] initWithFrame:CGRectMake(
        ([UIScreen mainScreen].bounds.size.width - dialogWidth) / 2,
        ([UIScreen mainScreen].bounds.size.height - dialogHeight) / 2,
        dialogWidth, dialogHeight)];
    dialog.backgroundColor = [UIColor clearColor];
    dialog.layer.cornerRadius = 28;
    dialog.layer.masksToBounds = YES;
    [self applyLiquidGlassToDialog:dialog];
    dialog.layer.shadowColor = [UIColor blackColor].CGColor;
    dialog.layer.shadowOpacity = 0.6; // Stronger shadow
    dialog.layer.shadowRadius = 30; // Shadow radius
    dialog.layer.shadowOffset = CGSizeMake(0, 15); // Shadow offset
    dialog.alpha = 0;
    dialog.transform = CGAffineTransformMakeScale(0.75, 0.75); // Start smaller for better animation
    
    self.currentDialog = dialog;
    self.keyInfoDialog = dialog;
    
    CGFloat y = 16;
    
    // Title
    UILabel *titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(0, y, dialogWidth, 28)];
    titleLabel.text = KEYAUTH_APP_DISPLAY_NAME;
    titleLabel.font = [UIFont systemFontOfSize:24 weight:UIFontWeightBold];
    titleLabel.textColor = [self accentColor];
    titleLabel.textAlignment = NSTextAlignmentCenter;
    [dialog addSubview:titleLabel];
    y += 28;
    
    // Success message - smaller
    UILabel *successLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, y, dialogWidth - 32, 22)];
    successLabel.text = @"授權驗證成功";
    successLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightSemibold];
    successLabel.textColor = [self accentColor];
    successLabel.textAlignment = NSTextAlignmentCenter;
    [dialog addSubview:successLabel];
    y += 28;
    
    // Package info section - more compact
    if (self.packageInfo) {
        UILabel *packageTitle = [[UILabel alloc] initWithFrame:CGRectMake(16, y, dialogWidth - 32, 18)];
        packageTitle.text = @"套件資訊";
        packageTitle.font = [UIFont systemFontOfSize:13 weight:UIFontWeightBold];
        packageTitle.textColor = [self textColor];
        [dialog addSubview:packageTitle];
        y += 20;
        
        UIView *separator1 = [[UIView alloc] initWithFrame:CGRectMake(16, y, dialogWidth - 32, 1)];
        separator1.backgroundColor = [[self accentColor] colorWithAlphaComponent:0.3];
        [dialog addSubview:separator1];
        y += 8;
        
        UILabel *appLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, y, dialogWidth - 32, 18)];
        NSString *appName = self.packageInfo[@"app_name"];
        if (appName.length > 20) {
            appName = [[appName substringToIndex:17] stringByAppendingString:@"..."];
        }
        appLabel.text = [NSString stringWithFormat:@"應用: %@", appName];
        appLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightRegular];
        appLabel.textColor = [self secondaryTextColor];
        appLabel.adjustsFontSizeToFitWidth = YES;
        appLabel.minimumScaleFactor = 0.8;
        [dialog addSubview:appLabel];
        y += 18;
        
        UILabel *versionLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, y, dialogWidth - 32, 18)];
        versionLabel.text = [NSString stringWithFormat:@"版本: %@", self.packageInfo[@"version"]];
        versionLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightRegular];
        versionLabel.textColor = [self secondaryTextColor];
        [dialog addSubview:versionLabel];
        y += 18;
        
        UILabel *creatorLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, y, dialogWidth - 32, 18)];
        NSString *creator = self.packageInfo[@"creator"];
        if (creator.length > 20) {
            creator = [[creator substringToIndex:17] stringByAppendingString:@"..."];
        }
        creatorLabel.text = [NSString stringWithFormat:@"創建者: %@", creator];
        creatorLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightRegular];
        creatorLabel.textColor = [self secondaryTextColor];
        creatorLabel.adjustsFontSizeToFitWidth = YES;
        creatorLabel.minimumScaleFactor = 0.8;
        [dialog addSubview:creatorLabel];
        y += 24;
    }
    
    // Key info section - more compact with overflow handling
    UILabel *keyTitle = [[UILabel alloc] initWithFrame:CGRectMake(16, y, dialogWidth - 32, 18)];
    keyTitle.text = @"金鑰資訊";
    keyTitle.font = [UIFont systemFontOfSize:13 weight:UIFontWeightBold];
    keyTitle.textColor = [self textColor];
    [dialog addSubview:keyTitle];
    y += 20;
    
    UIView *separator2 = [[UIView alloc] initWithFrame:CGRectMake(16, y, dialogWidth - 32, 1)];
    separator2.backgroundColor = [[self accentColor] colorWithAlphaComponent:0.3];
    [dialog addSubview:separator2];
    y += 8;
    
    UILabel *keyLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, y, dialogWidth - 32, 18)];
    NSString *shortKey = keyDisplay;
    if (shortKey.length > 25) {
        shortKey = [[shortKey substringToIndex:22] stringByAppendingString:@"..."];
    }
    keyLabel.text = [NSString stringWithFormat:@"金鑰: %@", shortKey];
    keyLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightRegular];
    keyLabel.textColor = [self secondaryTextColor];
    keyLabel.adjustsFontSizeToFitWidth = YES;
    keyLabel.minimumScaleFactor = 0.75;
    [dialog addSubview:keyLabel];
    y += 18;
    
    UILabel *deviceLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, y, dialogWidth - 32, 18)];
    deviceLabel.text = [NSString stringWithFormat:@"設備: %@...", udidDisplay];
    deviceLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightRegular];
    deviceLabel.textColor = [self secondaryTextColor];
    [dialog addSubview:deviceLabel];
    y += 18;
    
    UILabel *timeLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, y, dialogWidth - 32, 18)];
    timeLabel.text = [NSString stringWithFormat:@"時間: %@", currentTime];
    timeLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightRegular];
    timeLabel.textColor = [self secondaryTextColor];
    [dialog addSubview:timeLabel];
    y += 18;
    
    UILabel *statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, y, dialogWidth - 32, 18)];
    statusLabel.text = @"狀態: 已綁定此設備";
    statusLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightRegular];
    statusLabel.textColor = [self accentColor];
    [dialog addSubview:statusLabel];
    
    [window addSubview:dialog];
    
    // Apply stream mode protection using UpdateStreamProtectionForView
    UpdateStreamProtectionForView(dialog);
    if (self.blurBackgroundView) {
        UpdateStreamProtectionForView(self.blurBackgroundView);
    }
    
    // Proper animation with spring effect and better timing
    [UIView animateWithDuration:0.5 delay:0 usingSpringWithDamping:0.65 initialSpringVelocity:0.8 options:UIViewAnimationOptionCurveEaseOut animations:^{
        dialog.alpha = 1.0;
        dialog.transform = CGAffineTransformIdentity;
    } completion:^(BOOL finished) {
        // Add subtle pulse animation
        CABasicAnimation *pulse = [CABasicAnimation animationWithKeyPath:@"transform.scale"];
        pulse.fromValue = @(1.0);
        pulse.toValue = @(1.02);
        pulse.duration = 0.3;
        pulse.autoreverses = YES;
        pulse.repeatCount = 1;
        [dialog.layer addAnimation:pulse forKey:@"pulse"];
    }];
    
    // Set up auto-dismiss timer with specified duration
    // Store reference to dialog for timer
    __weak KeyAuthSystem *weakSelf = self;
    __weak UIView *weakDialog = dialog;
    
    self.keyInfoTimer = [NSTimer scheduledTimerWithTimeInterval:duration repeats:NO block:^(NSTimer *timer) {
        KeyAuthSystem *strongSelf = weakSelf;
        UIView *strongDialog = weakDialog;
        
        if (strongSelf && strongDialog && strongSelf.currentDialog == strongDialog) {
            [strongSelf dismissCurrentDialog];
        }
        if (strongSelf) {
            strongSelf.keyInfoTimer = nil;
        }
    }];
}

- (void)showLoadingDialog:(NSString *)message {
    // Prevent double showing - same logic as showKeyInfo
    if (self.isShowingLoading) {
        // Just update message if already showing
        [self updateLoadingMessage:message];
        return;
    }
    
    // Set flag immediately
    self.isShowingLoading = YES;
    self.loadingStartTime = [NSDate date];
    
    // Dismiss any existing dialogs first
    if (self.currentDialog) {
        [self dismissCurrentDialog];
    }
    
    // Remove any existing loading dialog
    if (self.loadingDialog) {
        [self.loadingDialog removeFromSuperview];
        self.loadingDialog = nil;
    }
    
    // Remove any existing blur
    if (self.blurBackgroundView) {
        [self.blurBackgroundView removeFromSuperview];
        self.blurBackgroundView = nil;
    }
    
    [self addBlurBackground];
    
    UIWindow *window = [self getKeyWindow];
    if (!window) return;
    
    CGFloat dialogWidth = 260;
    CGFloat dialogHeight = 160;
    
    UIView *dialog = [[UIView alloc] initWithFrame:CGRectMake(
        ([UIScreen mainScreen].bounds.size.width - dialogWidth) / 2,
        ([UIScreen mainScreen].bounds.size.height - dialogHeight) / 2,
        dialogWidth, dialogHeight)];
    
    if ([self isLiquidTheme]) {
        dialog.backgroundColor = [UIColor clearColor];
        dialog.layer.cornerRadius = 28;
        dialog.layer.masksToBounds = YES;
        [self applyLiquidGlassToDialog:dialog];
    } else {
        dialog.backgroundColor = [self pillColor];
        dialog.layer.cornerRadius = 28;
        dialog.layer.masksToBounds = YES;
    }
    dialog.layer.shadowColor = [UIColor blackColor].CGColor;
    dialog.layer.shadowOpacity = 0.5;
    dialog.layer.shadowRadius = 25;
    dialog.layer.shadowOffset = CGSizeMake(0, 12);
    dialog.alpha = 0;
    dialog.transform = CGAffineTransformMakeScale(0.85, 0.85);
    
    self.loadingDialog = dialog;
    // Don't set as currentDialog - keep it separate
    
    // Loading spinner
    UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:[self isDarkMode] ? UIActivityIndicatorViewStyleWhiteLarge : UIActivityIndicatorViewStyleGray];
    spinner.frame = CGRectMake((dialogWidth - 40) / 2, 30, 40, 40);
    spinner.color = [self accentColor];
    [spinner startAnimating];
    [dialog addSubview:spinner];
    
    // Message label
    UILabel *messageLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, 80, dialogWidth - 32, 50)];
    messageLabel.text = message;
    messageLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightRegular];
    messageLabel.textColor = [self textColor];
    messageLabel.numberOfLines = 2;
    messageLabel.textAlignment = NSTextAlignmentCenter;
    messageLabel.tag = 1001; // Tag for updating message
    [dialog addSubview:messageLabel];
    
    [window addSubview:dialog];
    
    // Apply stream mode protection
    UpdateStreamProtectionForView(dialog);
    if (self.blurBackgroundView) {
        UpdateStreamProtectionForView(self.blurBackgroundView);
    }
    
    // Animation
    [UIView animateWithDuration:0.6 delay:0 usingSpringWithDamping:0.72 initialSpringVelocity:0.4 options:UIViewAnimationOptionCurveEaseOut animations:^{
        dialog.alpha = 1.0;
        dialog.transform = CGAffineTransformIdentity;
    } completion:nil];
}

- (void)updateLoadingMessage:(NSString *)message {
    if (self.loadingDialog) {
        UILabel *messageLabel = [self.loadingDialog viewWithTag:1001];
        if (messageLabel) {
            messageLabel.text = message;
        }
    }
}

- (void)dismissLoadingDialog {
    if (!self.loadingDialog) {
        self.isShowingLoading = NO;
        return;
    }
    
    UIView *dialogToDismiss = self.loadingDialog;
    UIView *blurToDismiss = self.blurBackgroundView;
    
    self.loadingDialog = nil;
    self.isShowingLoading = NO;
    self.loadingStartTime = nil;
    
    [UIView animateWithDuration:0.5 animations:^{
        if (blurToDismiss) {
            blurToDismiss.alpha = 0;
        }
        dialogToDismiss.alpha = 0;
        dialogToDismiss.transform = CGAffineTransformMakeScale(0.8, 0.8);
    } completion:^(BOOL finished) {
        [dialogToDismiss removeFromSuperview];
        
        // Remove blur after dialog is dismissed
        if (blurToDismiss) {
            [blurToDismiss removeFromSuperview];
            self.blurBackgroundView = nil;
        }
        
        // Also remove blur by tag
        UIWindow *window = [self getKeyWindow];
        if (window) {
            UIView *blurByTag = [window viewWithTag:99999];
            if (blurByTag) {
                [blurByTag removeFromSuperview];
            }
        }
    }];
}

- (void)showPackageErrorDialog:(NSString *)errorMsg {
    // Prevent double showing
    if (self.isShowingPackageError) {
        return;
    }
    
    // Dismiss any existing dialogs first
    if (self.currentDialog) {
        [self dismissCurrentDialog];
    }
    if (self.loadingDialog) {
        [self dismissLoadingDialog];
    }
    
    // Set flag
    self.isShowingPackageError = YES;
    
    // Wait a bit for dismissal to complete
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [self showPackageErrorDialogInternal:errorMsg];
    });
}

- (void)showPackageErrorDialogInternal:(NSString *)errorMsg {
    [self addBlurBackground];
    
    UIWindow *window = [self getKeyWindow];
    if (!window) {
        self.isShowingPackageError = NO;
        return;
    }
    
    CGFloat dialogWidth = 320;
    CGFloat dialogHeight = 200;
    
    UIView *dialog = [[UIView alloc] initWithFrame:CGRectMake(
        ([UIScreen mainScreen].bounds.size.width - dialogWidth) / 2,
        ([UIScreen mainScreen].bounds.size.height - dialogHeight) / 2,
        dialogWidth, dialogHeight)];
    if ([self isLiquidTheme]) {
        dialog.backgroundColor = [UIColor clearColor];
        dialog.layer.cornerRadius = 28;
        dialog.layer.masksToBounds = YES;
        [self applyLiquidGlassToDialog:dialog];
    } else {
        dialog.backgroundColor = [self pillColor];
        dialog.layer.cornerRadius = 28;
        dialog.layer.masksToBounds = YES;
    }
    dialog.layer.shadowColor = [UIColor blackColor].CGColor;
    dialog.layer.shadowOpacity = 0.5;
    dialog.layer.shadowRadius = 30;
    dialog.layer.shadowOffset = CGSizeMake(0, 15);
    dialog.alpha = 0;
    dialog.transform = CGAffineTransformMakeScale(0.8, 0.8);
    
    self.currentDialog = dialog;
    
    UILabel *titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(0, 20, dialogWidth, 28)];
    titleLabel.text = @"套件驗證失敗";
    titleLabel.font = [UIFont systemFontOfSize:18 weight:UIFontWeightBold];
    titleLabel.textColor = [self textColor];
    titleLabel.textAlignment = NSTextAlignmentCenter;
    [dialog addSubview:titleLabel];
    
    UILabel *messageLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 55, dialogWidth - 40, 100)];
    messageLabel.text = errorMsg;
    messageLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightRegular];
    messageLabel.textColor = [self secondaryTextColor];
    messageLabel.numberOfLines = 0;
    messageLabel.textAlignment = NSTextAlignmentCenter;
    [dialog addSubview:messageLabel];
    
    [window addSubview:dialog];
    
    // Apply stream mode protection using UpdateStreamProtectionForView
    UpdateStreamProtectionForView(dialog);
    if (self.blurBackgroundView) {
        UpdateStreamProtectionForView(self.blurBackgroundView);
    }
    
    [UIView animateWithDuration:0.5 animations:^{
        dialog.alpha = 1.0;
        dialog.transform = CGAffineTransformIdentity;
    }];
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        self.isShowingPackageError = NO;
        [self dismissCurrentDialog];
        xF9_ab2();
    });
}

- (NSString *)formatError:(NSString *)reason {
    if ([reason containsString:@"invalid_key"]) {
        return @"金鑰不存在於資料庫。";
    } else if ([reason containsString:@"key_package_mismatch"]) {
        return @"此金鑰不適用於此應用程式套件。";
    } else if ([reason containsString:@"expired"]) {
        return @"金鑰已過期。";
    } else if ([reason containsString:@"banned"]) {
        return @"金鑰已被封鎖。";
    } else if ([reason containsString:@"bound_to_another"]) {
        return @"金鑰已在其他設備使用。";
    } else if ([reason containsString:@"network"]) {
        return @"網路連線錯誤。";
    } else if ([reason containsString:@"server"]) {
        return @"伺服器錯誤。";
    } else if ([reason containsString:@"auth_failed"]) {
        return @"驗證失敗，請稍後再試。";
    } else if ([reason containsString:@"decryption"]) {
        return @"解密失敗，請更新應用程式。";
    } else if ([reason containsString:@"security_breach"]) {
        return @"偵測到安全風險，請關閉調試工具後重試。";
    } else if ([reason containsString:@"missing_var_field"]) {
        return @"伺服器回應格式錯誤。";
    } else if ([reason containsString:@"invalid_response_format"]) {
        return @"無效的伺服器回應。";
    }
    return @"請再試一次。";
}


@end

__attribute__((constructor))
static void initKeyAuth() {
    // ===== CRITICAL: DISABLE FEATURES ON INIT =====
    Vars.ewid = false;
    
    // Check for debugger/proxy immediately
    if (dG3_pq1() || pX4_yr2()) {
        Vars.ewid = false;
        dispatch_async(dispatch_get_main_queue(), ^{
            xF9_ab2();
        });
        return;
    }
    
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                          object:nil
                                                           queue:[NSOperationQueue mainQueue]
                                                      usingBlock:^(NSNotification *note) {
            static dispatch_once_t token;
            dispatch_once(&token, ^{
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                    [[KeyAuthSystem shared] start];
                });
            });
        }];
        
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            static BOOL started = NO;
            if (!started) {
                started = YES;
                [[KeyAuthSystem shared] start];
            }
        });
    });
}