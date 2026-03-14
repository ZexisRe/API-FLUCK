/**
 * Minimal Vars stub for standalone KeyAuth build.
 * Use this when building libKeyAuth.a without menuUIKIT.
 */
#ifndef VarsStub_h
#define VarsStub_h

#ifdef KEYAUTH_STANDALONE
#import <UIKit/UIKit.h>
struct Vars_t { bool ewid; };
extern Vars_t Vars;
extern bool StreamMode;
static inline void UpdateStreamProtectionForView(UIView *v) { (void)v; }
#endif

#endif
