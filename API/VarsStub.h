/**
 * Minimal Vars stub for standalone KeyAuth build.
 * Use this when building libKeyAuth.a without menuUIKIT.
 * If integrating with full app that has menuUIKIT/Vars.h, use that instead.
 */
#ifndef VarsStub_h
#define VarsStub_h

#ifdef KEYAUTH_STANDALONE
struct Vars_t { bool ewid; };
extern Vars_t Vars;
#endif

#endif
