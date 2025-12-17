
#ifndef _OEMEXPDEF_H
#define	_OEMEXPDEF_H


#if defined(WIN32) || defined(WINCE)
#define _OS_WINDOWS
#elif defined(LINUX) || defined(__LINUX__) || defined(__linux__)
#define _OS_LINUX
#elif defined(APPLE) || defined (__APPLE__) || defined (__apple__)
#define _OS_MACOS
#else
#define _OS_UNKNOW
#endif

#if defined(__x64__) || defined(__x86_64__) || defined(__amd64__) || defined(__aarch64__)
#define _OS_64
#elif defined(__x86__) || defined(__x64_86__) || defined(__i386__) || defined(__arm__)
#define _OS_32
#endif

#if defined(_OS_WINDOWS)
#if defined(_USRDLL)
#define OEM_EXP_API extern //__declspec(dllexport)
#define OEM_LOC_API 
#else
#define OEM_EXP_API extern //__declspec(dllimport)
#define OEM_LOC_API 
#endif
#else
#define OEM_EXP_API __attribute__((visibility("default"))) extern
#define OEM_LOC_API __attribute__((visibility("hidden")))
#endif

#define OEM_SELF_TEST

#endif	/* _OEMEXPDEF_H */

