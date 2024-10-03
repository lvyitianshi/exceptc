#ifndef _MSC_VER /* MSVC specific syntax is required, clang-cl requires the "/EHa" option */
    you can not use exceptc.h whitout MSVC compiler,
    because it is not supported by MinGW and other compilers
#else

#ifndef __cplusplus

#ifndef _EXCEPTC_H_
#define _EXCEPTC_H_

/* Please define the character encoding macro before using exceptc.h */

#include <tchar.h>
#include <Windows.h>

/*
    Note that the system will clear bit 28 of dwExceptionCode
    before displaying a message This bit is a reserved exception bit,
    used by the system for its own purposes.

    -- https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-raiseexception

    Bits : 
        30 -- 31 : Basic state
            11 : error
            00 : success
            01 : informational
            10 : warning

        29       : Client bit, set to 1 for user-defined codes
        28       : Reserved bit, set to 0 by the system
        27 -- 0  : Exception code
*/

#define EXCEPTC_CODE_SOFT_DEF_START     0xE0000000
#define EXCEPTC_CODE_SOFT_DEF_END       0xEFFFFFFF

#define EXCEPTC_TYPE_HARD 0
#define EXCEPTC_TYPE_SOFT 1

#define EXCEPTC_TYPE(dwCode)                                                 \
    (!((dwCode & (1 << 29)) >> 29)) ? EXCEPTC_TYPE_HARD : EXCEPTC_TYPE_SOFT

#define EXCEPTC_CODE_BITS(basic_state, exception_code)  \
    (DWORD)(                                            \
        (basic_state      << 30) |                      \
        (0x1              << 29) |                      \
        (0x0              << 28) |                      \
        (exception_code        )                        \
    )

#define EXCEPTC_CODE_BITS_BASIC_STATE_ERROR            0x3
#define EXCEPTC_CODE_BITS_BASIC_STATE_SUCCESS          0x0
#define EXCEPTC_CODE_BITS_BASIC_STATE_INFORMATIONAL    0x1 
#define EXCEPTC_CODE_BITS_BASIC_STATE_WARNING          0x2

#define EXCEPTC_CODE_SOFT_UNKNOWN (EXCEPTC_CODE_BITS(EXCEPTC_CODE_BITS_BASIC_STATE_ERROR, 0))
#define EXCEPTC_CODE_SOFT_NO_MEMORY (EXCEPTC_CODE_BITS(EXCEPTC_CODE_BITS_BASIC_STATE_ERROR, 1))
#define EXCEPTC_CODE_SOFT_FAILED_CALL (EXCEPTC_CODE_BITS(EXCEPTC_CODE_BITS_BASIC_STATE_ERROR, 2))

/* The 0 to 255 are defined by exceptc.h */
#define EXCEPTC_CODE_SOFT_USER_DEF_START 256
#define EXCEPTC_CODE_SOFT_USER_DEF_MAX_COUNT 268435200

#define EXCEPTC_TWAHT_MAX_LEN 512
typedef struct EXCEPTC_STRUCTURE {
    BOOL bCatchSuccess;
    DWORD dwCode;
    TCHAR tWhat[EXCEPTC_TWAHT_MAX_LEN];
} EXCEPTC_STRUCTURE, *PEXCEPTC_STRUCTURE;

#define EXCEPTC_CATCH_SUCCESS(e) (e.bCatchSuccess)
#define EXCEPTC_CATCH_FAILURE(e) (!e.bCatchSuccess)

#define tryc __try

typedef EXCEPTION_POINTERS EXCEPTC_RECODE, *PEXCEPTC_RECODE;
#define recordc (PEXCEPTC_RECODE)GetExceptionInformation()
#define codec GetExceptionCode

#define catchc(filter) __except(filter)

#define finallyc __finally

#define EXCEPTC_TWHAT_INDEX 0
#define EXCEPTC_FILTER_DATA_INDEX 1

/* The xxxEX function is an advanced usage of the same function */

/*
    filter_data is a pointer to the data on the function stack,
    and the data on the function stack is only allowed to be used in the filter function,
    because the data on the function stack will be
    cleaned up (Stack unwinding) after the filter function is run
*/
#define raisecEX(dwCode, dwFlags, tWhat, filter_data)  \
    RaiseException(                                    \
        dwCode, dwFlags,                               \
        2,                                             \
        (ULONG_PTR[]) {                                \
            (ULONG_PTR)tWhat,                          \
            (ULONG_PTR)filter_data                     \
        }                                              \
    )

#define raisec(dwCode, tWhat) \
    raisecEX(dwCode, EXCEPTION_NONCONTINUABLE, tWhat, NULL)

#define noreturnc __declspec(noreturn)

#define __macroc__(x) #x
#define __str_macroc__(x) __macroc__(x)

#ifdef __clang__ /* clang-cl */ /* The GNU C syntax is unnecessary */

/*
    The xxxRAS functions are used to raise exceptions, 
    and if the functions are not in the tryc block when they are called,
    they will cause the program exit abnormally
*/

#define format_soft_whatc(tWhat)                                  \
    _T("Source File : ")  _T(__FILE_NAME__)             _T("\n")  \
    _T("Line : ")         _T(__str_macroc__(__LINE__))  _T("\n")  \
    _T("Function : ")     _T(__FUNCSIG__)               _T("\n")  \
    _T("Infomation : ")   tWhat

#define malloccRAS(size) ( {                         \
    void *p = malloc(size);                          \
    if (!p) {                                        \
    raisec(                                          \
        EXCEPTC_CODE_SOFT_NO_MEMORY,                 \
        format_soft_whatc(                           \
            _T("Failed to allocate memory, size: ")  \
            _T(#size)                                \
        )                                            \
    ); }                                             \
    p;                                               \
} )

#define calloccRAS(count, size) ( {          \
    void *p = calloc(count, size);           \
    if (!p) {                                \
    raisec(                                  \
        EXCEPTC_CODE_SOFT_NO_MEMORY,         \
        format_soft_whatc(                   \
            _T("Failed to allocate memory")  \
            _T(", count: ") _T(#count)       \
            _T(", size: ") _T(#size)         \
        )                                    \
    ); }                                     \
    p;                                       \
} )

#endif /* __clang__ */

#define freec(p) \
    do { if (p) { free(p); p = NULL; } } while (0)

/* 
    The reason for being defined as a static function is to keep the type of tchar consistent.
    If you need these static functions,
    define the EXCEPTC_DEF_STATIC_FUNCTIONS before including exceptc.h.
    This macro is meant to prevent the same static function from being defined in every C file,
    causing the code segment to swell.
*/

#ifdef EXCEPTC_DEF_STATIC_FUNCTIONS

#include <stdio.h>

static INT default_filterc(
    PEXCEPTC_RECODE pRecode, EXCEPTC_STRUCTURE* pStructure
) {
    if (pStructure == NULL) { return EXCEPTION_EXECUTE_HANDLER; }
    
    __try {
        pStructure->bCatchSuccess = FALSE;

        pStructure->dwCode = pRecode->ExceptionRecord->ExceptionCode;
        if (EXCEPTC_TYPE(pStructure->dwCode) == EXCEPTC_TYPE_SOFT) {
            _tcscpy_s(
                pStructure->tWhat, EXCEPTC_TWAHT_MAX_LEN,
                (PTCHAR)pRecode->ExceptionRecord->
                ExceptionInformation[EXCEPTC_TWHAT_INDEX]
            );
        } else /* EXCEPTC_TYPE_HARD */ {
            _stprintf_s(
                pStructure->tWhat, EXCEPTC_TWAHT_MAX_LEN,
                _T("Code: 0x%08X\nFlags: 0x%08X\nAddress: 0x%08X"),
                pRecode->ExceptionRecord->ExceptionCode,
                pRecode->ExceptionRecord->ExceptionFlags,
                pRecode->ExceptionRecord->ExceptionAddress
            );
        }

        pStructure->bCatchSuccess = TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) { /* Ignore all exceptions */ }

    return EXCEPTION_EXECUTE_HANDLER;
}

#endif /* EXCEPTC_DEF_STATIC_FUNCTIONS */

#endif /* _EXCEPTC_H_ */
#endif /* __cplusplus */
#endif /* _MSC_VER */