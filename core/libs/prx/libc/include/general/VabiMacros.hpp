#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_GENERAL_GENERALMACROS_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_GENERAL_GENERALMACROS_HPP

#ifdef _WIN32
#define APS5_VABI __attribute__((sysv_abi))
#define APS5_VA_LIST __builtin_sysv_va_list
#define APS5_VA_START __builtin_sysv_va_start
#define APS5_VA_END __builtin_sysv_va_end
#else
#define APS5_VABI
#define APS5_VA_LIST __builtin_va_list
#define APS5_VA_START __builtin_va_start
#define APS5_VA_END __builtin_va_end
#endif

#endif
