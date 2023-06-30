#ifndef DEBUGGER_H
#define DEBUGGER_H
#include <stdio.h> 
#include<windows.h>
enum LOG_LEVEL {    
    LOG_LEVEL_OFF=0,
    LOG_LEVEL_FATAL,
    LOG_LEVEL_ERR,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
	LOG_LEVEL_ALL
};
extern enum LOG_LEVEL log_level_global;

#define log_fatal(level,format, ...) \
    do { \
         if(level>=LOG_LEVEL_FATAL)\
           printf("[FATAL @%s:%d->%s]" format,\
                     __FILE__, __LINE__, __func__, ##__VA_ARGS__ );\
    } while (0)

#define log_err(level,format, ...) \
    do { \
         if(level>=LOG_LEVEL_ERR){\
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 4);\
			printf("[ERROR @%s:%d->%s]" format,\
                     __FILE__, __LINE__, __func__, ##__VA_ARGS__ );\
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);\
		 }\
    } while (0)

#define log_warn(level,format, ...) \
    do { \
         if(level>=LOG_LEVEL_WARN){\
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 6);\
			printf("[WARN @%s:%d->%s]" format,\
                     __FILE__, __LINE__, __func__, ##__VA_ARGS__ );\
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);\
		 }\
    } while (0)

#define log_info(level,format, ...) \
    do { \
         if(level>=LOG_LEVEL_INFO){\
           printf("[INFO @%s:%d->%s]" format,\
                     __FILE__, __LINE__, __func__, ##__VA_ARGS__ );\
		 }\
    } while (0)

#define log_debug(level,format, ...) \
    do { \
         if(level>=LOG_LEVEL_ALL)\
           printf("[DEBUG @%s:%d->%s]" format,\
                     __FILE__, __LINE__, __func__, ##__VA_ARGS__ );\
    } while (0)

#endif