#ifndef DEBUGGER_H
#define DEBUGGER_H
#include <stdargs.h> 
#define infoprintf(format,args...) print_debug(INFO_OUTPUT, __FILE__,__func__,__LINE__,__DATE__, __TIME__,format,args);
int print_debug(FILE *stream,char *file_name,char *func_name,int line_number,char *date,char *time,char *format,...);

#endif