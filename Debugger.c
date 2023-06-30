#include "Debugger.h"
enum LOG_LEVEL log_level_global=LOG_LEVEL_WARN;
void log_level_switch_to(LOG_LEVEL new_level){
	switch(new_level){
		case LOG_LEVEL_OFF:
			log_warn(LOG_LEVEL_WARN,"switched log level to OFF MODE, no message will be printed\n\n");
			break;
			
		case LOG_LEVEL_FATAL:
			log_warn(LOG_LEVEL_WARN,"switched log level to FATAL MODE, only FATAL message will be printed\n\n");
			break;
			
		case LOG_LEVEL_ERR:
			log_warn(LOG_LEVEL_WARN,"switched log level to ERROR MODE, only ERROR message and FATAL message will be printed\n\n");
			break;
		
		
		case LOG_LEVEL_WARN:
			log_warn(LOG_LEVEL_WARN,"switched log level to NORMAL MODE, only WARNING message, ERROR message and FATAL message will be printed\n\n");
			break;
			
		case LOG_LEVEL_INFO:
			log_warn(LOG_LEVEL_WARN,"switched log level to INFO MODE, all messages except DEBUG message will be printed\n\n");
			break;
		case LOG_LEVEL_ALL:
			log_warn(LOG_LEVEL_WARN,"switched log level to DEBUG MODE, all messages will be printed\n\n");
			break;
	}
	log_level_global=new_level;
}