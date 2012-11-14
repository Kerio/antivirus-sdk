/**
 * Copyright (C) 1997-2012 Kerio Technologies s.r.o.  
 *
 * This file contains useful functions that you can use unchanged.
 * Include this file in your plugin's project.
 * 
 * DO NOT CHANGE THIS FILE
 */

#ifndef KERIO_AVCOMMON_H
#define KERIO_AVCOMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include "avApi.h"

/**
 * Size of config structure with last empty item
 */
extern const int CONFIG_SIZE;

/**
 * The external definition of instance of default configuration structure
 */
extern avir_plugin_config plugin_config[];

/**
 * The global error message.
 * Error message must be initialized as empty
 */
extern char errorMessage[MAX_STRING];

/**
 * Debug logging functions to log debug events
 */
void logDebug(const char* format, ...)
#ifdef __GNUC__
__attribute__((format(printf, 1, 2)))
#endif
;

/**
 * Error logging functions to log error events
 * Adds "ERR: " prefix to message
 */
void logError(const char* format, ...)
#ifdef __GNUC__
__attribute__((format(printf, 1, 2)))
#endif
;

/**
 * Warning logging functions to log warning events
 * Adds "WAR: " prefix to message
 */
void logWarning(const char* format, ...)
#ifdef __GNUC__
__attribute__((format(printf, 1, 2)))
#endif
;

/**
 * Security logging functions to log security events
 * Adds "SEC: " prefix to message
 */
void logSecurity(const char* format, ...)
#ifdef __GNUC__
__attribute__((format(printf, 1, 2)))
#endif
;

/**
 * Returns a copy of plugin_config.
 * Allocated configuration copy will released with freePluginConfig(cfg) call
 * 
 * \return cfg copy of configuration, must be copy of original structure
 */
avir_plugin_config *getPluginConfig();

/**
 * Frees memory previously allocated by getPluginConfig().
 * 
 * \param cfg configuration to free
 */
void freePluginConfig(avir_plugin_config *cfg);

#ifdef __cplusplus
}    // extern "C"
#endif

#endif // KERIO_AVCOMMON_H
