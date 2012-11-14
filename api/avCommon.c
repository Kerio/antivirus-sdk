/**
 * Copyright (C) 1997-2012 Kerio Technologies s.r.o.  
 *
 * This file contains useful functions that you can use unchanged.
 * Include this file in your plugin's project.
 * 
 * DO NOT CHANGE THIS FILE
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "avApi.h"
#include "avCommon.h"
#include "avName.h"    // use constants defined in the plugin
#include "avPlugin.h"  // use functions defined in the plugin -- return pointers to them as plugins' API

/**
 * Global error message
 */
char errorMessage[MAX_STRING] = "";

/**
 * The instance of global logging callback used for log forwarding
 */
AV_LOG_CALLBACK_NEW logCallback = NULL;

/**
 * Log a warning message to a Kerio product
 * 
 * \param format (const char *) null-terminated string format
 * \param  (...) null-terminated strings according to format
 * \return (void)
 */
void logWarning(const char* format, ...) 
{
    va_list arg;
    char buffer[MAX_STRING];

    if (logCallback && format) {
        va_start(arg, format);
        vsnprintf(buffer, sizeof(buffer), format, arg);
        va_end(arg);
        
        buffer[MAX_STRING - 1] = 0;
        logCallback("WRN: %s", buffer);
    }
}

/**
 * Log an error message to a Kerio product
 * 
 * \param format (const char *) null-terminated string format 
 * \param  (...) null-terminated strings according to format
 * \return (void)
 */
void logError(const char* format, ...) 
{
    va_list arg;
    char buffer[MAX_STRING];

    if (logCallback && format) {
        va_start(arg, format);
        vsnprintf(buffer, sizeof(buffer), format, arg);
        va_end(arg);

        buffer[MAX_STRING - 1] = 0;
        logCallback("ERR: %s", buffer);        
    }
}

/**
 * Log an security message to a Kerio product
 * 
 * \param format (const char *) null-terminated string format
 * \param  (...) null-terminated strings according to format
 * \return (void)
 */
void logSecurity(const char* format, ...) 
{
    va_list arg;
    char buffer[MAX_STRING];

    if (logCallback && format) {
        va_start(arg, format);
        vsnprintf(buffer, sizeof(buffer), format, arg);
        va_end(arg);

        buffer[MAX_STRING - 1] = 0; // safe string
        logCallback("SEC: %s", buffer);        
    }
}

/**
 * Log an debug message to a Kerio product
 * 
 * \param format (const char *) null-terminated string format
 * \param  (...) null-terminated strings according to format
 * \return (void)
 */
void logDebug(const char* format, ...) 
{
    va_list arg;
    char buffer[MAX_STRING];

    if (logCallback && format) {
        va_start(arg, format);
        vsnprintf(buffer, sizeof(buffer), format, arg);
        va_end(arg);

        buffer[MAX_STRING - 1] = 0; // safe string
        logCallback("External_plugin: %s", buffer);
    }
}

/**
 * Get plugin info
 * 
 * \param info (avir_plugin_info *) Allocated plugin-info structure
 * \return (void)
 */
void getPluginInfo(avir_plugin_info *info) 
{
    assert(sizeof(AVPLUGIN_SHORTCUT) < 64);
    assert(sizeof(AVPLUGIN_DESCRIPTION) < 128);
    assert(sizeof(AVPLUGIN_SHORTCUT) > 0);
    assert(sizeof(AVPLUGIN_DESCRIPTION) > 0);

    strncpy(info->name, AVPLUGIN_SHORTCUT, sizeof(AVPLUGIN_SHORTCUT));
    info->name[sizeof(AVPLUGIN_SHORTCUT) - 1] = 0; // safe string
    strncpy(info->description, AVPLUGIN_DESCRIPTION, sizeof(AVPLUGIN_DESCRIPTION));
    info->description[sizeof(AVPLUGIN_DESCRIPTION) - 1] = 0; // safe string

    info->reserved[0] = 0;
    info->reserved2 = 0;
}

/**
 * Get global error message, null terminated
 * 
 * \param buffer (char *) output buffer
 * \param bufsize (int) output buffer size
 * \return (void)
 */
void getErrorMessage(char* buffer, int bufsize) 
{
    strncpy(buffer, errorMessage, bufsize > MAX_STRING ? MAX_STRING : bufsize);
    buffer[bufsize > MAX_STRING ? MAX_STRING - 1 : bufsize - 1] = 0; // safe string
}

/**
 * Upload new configuration to this plugin (used by Kerio products)
 * 
 * \param cfg (const avir_plugin_config *) input configuration
 * \return (int) count of saved items
 */
int setPluginConfig(const avir_plugin_config *cfg) 
{
    unsigned int i, j, saved = 0;

    if (NULL == cfg) {
        return 0;
    }

    for (i = 0; cfg[i].name[0]; i++) {
        for (j = 0; plugin_config[j].name[0]; j++) {
            if (stricmp(cfg[i].name, plugin_config[j].name) == 0) {
                plugin_config[j] = cfg[i];
                saved++;
                break;
            }
        }
    }
    return saved;
}

/**
 * Get actual plugin configuration
 * 
 * \return (avir_plugin_config *) new instance of plugin configuration
 */
avir_plugin_config *getPluginConfig() 
{
    avir_plugin_config *rv;
    unsigned int i;

    if ((rv = (avir_plugin_config *) malloc(sizeof(avir_plugin_config) * CONFIG_SIZE)) == 0) {
        return 0;
    }
    for (i = 0; i < CONFIG_SIZE; i++) {
        rv[i] = plugin_config[i];
    }
    return rv;
}

/**
 * Free plugin configuration
 * 
 * \param cfg (avir_plugin_config *) An instance of plugin configuration returned by getPluginConfig()
 * \return (void)
 */
void freePluginConfig(avir_plugin_config *cfg) 
{
    free(cfg);
}

/**
 * Store log_callback, and let the plugin do the rest of initialization.
 */
int pluginInitWrapper(AV_LOG_CALLBACK_NEW log_callback) 
{
    logCallback = log_callback;
    return pluginInit();
}

/**
 * Prototype of public method returning the plugin interface (set of pointers to functions).
 * The plugin must define function get_plugin_extended_iface 
 * (exported with extern "C" linkage if written in C++),
 * and set *version to 2.
 * 
 * \param version (unsigned int *) API version
 * \return (extern "C" DLL_EXPORT avir_plugin_extended_thread_iface*) interface structure
 */
extern avir_plugin_extended_thread_iface* get_plugin_extended_iface(unsigned int* version) 
{
    static avir_plugin_extended_thread_iface syncInterface = {
        getPluginInfo,
        getErrorMessage,
        setPluginConfig,
        getPluginConfig,
        freePluginConfig,
        pluginInitWrapper,
        pluginClose,
        NULL,
        NULL,
        NULL,
        NULL,
        threadInit,
        threadClose,
        testFile
    };

    *version = 2;
    return (&syncInterface);
}
