/**
 * Copyright (C) 1997-2012 Kerio Technologies s.r.o.  
 *
 * This header defines the alternate, simpler API (compared to the API defined in avApi.h).
 * 
 * The functions will be called from avCommon.c, thus they must declared and defined as extern "C".
 * 
 * To create your own plugin, 
 * implement the functions declared here.
 * 
 * DO NOT CHANGE THIS FILE
 */

#ifndef KERIO_AVPLUGIN_H
#define KERIO_AVPLUGIN_H

#include "avApi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * To be implemented by the plugin
 * 
 * \see avApi.h plugin_init
 * \return (int)
 */
int pluginInit(void);

/**
 * Forward declaration
 * 
 * \see avApi.h plugin_close
 * \return (int)
 */
int pluginClose(void);

/**
 * To be implemented by the plugin
 * 
 * \see avApi.h plugin_thread_init
 * \param context (void * *)
 * \return (int)
 */
int threadInit(void **context);

/**
 * To be implemented by the plugin
 * 
 * \see avApi.h plugin_thread_close
 * \param context (void * *)
 * \return (int)
 */
int threadClose(void **context);

/** 
 * Check a file for a virus using synchronous (blocking) method.
 * To be implemented by the plugin
 * 
 * \see avApi.h plugin_thread_test_file
 * \param context context-data created with plugin_thread_init()
 * \param filename (with full path) file to check
 * \param realname original name of the file, if known
 * \param reserved not used, ignore the value
 * \param reserved_size not used, ignore the value
 * \param vir_info virus name or error message
 * \param vi_size size of message
 * \return check result code AVCHK_XXXX, e.g. AVCHK_OK
 */
int testFile(void *context,
        const char *filename,
        const char *realname,
        char *reserved, unsigned int reserved_size,
        char *vir_info, unsigned int vi_size);

#ifdef __cplusplus
}    // extern "C"
#endif

#endif // KERIO_AVPLUGIN_H
