/**
 * Copyright (C) 1997-2012 Kerio Technologies s.r.o.  
 *
 * API header for antivirus plugins.
 *
 * This is the core API used by plugins.
 * 
 * You may use only this file (without using avCommon.c) in your plugin and implement the API, but
 * the easier way is to use all the files in this directory and implement functions from avPlugin.h instead.
 *
 * DO NOT CHANGE THIS FILE
 */

#ifndef KERIO_AVAPI_H
#define KERIO_AVAPI_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Maximum string size for error and log messages
 */
#define MAX_STRING 512

#ifndef _WIN32
#undef stricmp
#define stricmp(a,b) strcasecmp(a,b)
#endif

/**
 * Error while scanning file
 */
#define AVCHK_FAILED      0
/**
 * File is clean
 */
#define AVCHK_OK          1
/**
 * Virus found in file
 */
#define AVCHK_VIRUS_FOUND 2		
/**
 * File was cured - not supported yet
 */
#define AVCHK_VIRUS_CURED 3		
/**
 * Cannot check whether the file is infected or not (corrupted, encrypted, ...)
 */
#define AVCHK_IMPOSSIBLE  4		
/**
 * Serious error, avserver will be killed and plugin will be loaded again
 */
#define AVCHK_ERROR       5		

/** 
 * Log callback to send log message, message should not be terminated with endline but must be terminated with \0
 */
typedef void (* AV_LOG_CALLBACK_NEW)(const char* format, ...)
#ifdef __GNUC__
__attribute__((format(printf, 1, 2)))
#endif
;

/** 
 * Configuration option name and its value pair
 * Encoding of each string is US-ASCII
 */
typedef struct avir_plugin_config_s {
    /**
     * Name of configuration item
     */
    char name[32];
    /**
     * Value of item
     */
    char value[128];
} avir_plugin_config;

/** 
 * Information about the plugin itself 
 * Encoding of each string is US-ASCII
 */
typedef struct avir_plugin_info_s {
    /**
     * Name of plugin (for example "avir_clam")
     */
    char name[64];
    /**
     * Description shown in Administration console (for example "Clam AntiVirus plugin for Kerio")
     */
    char description[128];
    /**
     * NOT USED and must be set to empty string ""
     */
    char reserved[64];
    /**
     * NOT USED and must be set to 0
     */
    int reserved2;
} avir_plugin_info;

/**
 * Pointers to plugin's exported functions.
 */
typedef struct avir_plugin_extended_thread_iface_s {
    /** 
     * Get information about the plugin.
     * 
     * \param info The function must fill info's name and description, and zeroed reserved and reserved2.
     */
    void (* get_plugin_info)(avir_plugin_info * info);

    /** 
     * Get the last error from initialization or updating.
     * You must zero-terminate the message, and fit within the given buffer (incl. the terminating '\0').
     * 
     * \param buffer buffer to put the message in, result string will be always zero terminated
     * \param bufsize size of the buffer
     */
    void (* get_error_message)(char* buffer, int bufsize);

    /** 
     * Set configuration.
     * This function is always called before plugin_init(...).
     * 
     * \param config array with configuration.
     * The terminating entry beyond the array has a name "" (i.e. let's iterate until we find empty name).
     * \return number of saved values (this means whose names were valid)
     */
    int (* set_plugin_config)(const avir_plugin_config * config);

    /** 
     * Get current configuration.
     * 
     * \return pointer to array with configuration,
     * Given structure will be released by calling free_plugin_config(...)
     * You must put a terminating entry with empty name "" to mark the end of the array.
     */
    avir_plugin_config * (* get_plugin_config)();

    /** 
     * Release the configuration created by get_plugin_config().
     * 
     * \param config pointer to array with configuration created by get_plugin_config
     */
    void (* free_plugin_config)(avir_plugin_config * config);

    /** 
     * Init the plugin (and antivirus).
     * 
     * \param log_callback will be called for every events from plugion with these prefixes:
     * * "ERR: <text>" - error log, 
     * * "PRO: <text>" update progress,
     * * "SEC: <text> - security log, 
     * * "<text>" - debug log.
     * You may store log_callback and use it anytime later, e.g. inside plugin_thread_test_file().
     */
    int (* plugin_init)(AV_LOG_CALLBACK_NEW log_callback);

    /** 
     * Finish the work with antivirus and release resources.
     * 
     * \return 1 on success, 0 on failure
     */
    int (* plugin_close)(void);

    /** RESERVED, MUST BE NULL */
    int (* reserved1)(void);
    /** RESERVED, MUST BE NULL */
    int (* reserved2)(void);
    /** RESERVED, MUST BE NULL */
    int (* reserved3)(void);
    /** RESERVED, MUST BE NULL */
    int (* reserved4)(void);

    /** 
     * Init the context for new scanning thread, worker thread will be created from engine itself and will call 
     * plugin_thread_test_file with returned context each time file is scanned.
     * Do not create your own thread inside this function.
     * Variables inside context must not be shared to ensure thread-safe.
     * 
     * \param [out] context data needed for scanning using the thread.
     * E.g. *context = new MyThreadContext(...);
     * \return 1 on success, 0 on failure
     */
    int (* plugin_thread_init)(void **context);

    /** 
     * Free given thread context, context is not needed anymore due to termination of worker thread.
     * This is pair function for plugin_thread_init function.
     * 
     * \param [in] context data returned from plugin_thread_init() method.
     * E.g. delete (MyThreadContext*)(*context);
     * \return 1 on success, 0 on failure
     */
    int (* plugin_thread_close)(void **context);

    /** 
     * Check given file for a virus using synchronous (blocking) method.
     * This function is called from worker threads within engine with context created by plugin_thread_init function. 
     * If all worker threads are blocked, additional thread will be created from engine.
     * 
     * \param context context-data created with plugin_thread_init()
     * \param filename (with full path) file to check
     * \param realname original name of the file, if known
     * \param reserved not used, ignore the value
     * \param reserved_size not used, ignore the value
     * \param vir_info virus name or error message
     * \param vi_size size of vir_info message
     * \return check result code AVCHK_XXXX, e.g. AVCHK_OK
     */
    int (* plugin_thread_test_file)(
            void *context,
            const char *filename,
            const char *realname,
            char *reserved, unsigned int reserved_size,
            char *vir_info, unsigned int vi_size);

} avir_plugin_extended_thread_iface;

/**
 * Add __declspec(dllexport) on windows before functions.
 */
#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT
#endif

/**
 * Prototype of public method returning the plugin interface (set of pointers to functions).
 * The plugin must define function get_plugin_extended_iface 
 * (exported with extern "C" linkage if written in C++),
 * and set *version to 2.
 * 
 * \param version (unsigned int *) API version
 * \return (extern "C" DLL_EXPORT avir_plugin_extended_thread_iface*) interface structure
 */
typedef avir_plugin_extended_thread_iface *(* GET_PLUGIN_EXTENDED_IFACE)(unsigned int* version);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // KERIO_AVAPI_H
