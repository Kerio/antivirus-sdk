/**
 * Copyright (C) 1997-2012 Kerio Technologies s.r.o.  
 *
 * This is a sample no-op plugin.
 *
 * It only defines necessary functions.
 *
 * To create your own plugin, provide bodies for the functions below.
 *
 * Compile together with ../api/avCommon.c.
 */

#include <string.h>
#include "avApi.h"
#include "avCommon.h"
#include "avPlugin.h"

/**
 * The instance of example configuration structure
 */
avir_plugin_config plugin_config[] = {
    {"Option 1", "0"},
    {"Option 2", "a string"},
    {"", ""} // mandatory terminating pair of two empty strings
};

const int CONFIG_SIZE = sizeof (plugin_config) / sizeof (plugin_config[0]);

int pluginInit(void)
{
    logDebug("The Sample plugin is initializing ...");
    return 1; // ok
}

int pluginClose()
{
    logDebug("The Sample plugin is closing ...");
    return 1; // ok
}

int threadInit(void **context)
{
    logDebug("The Sample plugin thread context is initializing ...");
    *context = NULL;

    return 1; // ok
}

int threadClose(void **context)
{
    logDebug("The Sample plugin thread context is closing ...");
    *context = NULL;
    
    return 1; // ok
}

int testFile(void *context,
        const char *filename,
        const char *realname,
        char *reserved, unsigned int reserved_size,
        char *vir_info, unsigned int vi_size)
{
    logDebug("The Sample plugin is scanning file %s", filename);
    
    int result = AVCHK_FAILED;

    /* dummy compare to pass test */
    if (strstr(filename, "clean.exe")) {
        result = AVCHK_OK;
    }
    else if (strstr(filename, "eicar.com")) {
        result = AVCHK_VIRUS_FOUND;
    }
    else if (strstr(filename, "eicar.tmp")) {
        result = AVCHK_VIRUS_FOUND;
    }
    else if (strstr(filename, "eicar.zip")) {
        result = AVCHK_VIRUS_FOUND;
    }
    else if (strstr(filename, "eicarpwd.zip")) {
        result = AVCHK_IMPOSSIBLE;
    }
    else if (strstr(filename, "empty.file")) {
        result = AVCHK_OK;
    }
    else if (strstr(filename, "huge.file")) {
        result = AVCHK_OK;
    }
    else if (strstr(filename, "nonexisting.file")) {
        result = AVCHK_FAILED;
    }
    
    return result;
}
