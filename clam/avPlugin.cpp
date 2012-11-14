/**
 * Copyright (C) 1997-2012 Kerio Technologies s.r.o.  
 *
 * Kerio Multi-threaded Antivirus plugin for Clam AntiVirus 0.95+
 * 
 * This file is the bridge between api/avCommon.* and ClamPlugin.*.
 *
 * It also defines plugin's default configuration.
 */

#include <string.h>
#include "avApi.h"
#include "avCommon.h"
#include "avPlugin.h"
#include "ClamPlugin.hpp"

extern "C" {

/**
 * Plugin instance
 */
ClamPlugin plugin;

/**
 * The instance of default configuration structure
 * These options are available to be changed from product's Web Administration
 */
avir_plugin_config plugin_config[] = {
    {"Address", "127.0.0.1"},
    {"Port", "3310"},
    {"StartupTimeout", "90"},
    {"", ""}
};

const int CONFIG_SIZE = sizeof(plugin_config) / sizeof(plugin_config[0]);

int pluginInit(void)
{
    return plugin.Init();
}

int pluginClose()
{
    return plugin.Close();
}

int threadInit(void **context)
{
    return plugin.ThreadInit(context);
}

int threadClose(void **context)
{
    return plugin.ThreadClose(context);
}

int testFile(void *context,
        const char *filename,
        const char *realname,
        char* reserved, unsigned int reserved_size,
        char *vir_info, unsigned int vi_size)
{
    return plugin.TestFile(context, filename, realname, reserved, reserved_size, vir_info, vi_size);
}

}    // extern "C"

