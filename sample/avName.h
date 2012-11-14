/**
 * Copyright (C) 1997-2012 Kerio Technologies s.r.o.  
 *
 * Sample plugin.
 * 
 * This file defines the name and description of the plugin.
 *
 * It's included by ../api/avCommon.c
 * 
 * To create your own plugin, 
 * replace the definitions (strings).
 */

#ifndef KERIO_AVNAME_H
#define KERIO_AVNAME_H

/**
 * The plugin shortcut must begin with "avir_" and should be the same as dynamic library filename
 */
#define AVPLUGIN_SHORTCUT "avir_sample"

/**
 * The plugin description
 */
#define AVPLUGIN_DESCRIPTION "A sample external plugin for Kerio"

#endif // KERIO_AVNAME_H
