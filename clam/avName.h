/**
 * Copyright (C) 1997-2012 Kerio Technologies s.r.o.  
 *
 * Kerio Multi-threaded Antivirus plugin for Clam AntiVirus 0.95+
 *
 * This file defines the name and description of the plugin.
 *
 * It's included by ../api/avCommon.c
 */

#ifndef KERIO_AVNAME_H
#define KERIO_AVNAME_H

/**
 * The plugin shortcut must begin with "avir_" and should be the same as dynamic library filename
 */
#define AVPLUGIN_SHORTCUT "avir_clam"

/**
 * The plugin description
 */
#define AVPLUGIN_DESCRIPTION "Clam AntiVirus plugin v0.1 for Kerio"

#endif // KERIO_AVNAME_H
