# Antivirus Plugins for Kerio Products

Antivirus plugins for Kerio products are used for communication between Kerio products (Kerio Connect, Kerio Control) and external antivirus program.

## Supported versions and platforms

We successfully compiled it on Debian GNU/Linux 6.0 and CentOS 6.3.

* Kerio Connect 7.1 and newer
* Kerio Control 7.0 and newer

## Content

* `api/` -- The API a plugin must implement
* `clam/` -- ClamAV plugin
* `sample/` -- Skeleton of a new plugin

## How to compile

1. You need a 32-bit compiler. The easiest way is to use an i386 (not x64) Linux distribution.
2. Get CMake build tool.

   **NOTE:** We tested version 2.8.7
   * [Download CMake](http://www.cmake.org/HTML/Download.html), build and install
   * Or install a package, e.g. on Debian

         apt-get install cmake        
    
3. Get Boost libraries. (Only for ClamAV plugin, not needed for sample.)

   **NOTE:** We tested versions 1.48 and 1.51
   * [Download Boost](http://www.boost.org/users/history/version_1_51_0.html), build and install. 
   * Set environment variables:

         export BOOST_INCLUDEDIR=/usr/local/include
         export BOOST_LIBRARYDIR=/usr/local/lib

   * Or install packages, e.g. on Debian:

         apt-get install libboost1.48-dev libboost-thread1.48-dev libboost-filesystem1.48-dev libboost-system1.48-dev libboost-date-time1.48-dev libboost-regex1.48-dev libboost-chrono1.48-dev

4. Run `cmake .` inside plugin's source directory (where `CMakeLists.txt` resides) -- in `clam/` or in `sample/`.
5. Build binary using `make`.

## Installation

Once you compile the plugin (`avir_*.so`), copy it to `/opt/kerio/mailserver/plugin/avirs/` (Kerio Connect) or `/opt/kerio/winroute/avirplugins/` (Kerio Control), and run the administration console. You may want to change the default settings in (`Antivirus -> Select antivirus... -> Options...`). Then start the plugin in the administration console.

See [ClamAV Kerio KB article](http://kb.kerio.com/article.php?id=282) for further instructions.

## How To Write Your Own Plugin

To write a new AV plugin, you need to provide implementation of the Kerio AV API, calling the external AV to actually scan files.

There are two options:

1. **avPlugin.h**
2. **avApi.h**

You shall implement one of those.

### 1. avPlugin.h

This is the simpler API. To use it, include all files from `api/` directory (incl. `avCommon.c`) in your project, then copy `sample/avPlugin.c` to a new file and provide function bodies -- the implementation, the calls to the external AV.

You don't need to understand the details described below, because `avCommon.c` does the dirty work for you.

Both plugins (in `sample/` and in `clam/`) use this way.

### 2. avApi.h

This is the low-level API. To use it, include just `api/avApi.h`, ignore the other files in the `api/` directory, and follow the instructions below.

## Exported Symbols

The plugin must export the `get_plugin_extended_iface(unsigned int* version)` function. The function has to use the C calling convention. This function should set ***version** to **2** and return a pointer to the **avir_plugin_extended_thread_iface** defined in `avApi.h`.

## Plugin Usage

Plugin's functions are usually called in this order:

1. get_plugin_extended_iface
2. set_plugin_config
3. plugin_init
4. plugin_thread_init
5. plugin_thread_test_file
6. plugin_thread_close
7. plugin_close
8. Configuration

When the plugin library is loaded and the exported function is found and executed, `set_plugin_config(…)` is called to set the current plugin configuration. It can contain for example an IP address of the antivirus server in case it uses network communication.

Notice that the list of options is hard-coded in each plugin. The plugin shall ignore unknown options.

Function `get_plugin_config()` should return a copy of current config; `free_plugin_config(…)` will be called later to free it.

Each of these functions works with a structure containing a name of an option and its value:

    typedef struct avir_plugin_config_s {
        char name[32];
        char value[128];
    } avir_plugin_config;

The name and value of the last item in the array of configuration values should be an empty string.

The function `get_plugin_info(…)` returns an information about the plugin.

    typedef struct avir_plugin_info_s {
        char name[64];
        char description[128];
        char reserved[64];
        int reserved2;
    } avir_plugin_info;
 
The **name** should contain a name of the plugin library without path and extension, e.g. `avir_clam`. The **description** should contain name of the antivirus and version of the plugin, such as **TheAV plugin 0.4.2 for Kerio**. The **reserved** and **reserved2** are ignored and should be zeroed.

## Threading

When Kerio product wants to pass a scanning request to the plugin, the thread management checks if at least one thread is free for use. If it is not, a new thread is created and then `plugin_thread_init` is called to create a new context (which could be a new connection to TCP-based antivirus, or a new handle created by the antivirus SDK), and the context is then used as a parameter of `plugin_thread_test_file method`. Contexts are reused if a thread is available. Too old unused thread is automatically closed, and `plugin_thread_close` method is called to free the context.

Notice that the thread management (which creates or destroys a thread) is a part of Kerio products (**avserver** daemon), and the plugin implements just a few callbacks (init and close a context). Plugin does not actually create a new thread.

## Using external dynamic libraries

The communication between plugin and antivirus could be for example via loading a dynamic library, pipes or network communication using protocols like ICAP or SCIP.

If the antivirus manufacturer provides their API as a dynamic library, don't use static linkage against the dynamic library. Dynamic linkage (dlopen(3)) should be used, so that it's always possible to load the plugin, even if the antivirus isn't installed.

## Strings encoding

* Input encoding (incoming strings to plugin) is UTF-8
* Output encoding is 7-bit US-ASCII (virus results, logs)

## Logging

Use `debug/error/warning` logging extensively! It will greatly help you to identify problems which will happen.

The **printf()**-like functions `logDebug`, `logError`, `logWarning` and `logSecurity` are defined in `api/avCommon.c`.

## How To Test Your Own Plugin

After you successfully wrote a new AV plugin, it can be tested with provided framework under `test/` directory. In order to test your plugin, copy compiled shared library into `test/` directory and rename it to `avir.so`. Run `./tests` executable via command line and you will be prompted to choose one of prepared tests:

* `avplugins_generate_test_data` - run it first to generate all test samples
* `avplugins_scanning_test` - simply scans prepared set of files with provided plugin
* `avplugins_waiting_test` - scans prepared set of files and tests whether connections will not timeout between scans
* `avplugins_server_test` - plugin is used exactly the same way as inside product, it is embedded into standalone antivirus server process outside test process, thus tests various conditions of plugin states

Run chosen test simply by entering its number into command line.

Note that every configuration of plugin (ip address, port, etc.) must be done via default configuration inside plugin, it will not be overwritten by tests. That's a limitation of tests, Kerio products will provide the configuration values as described above.

## Copyright

Copyright © 1997-2012 Kerio Technologies s.r.o.

Licensed and distributed under the New BSD License

## License

    Copyright (c) 1997-2012, Kerio Technologies s.r.o.
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:
        * Redistributions of source code must retain the above copyright
          notice, this list of conditions and the following disclaimer.
        * Redistributions in binary form must reproduce the above copyright
          notice, this list of conditions and the following disclaimer in the
          documentation and/or other materials provided with the distribution.
        * Neither the name of the Kerio Technologies nor the
          names of its contributors may be used to endorse or promote products
          derived from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL KERIO TECHNOLOGIES BE LIABLE FOR ANY
    DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
    ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.`

