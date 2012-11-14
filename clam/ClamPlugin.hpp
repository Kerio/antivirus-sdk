/**
 * Copyright (C) 1997-2012 Kerio Technologies s.r.o.  
 *
 * Kerio Multi-threaded Antivirus plugin for Clam Antivirus 0.95+
 */

#ifndef CLAM_PLUGIN_HPP
#define CLAM_PLUGIN_HPP

#include <string>
#include <sstream>
#include <boost/shared_ptr.hpp>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include "avPlugin.h"

/**
 * Acts as ClamAV TCP client to implement Kerio AV API.
 */
class ClamPlugin {
public:
    /**
     * Constructor
     */
    ClamPlugin();

    /**
     * Destructor
     */
    ~ClamPlugin();

    /**
     * Plugin initialization method
     * API method, see avPlugin.h ...
     * 
     * \return 0/1 false/true
     */
    int Init();

    /**
     * Plugin closing method
     * API method, see avPlugin.h ...
     * 
     * \return 0/1 false/true
     */
    int Close();

    /**
     * Check given file for a virus using synchronous (blocking) method.
     * This function is called from worker threads within engine with context created by plugin_thread_init function. 
     * If all worker threads are blocked, additional thread will be created from engine.
     * 
     * \param context context-data created with plugin_thread_init()
     * \param filename (with full path) file to check
     * \param realname original name of the file, if known
     * \param cured_fname not used, ignore the value
     * \param cf_size not used, ignore the value
     * \param vir_info virus name or error message
     * \param vi_size size of message
     * \return check result code AVCHK_XXXX, e.g. AVCHK_OK
     */
    int TestFile(void *context,
            const char *filename,
            const char *realname,
            char* cured_fname, unsigned int cf_size,
            char *vir_info, unsigned int vi_size);

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
    int ThreadInit(void **context);
    
    /** 
     * Free given thread context, context is not needed anymore due to termination of worker thread.
     * This is pair function for plugin_thread_init function.
     * 
     * \param [in] context data returned from plugin_thread_init() method.
     * E.g. delete (MyThreadContext*)(*context);
     * \return 1 on success, 0 on failure
     */
    int ThreadClose(void **context);

private:
    /**
     * All available plugin states
     */
    typedef enum _PluginState {
        Initializing = 0,
        Running,
        Updating,
        Reloading,
        Closing,
        Closed,
        Failed
    } PluginState;

    /**
     * Pointer to TCP stream
     */
    typedef boost::shared_ptr<boost::asio::ip::tcp::iostream> TCPClientStreamPtr;

    /**
     * Mutex type
     */
    typedef boost::mutex MutexType;
    
    /**
     * Mutex pointer
     */
    typedef boost::shared_ptr<MutexType> MutexPtr;
    
    /**
     * One thread context
     */
    class SyncStream {
        TCPClientStreamPtr stream;        
        int timeout;
        
    public:
        MutexPtr mutex;
        
        /**
         * Constructor
         */
        SyncStream(int _timeout)
            :stream(new boost::asio::ip::tcp::iostream()),timeout(_timeout),mutex(new MutexType) {            
        }
        
        /**
         * Connect to server
         * 
         * \param server server address with port separater by colon
         * \return true on success, false otherwise
         */
        bool connect(std::string &server);
        
        /**
         * Read data from server
         * 
         * \param id (unsigned int *) id of operation
         * \param output (string &) output string stream
         * \return (bool) result
         */
        bool readString(std::string &output, unsigned int *id = NULL);

        /**
         * Send string to ClamAV Server
         * 
         * \param input (const string &) data
         * \return (bool) result
         */
        bool sendString(const std::string & input);

        /**
         * Send file as STREAM to ClamAV Server 
         * 
         * \param file (const string &) file
         * \return (bool) result
         */
        bool sendFile(const std::string & file);
        
        /**
         * StartSession (atomic operation)
         * 
         * \return (bool) result
         */
        bool startSession();

        /**
         * Get version (atomic operation)
         * 
         * \param version (std::string &) result
         * \return (bool)
         */
        bool getVersion(std::string &version);

        /**
         * Send PING and receive PONG (clam protocol)
         * 
         * \param error (std::string &) error message when return value is false
         * \return (bool) result
         */
        bool sendPingPong(std::string &error);

        /**
         * EndSession (atomic operation)
         * 
         * \return (bool) result
         */
        bool endSession();
    };

    /**
     * Pointer to SyncStream
     */
    typedef boost::shared_ptr<SyncStream> SyncStreamPtr;

    /**
     * Vector of synchronized streams
     */
    typedef std::vector<SyncStreamPtr> ThreadStreams;

    /**
     * Currect status of this plugin
     */
    volatile PluginState state;

    /**
     * Count of running threads
     */
    volatile int runningThreads;

    /**
     * Flag for synchronization while closing
     */
    volatile bool closing;

    /**
     * Actual server address
     */
    std::string server;
        
    /**
     * Timeout in seconds for scanning connection
     */
    int timeout;

    /**
     * Mutex to secure connVector variable
     */
    MutexType connMutex;

    /**
     * Vector of connections for ping-ponging
     */
    ThreadStreams connVector;

    /**
     * Handle for keep-a-live thread
     */
    boost::thread *pingThreadHandle;

    /**
     * Add connection to vector for keep-alive
     * 
     * \param conn (SyncStreamPtr) TCP stream
     * \return (void)
     */
    void startConnectionRefresh(SyncStreamPtr &conn);

    /**
     * Remove connection from vector for keep-alive
     * 
     * \param conn (SyncStreamPtr) TCP stream
     * \return (void)
     */
    void dropConnectionRefresh(SyncStreamPtr &conn);

    /**
     * Wrapper for keep-a-live thread
     * 
     * \param params (void *)
     * \return (void)
     */
    static void keepAliveThreadWrapper(void *params);

    /**
     * Thread for keep-a-live
     * 
     * \return (void)
     */
    void keepAliveThread();
};

#endif // CLAM_PLUGIN_HPP
