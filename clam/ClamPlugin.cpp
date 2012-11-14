/**
 * Copyright (C) 1997-2012 Kerio Technologies s.r.o.  
 *
 * Kerio Multi-threaded Antivirus plugin for Clam AntiVirus 0.95+
 *
 */

#include <sys/stat.h>
#include <fstream>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string/trim.hpp>
#include "avCommon.h"
#include "ClamPlugin.hpp"

using namespace std;

/**
 * Minimal timeout to init contact with clamm-server in seconds. If configured timeout is lesser than INIT_TIMEOUT, 
 * INIT_TIMEOUT will be used instead.
 */
#define INIT_TIMEOUT 10

/**
 * Maximum allowed init timeout in seconds. If configured timeout is greater than MAX_TIMEOUT, 
 * MAX_TIMEOUT will be used instead.
 */
#define MAX_TIMEOUT 100

/**
 * Seconds between ping pong requests for keep alive thread
 */
#define KEEPALIVE_TIMEOUT 60

/**
 * Default port to contact ClamAV Server
 */
#define DEFAULT_PORT "3310"

/**
 * Specific answers from ClamAV Server
 */
const char encryptedMsg[] = "Encrypted";
const char brokenMsg[] = "Broken";
const char heuristicsEncryptedMsg[] = "Heuristics.Encrypted";

#ifdef _WIN32

#ifndef stat
/**
 *	Windows stat
 */
#   define stat _stati64
#endif

#ifndef k_lstat
/**
 * same as stat on windows, but lstat() on unixes
 */
#   define k_lstat _stati64
#endif

#else

#ifndef k_lstat 
#   define k_lstat lstat
#endif /* k_lstat */

#endif

/**
 * Atomic operations for Windows systems
 */
#ifdef _WIN32

static inline int atomicInc(volatile int *a) {return _InterlockedIncrement(reinterpret_cast<volatile long *>(a));}
static inline int atomicDec(volatile int *a) {return _InterlockedDecrement(reinterpret_cast<volatile long *>(a));}
static inline int atomicGet(volatile int *a) {return _InterlockedCompareExchange(reinterpret_cast<volatile long *>(a), 0, 0);}

#else /* not Windows */

/**
 * Atomic operations for Unix systems
 */
#ifdef __GNUC__
#   define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
/* Test for GCC >= 3.4.0 */
#   if GCC_VERSION >= 30400
#       define exchange_and_add_function __gnu_cxx::__exchange_and_add
#   else     /* <3.4.0 */
#       define exchange_and_add_function __exchange_and_add
#   endif    /* >=3.4.0 */
static inline int atomicInc(volatile int *a) {return exchange_and_add_function((a), 1) + 1;}
static inline int atomicDec(volatile int *a) {return exchange_and_add_function((a), -1) - 1;}
static inline int atomicGet(volatile int *a) {return exchange_and_add_function((a), 0);}
#else /* not gcc */
#   error Only GCC is supported for atomic operations! __GNUC__ not defined.
#endif /* gcc */

#endif /* else not Windows */

/**
 * Function for safe copy of null-terminated strings, function will copy string using strcpy and add additional Null character
 * at the end of string for sure.
 * 
 * \param dest target string buffer
 * \param src source string buffer
 * \param size size of string to be copied
 */
void strncpys(char *dest, const char *src, size_t size)
{
	assert(size > 0);

	if (size > 0) {
		strncpy(dest, src, size);
		dest[size - 1] = 0;
	}
}

bool ClamPlugin::SyncStream::connect(std::string &server)
{
    std::string::size_type colon = server.find_last_of(':');

    stream->expires_from_now(boost::posix_time::seconds(this->timeout)); // set timeout
    stream->connect(server.substr(0, colon), server.substr(colon + 1));
    stream->expires_from_now(boost::posix_time::pos_infin); // reset timeout

    if (stream->bad() || (!stream->good())) {
        return false;
    }
    return true;
}

bool ClamPlugin::SyncStream::sendString(const string &input)
{
    stream->expires_from_now(boost::posix_time::seconds(this->timeout)); // set timeout
    if (stream && (!stream->fail())) {
        *stream << "n" << input << endl;
        stream->flush();
        stream->expires_from_now(boost::posix_time::pos_infin); // reset timeout

        if (!stream->fail()) {
            return true;
        }
    }    
    return false;
}

bool ClamPlugin::SyncStream::sendFile(const string &file)
{
    stream->expires_from_now(boost::posix_time::seconds(this->timeout)); // set timeout
    if (stream && (!stream->fail())) {
        struct stat sb;
        if (-1 != k_lstat(file.c_str(), &sb)) {
            ifstream fstr(file.c_str(), ios::binary);
            if (fstr.is_open() && (!fstr.fail())) {
                unsigned int clamSize = (unsigned int) sb.st_size;

                clamSize = htonl(clamSize);
                stream->write((const char *) &clamSize, sizeof(unsigned int));

                if (fstr.good()) {
                    *stream << fstr.rdbuf();
                }
                clamSize = 0; // Write last empty chunk according to API
                stream->write((const char *) &clamSize, sizeof(unsigned int));
                stream->flush();
                stream->expires_from_now(boost::posix_time::pos_infin); // reset timeout

                if (!stream->fail()) {
                    return true;
                }
            }
        }
        stream->expires_from_now(boost::posix_time::pos_infin); // reset timeout
    }
    return false;
}

bool ClamPlugin::SyncStream::readString(string &output, unsigned int *id)
{
    output.clear();
    if (stream && stream->good()) {
        getline(*stream, output);
        boost::algorithm::trim(output);

        string::size_type pos = output.find(":");
        if (pos != string::npos) {
            if (id) {
                *id = atoi(output.c_str());
            }
            output.erase(output.begin(), output.begin() + pos + 2); // Reply format --> "NUMBER: REPLY"
        } 
        else if (id) {
            *id = 0;
        }

        pos = output.find("stream:");
        if (pos == 0) {
            output.erase(output.begin(), output.begin() + 8); // stream-reply format --> "NUMBER: stream: REPLY"
        }

        if (!stream->fail()) {
            return true;
        } 
        else {
            output = "Connection to ClamAV Server has failed.";
            return false;
        }
    } 
    else {
        output = "An error has occurred. Check your connection.";
        return false;
    }
}

ClamPlugin::ClamPlugin()
{
    this->server.clear();
    this->connVector.clear();
    this->closing = false;
    this->state = Closed;
    this->runningThreads = 0;
    this->pingThreadHandle = NULL;
}

ClamPlugin::~ClamPlugin()
{
    this->closing = true;

    if (NULL != this->pingThreadHandle) {
        this->pingThreadHandle->join();
        delete this->pingThreadHandle;
        this->pingThreadHandle = NULL;
    }
}

int ClamPlugin::ThreadInit(void **context)
{
    *context = NULL;
    
    logDebug("Initializing context");
    if (this->server.empty() || (context == NULL)) {
        logDebug("Internal context error");
        return 0;
    }

    SyncStreamPtr connection(new SyncStream(timeout));
    try {
        if (!connection->connect(this->server)) {
            strncpys(errorMessage, "Cannot connect to ClamAV Server.", MAX_STRING);
            logError("Cannot connect to ClamAV Server on %s", this->server.c_str());
            this->state = Failed;
            return 0;
        }
    } 
    catch (std::exception &e) {
        std::string msg = "Cannot connect to ClamAV Server, error: " + std::string(e.what());
        strncpys(errorMessage, msg.c_str(), MAX_STRING);
        logError("%s", msg.c_str());
        this->state = Failed;
        return 0;
    }

    if (!connection->startSession()) {
        logError("Cannot initiate session at the ClamAV Server");
        this->state = Failed;
        return 0;
    }
    
    this->startConnectionRefresh(connection);
    
    *context = new SyncStreamPtr(connection);
    logDebug("Context initialized");    
    return 1;
}

int ClamPlugin::ThreadClose(void **context)
{
    int result = 0;

    logDebug("De-initializing context");
    if (context) {
        SyncStreamPtr * connection((SyncStreamPtr *) * context);

        this->dropConnectionRefresh(*connection);

        if (!connection->get()->endSession()) {
            logWarning("Cannot destroy session at the ClamAV Server");
            result = 0;
        } 
        else {
            result = 1;
        }

        delete connection;
        *context = NULL;
    }
    return result;
}

int ClamPlugin::Init()
{
    if (this->state != Failed && this->state != Closed) {
        strncpys(errorMessage, "The Clam AntiVirus plugin has already been initialized.", MAX_STRING);
        logError("The Clam AntiVirus plugin has already been initialized.");
        this->state = Failed;
        return 0;
    }
    this->state = Initializing;

    string address;
    string port = DEFAULT_PORT;

    logDebug("Initializing Clam AntiVirus plugin...");

    avir_plugin_config *cfg = getPluginConfig();

    for (unsigned int i = 0; cfg[i].name[0]; i++) {
        if (stricmp("Address", cfg[i].name) == 0) {
            address = cfg[i].value;
            continue;
        }
        if (stricmp("Port", cfg[i].name) == 0) {
            port = cfg[i].value;
            continue;
        }
        if (stricmp("StartupTimeout", cfg[i].name) == 0) {
            string tm = cfg[i].value;
            timeout = atoi(tm.c_str());
            continue;
        }
    }

    freePluginConfig(cfg);

    if (timeout < INIT_TIMEOUT) {
        timeout = INIT_TIMEOUT;
    }

    if (timeout > MAX_TIMEOUT) {
        timeout = MAX_TIMEOUT;
    }

    logDebug("Startup timeout is set to %d", timeout);

    try {
        boost::asio::io_service io_service;
        boost::asio::ip::tcp::resolver resolver(io_service);
        boost::asio::ip::tcp::resolver::query query(address.c_str(), "");
        boost::asio::ip::tcp::resolver::iterator iter = resolver.resolve(query);
        boost::asio::ip::tcp::resolver::iterator end;

        if (iter != end) {
            boost::asio::ip::address addr = iter->endpoint().address();
            stringstream hostPort;
            hostPort << addr.to_string() << ":" << port;
            this->server = hostPort.str();
            logDebug("ClamAV Server IP address: %s", this->server.c_str());
        } 
        else {
            std::string msg = "Cannot resolve host (" + address + ").";
            strncpys(errorMessage, msg.c_str(), MAX_STRING);
            logError("%s", msg.c_str());
            this->state = Failed;
            return 0;
        }
    }
    catch (std::exception &e) {
        std::string msg = "Cannot resolve host (" + address + "). Error: " + std::string(e.what());
        strncpys(errorMessage, msg.c_str(), MAX_STRING);
        logError("%s", msg.c_str());
        this->state = Failed;
        return 0;
    }

    SyncStreamPtr connection(new SyncStream(timeout));
    try {
        if (!connection->connect(this->server)) {
            strncpys(errorMessage, "Cannot connect to ClamAV Server.", MAX_STRING);
            logError("Cannot connect to ClamAV Server on %s", this->server.c_str());
            this->state = Failed;
            return 0;
        }
    }
    catch (std::exception &e) {
        std::string msg = "Cannot connect to ClamAV Server, error: " + std::string(e.what());
        strncpys(errorMessage, msg.c_str(), MAX_STRING);
        logError("%s", msg.c_str());
        this->state = Failed;
        return 0;
    }

    bool result = connection->startSession();
    if (!result) {
        logWarning("Cannot initiate session to the ClamAV Server");
    } 
    else {
        logDebug("Session initialized.");
    }

    string error;
    if (!connection->sendPingPong(error)) {
        strncpys(errorMessage, error.c_str(), MAX_STRING);
        this->state = Failed;
        return 0;
    }
    
    string answer;
    if (!connection->getVersion(answer)) {
        strncpys(errorMessage, "Only ClamAV Server 0.95 and newer is supported.", MAX_STRING);
        logError("Only ClamAV Server 0.95 and newer is supported.");
        this->state = Failed;
        return 0;
    }
    logDebug("Version: %s", answer.c_str());

    result = connection->endSession();
    if (!result) {
        logWarning("Cannot destroy session at the ClamAV Server");
    } 
    else {
        logDebug("Session finished.");
    }

    logDebug("The engine has been initialized");
    this->state = Running;

    try {
        this->pingThreadHandle = new boost::thread(boost::bind(this->keepAliveThreadWrapper, this)); // boost::thread_resource_error can be thrown
    } 
    catch (std::exception &e) {        
        logWarning("Unable to run thread for keep-a-live.");
        this->pingThreadHandle = NULL;
    }

    return 1;
}

int ClamPlugin::Close()
{
    if (this->state == Closed) {
        logDebug("The Clam AntiVirus plugin is already closed.");
        return 1;
    }

    logDebug("The Clam AntiVirus plugin is closing...");
    this->closing = true;
    this->state = Closing;

    int count = atomicGet(&this->runningThreads);    
    while (count > 0) {
        logDebug("Waiting for %d of running threads before closing.", count);
        boost::this_thread::sleep(boost::posix_time::milliseconds(1000));        
        count = atomicGet(&this->runningThreads);
    }

    if (this->pingThreadHandle) {
        this->pingThreadHandle->join();
        delete this->pingThreadHandle;
        this->pingThreadHandle = NULL;
    }

    this->state = Closed;
    return 1;
}

int ClamPlugin::TestFile(void *context, const char *filename, const char *realname, char* cured_fname, unsigned int cf_size,
        char *vir_info, unsigned int vi_size)
{
    logDebug("Scanning file '%s'...", filename);

    if ((filename == NULL) || (vir_info == NULL)) {
        return AVCHK_ERROR;
    }

    /* check whether file exists */
    try {
        if (!boost::filesystem::exists(filename)) {
            std::string response = std::string(filename) + " does not exist.";
            strncpys(vir_info, response.c_str(), vi_size);
            logDebug("Scanned file %s", vir_info);
            return AVCHK_FAILED;
        }
    } 
    catch (boost::filesystem::filesystem_error &e) {
        std::string msg = "Cannot check file: " + std::string(filename) + ", error: " + std::string(e.what());
        strncpys(vir_info, msg.c_str(), vi_size);
        logDebug("%s", vir_info);
        return AVCHK_FAILED;
    }

    /* check whether file is non empty, empty file doesnt need to be checked and are AVCHK_OK by default*/
    try {
        if (0 == boost::filesystem::file_size(filename)) {
            std::string response = std::string(filename) + " is empty.";
            strncpys(vir_info, response.c_str(), vi_size);
            logDebug("Scanned file %s", vir_info);
            return AVCHK_OK;
        }
    } 
    catch (boost::filesystem::filesystem_error &e) {
        std::string msg = "Cannot check file size: " + std::string(filename) + ", error: " + std::string(e.what());
        strncpys(vir_info, msg.c_str(), vi_size);
        logDebug("%s", vir_info);
        return AVCHK_FAILED;
    }

    /* check whether engine has been initialized */
    if (context == NULL) {
        strncpys(vir_info, "Scanning failed - No engine is initialized...", vi_size);
        logDebug("%s", vir_info);
        return AVCHK_ERROR;
    }

    atomicInc(&this->runningThreads);

#ifdef _DEBUG
    logDebug("Currently running threads: %d.", atomicGet(&this->runningThreads));
#endif

    if (this->state != Running) {
        strncpys(vir_info, "Scanning failed - The engine is not ready...", vi_size);
        logDebug("%s", vir_info);
        atomicDec(&this->runningThreads);
        return AVCHK_ERROR;
    }

    /* default results */
    std::string errmsg = "Internal error";
    int scanningResult = AVCHK_ERROR; // kill plugin and make new initialization (recovery)
    bool result;
    SyncStreamPtr connection(*(SyncStreamPtr *) context);

    MutexType::scoped_lock lock(*connection->mutex.get());

    /* send file to ClamAV Server and wait for response (blocking operations) */
    result = connection->sendString("INSTREAM");
    if (!result) {
        errmsg = "Cannot send stream to the ClamAV Server while processing scan of :" + std::string(filename);
        logError("%s", errmsg.c_str());
    } 
    else {
        result = connection->sendFile(filename);
        if (!result) {
            errmsg = "Cannot send file to the ClamAV Server: " + std::string(filename);
            logError("%s", errmsg.c_str());
        } 
        else {
            /* receive answer */
            string answer;
            result = connection->readString(answer);
            if (!result) {
                errmsg = "Scanning failed - The file cannot be scanned. ";
                if (!answer.empty()) {
                    errmsg += "Response: " + answer + ".";
                } 
                else {
                    errmsg += "Scanner did not respond.";
                }
                logDebug("%s", errmsg.c_str());
            } 
            else {
                /* parse answer from server */
                logDebug("%s", answer.c_str());
                if (answer == "OK") {
                    errmsg = "Clean";
                    scanningResult = AVCHK_OK;
                }
                else if (!answer.empty()) {
                    string::size_type lastWord = answer.rfind(" "); // for example: "INSTREAM size limit exceeded. ERROR"
                    if (lastWord != string::npos) {
                        string msgType = answer.substr(lastWord + 1);
                        answer.erase(answer.begin() + lastWord, answer.end());
                        if (msgType == "FOUND") {
                            errmsg = answer;

                            /* check for special answers from server that indicates impossible file check */
                            if ((0 == errmsg.compare(0, sizeof(encryptedMsg) - 1, encryptedMsg)) ||
                                    (0 == errmsg.compare(0, sizeof(brokenMsg) - 1, brokenMsg)) ||
                                    (0 == errmsg.compare(0, sizeof(heuristicsEncryptedMsg) - 1, heuristicsEncryptedMsg))) {
                                scanningResult = AVCHK_IMPOSSIBLE;
                            } 
                            else {
                                scanningResult = AVCHK_VIRUS_FOUND;
                            }
                        } 
                        else {
                            /* msgType contains ERROR or anything else */
                            scanningResult = AVCHK_FAILED;
                            errmsg = "Scanning failed - ClamAV Server returns error: " + answer;
                        }
                    }
                }
            }
        }
    }

    if (scanningResult != AVCHK_OK) {
        logDebug("File scanning result: %s", errmsg.c_str());
    } 
    else {
        logDebug("File scanning finished successfully");
    }

    strncpys(vir_info, errmsg.c_str(), vi_size);

    atomicDec(&this->runningThreads);
    return scanningResult;
}

void ClamPlugin::startConnectionRefresh(SyncStreamPtr &conn)
{
    if (conn) {
        MutexType::scoped_lock lock(this->connMutex);
        this->connVector.push_back(conn);
    }
}

void ClamPlugin::dropConnectionRefresh(SyncStreamPtr &conn)
{
    if (conn) {
        MutexType::scoped_lock lock(this->connMutex);
        for (ThreadStreams::iterator i = this->connVector.begin(); i != this->connVector.end(); ++i) {
            if (*i == conn) {
                this->connVector.erase(i);
                break;
            }
        }
    }
}

void ClamPlugin::keepAliveThreadWrapper(void *params)
{
    if (params) {
        ClamPlugin *th = (ClamPlugin *) params;
        th->keepAliveThread();
    }
}

void ClamPlugin::keepAliveThread()
{
    unsigned int timeout = KEEPALIVE_TIMEOUT;
    std::string error;

    while (!closing) {
        timeout--;
        boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
        if (0 == timeout) {
            MutexType::scoped_lock lock(this->connMutex);

            if (this->connVector.empty()) {
                continue;
            }
            /* timeout has occurred */
            for (ThreadStreams::iterator i = this->connVector.begin(); i != this->connVector.end(); ++i) {
                (void) (*i)->sendPingPong(error);
            }            
            timeout = KEEPALIVE_TIMEOUT;
        }
    }
}

bool ClamPlugin::SyncStream::startSession()
{
    MutexType::scoped_lock lock(*mutex.get());

    logDebug("Sending SESSION command...");
    return sendString("IDSESSION");
}

bool ClamPlugin::SyncStream::getVersion(std::string &version)
{
    MutexType::scoped_lock lock(*mutex.get());

    logDebug("Sending VERSION command...");
    if (!sendString("VERSION")) {
        logWarning("Cannot send VERSION command to the ClamAV Server");
        version = "unknown";
        return true;
    }
    if (!readString(version)) {
        logDebug("Cannot read response from ClamAV Server session, error: %s", version.c_str());
        return false;
    }

    return true;
}

bool ClamPlugin::SyncStream::endSession()
{
    MutexType::scoped_lock lock(*mutex.get());

    logDebug("Sending END command...");
    return sendString("END");
}

bool ClamPlugin::SyncStream::sendPingPong(std::string &error)
{
    MutexType::scoped_try_lock lock(*mutex.get());
    if (!lock) {
        logDebug("Ping pong not needed");
        return true; // no ping pong needed, stream is being used right now (aquired by testFile call)
    }

    string answer;
    bool result = false;

    if (stream == NULL) {
        error = "Stream is empty.";
        logError("%s", error.c_str());
        return false;
    }

    logDebug("Sending PING command...");
    result = sendString("PING");
    if (!result) {
        logWarning("Cannot send PING command");
        return false;
    }

    if (!readString(answer)) {
        error = "Cannot read response from ClamAV Server session.";
        logError("%s", error.c_str());
        return false;
    }
    if (answer != "PONG") {
        error = "An incorrect answer has been received from ClamAV Server '" + answer + "'.";
        logError("%s", error.c_str());
        return false;
    }
    return true;
}
