#pragma once

#include <fstream>
#include <functional>
#include <unordered_map>
#include <memory>
#include <algorithm>
#include <thread>
#include <mutex>
#include <vector>
#include <queue>
#include <iostream>
#include <sstream>

#if defined _WIN32
    #define V_WINDOWS
    #define V_WIN_32
#elif defined _WIN64
    #define V_WINDOWS
    #define V_WIN_64
#elif defined __linux
    #define V_LINUX
    #define V_POSIX
#elif defined __APPLE__
    #define V_MAC_OS
    #define V_POSIX
#endif

namespace DVoid { //dense_void!

struct LogMessage;
using Filter = std::function<bool(LogMessage &)>;
using Formatter = std::function<std::string(LogMessage &)>;
using MsgQueue = std::queue<std::unique_ptr<LogMessage>,
                            std::vector<std::unique_ptr<LogMessage>>>;

std::string format(const LogMessage &msg) {
    return "";
}

//############### <Severity> ####################
enum class Severity {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Special
};
inline const std::string & toString(Severity sev) {
    static const std::string TRACE("[ TRACE ]");
    static const std::string DEBUG("[ DEBUG ]");
    static const std::string INFO("[ INFO  ]");
    static const std::string WARN("[ WARNG ]");
    static const std::string ERROR("[ ERROR ]");
    static const std::string SPECIAL("[ ***** ]");
    switch(sev) {
        case Severity::Trace  : return TRACE;
        case Severity::Debug  : return DEBUG;
        case Severity::Info   : return INFO;
        case Severity::Warn   : return WARN;
        case Severity::Error  : return ERROR;
        case Severity::Special: return SPECIAL;
    }
    return SPECIAL;
}
std::ostream & operator << (std::ostream &stream, Severity severity) {
    stream << toString(severity);
    return stream;
}
//############### </Severity> ####################


//############### <LogMessage> ####################
struct LogMessage {
    time_t m_time;
    Severity m_severity;
    std::thread::id m_threadID;
    int m_line;
    std::string m_module;
    std::string m_method;
    std::string m_file;
    std::string m_logMsg;
};
//############### </LogMessage> ####################



//############### <AbstractSync> ####################
class AbstractSync {
public:
    explicit AbstractSync(const std::string &id) : m_id(id) { }

    const std::string & id() const { return m_id; }

    virtual void write(const LogMessage &msg, const std::string &formated) = 0;

    virtual ~AbstractSync();

private:
    std::string m_id;
};
AbstractSync::~AbstractSync() { }
//############### </AbstractSync> ####################


//############### <SyncEntry> ####################
struct SyncEntry {
    Filter m_filter;
    bool m_enabled;
    std::unique_ptr<AbstractSync> m_sync;

    bool operator==(const SyncEntry &se) {
        return this->m_sync->id() == se.m_sync->id();
    }
};
//############### </SyncEntry> ####################

//############### <Logger> ####################
class Logger {
private:
    auto findEntry(const std::string &id) {
        auto it = std::find_if(std::begin(m_syncs),
                               std::end(m_syncs),
                               [&id](const SyncEntry &se) -> bool {
            return id == se.m_sync->id();
        });
        if (it != std::end(m_syncs)) {
            return it;
        }
        return std::end(m_syncs);
    }

    auto findEntry(const std::string &id) const {
        auto it = std::find_if(std::begin(m_syncs),
                               std::end(m_syncs),
                               [&id](const SyncEntry &se) -> bool {
            return id == se.m_sync->id();
        });
        if (it != std::end(m_syncs)) {
            return it;
        }
        return std::end(m_syncs);
    }

public:
    enum class Type {
        Direct,
        Async,
    };

    static void init(Type type) {
        if (!static_cast<bool>(s_instance)) {
            s_instance = std::make_unique<Logger>(type);
        }
    }

    static Logger & get() {
        if (!static_cast<bool>(s_instance)) {
            s_instance = std::make_unique<Logger>(Type::Direct);
        }
        return *s_instance.get();
    }

    void addSync(std::unique_ptr<AbstractSync> sync) {
        auto it = std::find_if(std::begin(m_syncs),
                               std::end(m_syncs),
                               [&sync](const SyncEntry &se) -> bool {
            return sync->id() == se.m_sync->id();
        });
        if (it == std::end(m_syncs)) {
            m_syncs.push_back({nullptr, true, std::move(sync)});
        } else {
            //replace if already exists
            *it = {nullptr, true, std::move(sync)};
        }
    }

    void removeSync(std::string &id) {
        m_syncs.erase(std::remove(std::begin(m_syncs), std::end(m_syncs), id),
                      std::end(m_syncs));
    }

    void write(std::unique_ptr<LogMessage> msg) {
        if (m_type == Type::Async && m_running) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_queue.push(std::move(msg));
        } else {

        }
    }

    void dispatch() {
        while (true) {
            bool empty = false;
            std::unique_ptr<LogMessage> msg;
            {
                empty = m_queue.empty();
                if (!empty) {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    msg = std::move(m_queue.back());
                    m_queue.pop();
                    empty = m_queue.empty();
                }
            }
            if (msg) {
                for (const auto &se : m_syncs) {
                    if (se.m_enabled && (se.m_filter && se.m_filter(*msg))) {
                        auto mstr = m_formatter ? m_formatter(*msg)
                                                : format(*msg);
                        se.m_sync->write(*msg, mstr);
                    }
                }
            }
            if (empty) {
                //stop dispatching only after all messages are written
                if (!m_running) {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
        }
    }

    const AbstractSync * sync(const std::string &id) const {
        auto entry = this->findEntry(id);
        if (entry != std::end(m_syncs)) {
            return entry->m_sync.get();
        }
        return nullptr;
    }

    bool addFilter(const std::string &id, Filter filter) {
        auto it = this->findEntry(id);
        if (it != std::end(m_syncs)) {
            it->m_filter = filter;
            return true;
        }
        return false;
    }

    bool removeFilter(const std::string &id) {
        return addFilter(id, nullptr);
    }

    void setSeverityLevel(Severity sev) {
        m_severity = sev;
    }

    Severity severityLevel() const {
        return  m_severity;
    }


private:
    void writeDirect(LogMessage &msg) {
        for (const auto &se : m_syncs) {
            if (se.m_enabled && (se.m_filter && se.m_filter(msg))) {
                auto mstr = m_formatter ? m_formatter(msg) : format(msg);
                se.m_sync->write(msg, mstr);
            }
        }
    }

    explicit Logger(Type type): m_type(type) {}
    ~Logger() { }

private:
    Type m_type;

    Severity m_severity;

    std::vector<SyncEntry> m_syncs;

    Formatter m_formatter;

    std::mutex m_mutex;

    MsgQueue m_queue;

    bool m_running;

    static std::unique_ptr<Logger> s_instance;
};
//############### </Logger> ####################


//############### <ConsoleSync> ####################
class ConsoleSync : public AbstractSync {
public:
    ConsoleSync() : AbstractSync("inbuilt.console") {}

public: // for AbstractSync
    void write(const LogMessage &msg, const std::string &formated);
};

void ConsoleSync::write(const LogMessage &msg, const std::string &formated) {
    if (msg.m_severity >= Severity::Warn) {
        std::cerr << formated << '\n';
    } else {
        std::cout << formated << '\n';
    }
}
//############### </ConsoleSync> ####################


//############### <FileSync> ####################
class FileSync : public AbstractSync {
public:
    explicit FileSync(
            const std::string &logDirPath,
            const std::string &fileNamePrefix)
        : AbstractSync("inbuilt.file")
        , m_fileNamePrefix(fileNamePrefix)
        , m_logDir(logDirPath)
        , m_valid(false){ }

public: // for AbstractSync
    void write(const LogMessage &msg, const std::string &formated);

private:
    std::string m_fileNamePrefix;

    std::string m_logDir;

    std::ofstream m_stream;

    bool m_valid;
};

void FileSync::write(const LogMessage &/*msg*/,
                     const std::string &formated) {
    if (!m_valid) {
        auto fpath = m_logDir + "/" + m_fileNamePrefix + ".log";
        m_stream = std::ofstream(fpath);
    }
    m_stream << formated << '\n';
}
//############### </FileSync> ####################



class LogLineHolder
{
public:
    typedef std::ostream & ( Manip )( std::ostream & );

    LogLineHolder( Logger *logger, LogMessage *msg )
        : m_msg( msg )
        , m_logger( logger )
        , m_level( Logger::get().severityLevel() )
    {

    }

    template< typename T >
    LogLineHolder & operator<<( const T &obj )
    {
        if( m_msg->m_severity >= m_level ) {
            m_stream << obj;
        }
        return *this;
    }

    template< typename T >
    LogLineHolder & operator<<( T &&obj )
    {
        if( m_msg->m_severity >= m_level ) {
            m_stream << obj;
        }
        return *this;
    }

    LogLineHolder & operator << ( Manip &manip )
    {
        if( m_msg->m_severity >= m_level ) {
            m_stream << manip;
        }
        return *this;
    }

    ~LogLineHolder()
    {
        if( m_msg->m_severity >= m_level ) {
            m_stream.flush();
            if( m_logger != nullptr ) {
                m_msg->m_logMsg = m_stream.str(); //copy ellided
                m_logger->write( std::move(m_msg));
            }
        }
    }

private:
    std::unique_ptr<LogMessage> m_msg;

    Logger *m_logger;

    std::ostringstream m_stream;

    Severity m_level;
};

}



#define DV_LOGGER() DVoid::Logger::get()

#ifndef __FUNCTION_NAME__
    #ifdef _MSC_VER //VC++
        #define FUNCTION_NAME  __FUNCSIG__
    #else          //Other
        #define FUNCTION_NAME   __PRETTY_FUNCTION__
    #endif
#endif


//time_t m_time;
//Severity m_severity;
//std::thread::id m_threadID;
//int m_line;
//std::string m_module;
//std::string m_method;
//std::string m_file;
//std::string m_logMsg;

#ifndef DV_DISABLE_DEFAULT_LOGGING
        #define DV_COMMON( level, mod )                                       \
            Quartz::Logger::LogLineHolder(                                    \
                DVoid::Logger::::get(),                                       \
                    new DVoid::LogMessage{            \
                        std::time(0),                 \
                        level,                        \
                        std::this_thread::get_id(),   \
                        __LINE__,                     \
                        mod,                          \
                        FUNCTION_NAME,                \
                        __FILE__                      \
                    }
        #define DV_TRACE( module ) \
            DV_COMMON( DVoid::Severity::Trace, module )

        #define DV_DEBUG( module ) \
            DV_COMMON( DVoid::Severity::Debug, module )

        #define DV_INFO( module ) \
            DV_COMMON( DVoid::Severity::Info, module )

        #define DV_WARN( module ) \
            DV_COMMON( DVoid::Severity::Warn, module )

        #define DV_ERROR( module ) \
            DV_COMMON( DVoid::Severity::Error, module )

        #define DV_SPECIAL( module ) \
            DV_COMMON( DVoid::Severity::Special, module )
#else
    #define DV_COMMON( level, mod, message )
    #define DV_TRACE( module )
    #define DV_DEBUG( module )
    #define DV_INFO( module )
    #define DV_WARN( module )
    #define DV_ERROR( module )
    #define DV_SPECIAL( module )
#endif


#ifdef DV_LOGGER_IMPL
    const DVoid::Logger* DVoid::Logger::s_insance = nullptr;
#endif
