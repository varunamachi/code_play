#pragma once

#include <functional>
#include <unordered_map>
#include <memory>
#include <algorithm>
#include <thread>
#include <mutex>
#include <vector>
#include <queue>

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

struct LogMessage;
using Filter = std::function<bool(LogMessage &)>;
using Formatter = std::function<std::string(LogMessage &)>;

std::string format(const LogMessage &msg) {
    return "";
}

enum class Severity {

};

struct LogMessage {

};

class AbstractSync {
public:
    explicit AbstractSync(const std::string &id) : m_id(id) { }

    virtual void write(const LogMessage &msg, const std::string &formated) = 0;

    const std::string & id() const { return m_id; }

    virtual ~AbstractSync();

private:
    std::string m_id;
};
AbstractSync::~AbstractSync() { }

struct SyncEntry {
    Filter m_filter;
    bool m_enabled;
    std::unique_ptr<AbstractSync> m_sync;
};

class Logger {
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

    static Logger & instance() {
        if (!static_cast<bool>(s_instance)) {
            s_instance = std::make_unique<Logger>(Type::Direct);
        }
        return *s_instance.get();
    }

    void addSync(std::unique_ptr<AbstractSync> sync) {
        if (sync) {
            m_syncs[sync->id()] = SyncEntry{ nullptr, true, std::move(sync)};
        }
    }

    void removeSync(std::string &id) {
        m_syncs.erase(std::remove(std::begin(m_syncs), std::end(m_syncs), id),
                      std::end(m_syncs));
    }

    void write(std::unique_ptr<LogMessage> msg) {
        if (m_type == Type::Async) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_queue.push(std::move(msg));
        } else {
            for (const auto &pair : m_syncs) {
                const auto &se = pair.second;
                if (se.m_enabled && (se.m_filter && se.m_filter(*msg))) {
                    auto mstr = m_formatter ? m_formatter(*msg) : format(*msg);
                    se.m_sync->write(*msg, mstr);
                }
            }
        }
    }

private:
    explicit Logger(Type type): m_type(type) {}
    ~Logger() { }

private:
    Type m_type;
    std::unordered_map<std::string, SyncEntry> m_syncs;
    Formatter m_formatter;
    std::mutex m_mutex;
    std::queue<std::unique_ptr<LogMessage>,
               std::vector<std::unique_ptr<LogMessage>>> m_queue;

    static std::unique_ptr<Logger> s_instance;

};


#ifdef V_LOGGER_IMPL
    const Logger* Logger::s_insance = nullptr;
#endif
