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
using MsgQueue = std::queue<std::unique_ptr<LogMessage>,
                            std::vector<std::unique_ptr<LogMessage>>>;

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

    bool operator==(const SyncEntry &se) {
        return this->m_sync->id() == se.m_sync->id();
    }
};

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

    static Logger & instance() {
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
                    std::lock_guard lock(m_mutex);
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
    std::vector<SyncEntry> m_syncs;
    Formatter m_formatter;
    std::mutex m_mutex;
    MsgQueue m_queue;
    bool m_running;
    static std::unique_ptr<Logger> s_instance;
};


#ifdef V_LOGGER_IMPL
    const Logger* Logger::s_insance = nullptr;
#endif
