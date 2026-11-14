#include "driverless/audit_etw.h"
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <tlhelp32.h>
#include <QtCore/QByteArray>
#include <QtCore/QDateTime>
#include <QtCore/QJsonDocument>
#include <QtCore/QUuid>
#include <QtCore/QTimeZone>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <mutex>
#include <queue>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace nb {
namespace {
constexpr GUID WmiGuid{0x1418ef04, 0xb0b4, 0x4623, {0xbf, 0x7e, 0xd7, 0x4a, 0xb4, 0x7b, 0xbd, 0xaa}};
constexpr GUID FileGuid{0xedd08927, 0x9cc4, 0x4e65, {0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89}};
constexpr GUID RegistryGuid{0x70eb4f03, 0xc1de, 0x4f73, {0xa0, 0x51, 0x33, 0xd1, 0x3d, 0x54, 0x13, 0xbd}};
constexpr GUID NetworkGuid{0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};
constexpr GUID ProcessGuid{0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};
constexpr GUID PerfGuid{0xce1dbfb4, 0x137e, 0x4da6, {0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc}};
constexpr GUID ThreadGuid{0x3d6fa8d1, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
constexpr GUID LostGuid{0x6a399ae0, 0x4bc6, 0x4de9, {0x87, 0x0b, 0x36, 0x57, 0xf8, 0x94, 0x7e, 0x7e}};
constexpr quint64 QueueBudget = 128 * 1024 * 1024;
constexpr size_t QueueRecords = 262144;
struct OwnedHandle {
    HANDLE value = nullptr;
    OwnedHandle() = default;
    explicit OwnedHandle(HANDLE handle) : value(handle) {}
    ~OwnedHandle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    OwnedHandle(const OwnedHandle &) = delete;
    OwnedHandle &operator=(const OwnedHandle &) = delete;
};
quint64 fileTime(const FILETIME &time) { return (quint64(time.dwHighDateTime) << 32) | time.dwLowDateTime; }
quint64 clockTime() {
    FILETIME time{};
    GetSystemTimePreciseAsFileTime(&time);
    return fileTime(time);
}
QString guidText(const GUID &guid) {
    return QString::asprintf("{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}", guid.Data1,
                             guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2],
                             guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
}
GUID randomGuid() {
    const auto value = QUuid::createUuid();
    GUID result{value.data1, value.data2, value.data3, {}};
    std::copy(std::begin(value.data4), std::end(value.data4), result.Data4);
    return result;
}
bool guidEqual(const GUID &left, const GUID &right) { return std::memcmp(&left, &right, sizeof(GUID)) == 0; }
quint64 number(const QJsonValue &value) {
    if (value.isDouble()) return quint64(value.toInteger());
    auto text = value.toString();
    return text.startsWith("0x", Qt::CaseInsensitive) ? text.mid(2).toULongLong(nullptr, 16)
                                                     : text.toULongLong();
}
quint64 propertyNumber(const QJsonObject &properties, std::initializer_list<const char *> names) {
    for (auto name : names) {
        for (auto it = properties.begin(); it != properties.end(); ++it)
            if (it.key().compare(QLatin1String(name), Qt::CaseInsensitive) == 0) return number(it.value());
    }
    return 0;
}
QString propertyText(const QJsonObject &properties, std::initializer_list<const char *> names) {
    for (auto name : names) {
        for (auto it = properties.begin(); it != properties.end(); ++it)
            if (it.key().compare(QLatin1String(name), Qt::CaseInsensitive) == 0 && it.value().isString())
                return it.value().toString();
    }
    return {};
}
QString informationString(const std::vector<BYTE> &bytes, ULONG offset) {
    if (!offset || offset >= bytes.size() || offset % sizeof(wchar_t)) return {};
    const auto text = reinterpret_cast<const wchar_t *>(bytes.data() + offset);
    size_t maximum = (bytes.size() - offset) / sizeof(wchar_t);
    size_t count = 0;
    while (count < maximum && text[count]) ++count;
    return count < maximum ? QString::fromWCharArray(text, qsizetype(count)) : QString();
}
QJsonValue decodeValue(const QByteArray &bytes, USHORT type) {
    auto integer = [&](size_t width) -> quint64 {
        quint64 value = 0;
        if (bytes.size() >= qsizetype(width)) std::memcpy(&value, bytes.constData(), width);
        return value;
    };
    switch (type) {
    case TDH_INTYPE_UNICODESTRING:
    case TDH_INTYPE_COUNTEDSTRING:
    case TDH_INTYPE_NONNULLTERMINATEDSTRING: {
        qsizetype count = bytes.size() / sizeof(wchar_t);
        const auto text = reinterpret_cast<const wchar_t *>(bytes.constData());
        qsizetype actual = 0;
        while (actual < count && text[actual]) ++actual;
        return QString::fromWCharArray(text, actual);
    }
    case TDH_INTYPE_ANSISTRING:
    case TDH_INTYPE_COUNTEDANSISTRING:
    case TDH_INTYPE_NONNULLTERMINATEDANSISTRING: {
        auto nul = bytes.indexOf('\0');
        return QString::fromLocal8Bit(nul >= 0 ? bytes.first(nul) : bytes);
    }
    case TDH_INTYPE_UINT8: return int(integer(1));
    case TDH_INTYPE_INT8: return int(qint8(integer(1)));
    case TDH_INTYPE_UINT16: return int(integer(2));
    case TDH_INTYPE_INT16: return int(qint16(integer(2)));
    case TDH_INTYPE_UINT32: return qint64(integer(4));
    case TDH_INTYPE_INT32: return qint64(qint32(integer(4)));
    case TDH_INTYPE_BOOLEAN: return integer(4) != 0;
    case TDH_INTYPE_INT64: return QString::number(qint64(integer(8)));
    case TDH_INTYPE_UINT64:
    case TDH_INTYPE_FILETIME: return QString::number(integer(8));
    case TDH_INTYPE_POINTER:
    case TDH_INTYPE_SIZET:
    case TDH_INTYPE_HEXINT32:
    case TDH_INTYPE_HEXINT64: return "0x" + QString::number(integer(size_t(std::min<qsizetype>(8, bytes.size()))), 16);
    case TDH_INTYPE_GUID: {
        GUID value{};
        if (bytes.size() == sizeof(value)) { std::memcpy(&value, bytes.constData(), sizeof(value)); return guidText(value); }
        break;
    }
    case TDH_INTYPE_FLOAT: {
        float value = 0;
        if (bytes.size() == sizeof(value)) { std::memcpy(&value, bytes.constData(), sizeof(value)); return double(value); }
        break;
    }
    case TDH_INTYPE_DOUBLE: {
        double value = 0;
        if (bytes.size() == sizeof(value)) { std::memcpy(&value, bytes.constData(), sizeof(value)); return value; }
        break;
    }
    default: break;
    }
    return QJsonObject{{"encoding", "base64"}, {"data", QString::fromLatin1(bytes.toBase64())}};
}
bool enablePrivilege(const wchar_t *name) {
    OwnedHandle token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token.value)) return false;
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(nullptr, name, &privileges.Privileges[0].Luid)) return false;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    return AdjustTokenPrivileges(token.value, FALSE, &privileges, 0, nullptr, nullptr) && GetLastError() == ERROR_SUCCESS;
}
}

struct AuditEtw::Impl {
    struct Target {
        quint32 pid = 0;
        quint64 creation = 0, end = 0, verifiedThrough = 0;
        QString sandbox, run;
        std::shared_ptr<OwnedHandle> process, job;
        bool retired = false, root = false;
        quint64 processSequence = 0;
        QString admissionProof = "live_process_creation_and_job_membership";
    };
    struct ThreadOwner {
        quint32 pid;
        quint64 creation, begin, end = 0;
        std::shared_ptr<OwnedHandle> thread;
        quint64 threadCreation = 0;
        bool lifecycleStart = false, lifecycleEnd = false;
        quint64 verifiedThrough = 0, queryAttempt = 0;
    };
    struct ProcessHistory {
        quint32 pid = 0, parent = 0;
        quint64 creation = 0, exit = 0, sequence = 0, parentSequence = 0, eventTime = 0;
    };
    struct PendingCall {
        quint64 time = 0, value = 0;
        quint32 tid = 0, processor = 0;
        USHORT opcode = 0, flags = 0;
        quint64 serial = 0;
    };
    struct PendingFront {
        quint64 time, serial;
        quint32 tid;
        bool operator>(const PendingFront &other) const {
            return time > other.time || (time == other.time && serial > other.serial);
        }
    };
    struct NegativeProcess {
        quint64 checked = 0, creation = 0, end = 0;
        bool provedForeign = false;
    };
    struct CpuThread { quint32 tid = 0; quint64 begin = 0; };
    struct PendingEvent {
        EVENT_HEADER header{};
        ETW_BUFFER_CONTEXT buffer{};
        QByteArray payload;
        quint32 pid = 0;
        quint64 creation = 0;
    };
    struct Queued { QJsonObject record; quint64 bytes; };
    struct Session {
        Impl *owner = nullptr;
        QString name;
        std::wstring nativeName;
        TRACEHANDLE controller = 0, consumer = INVALID_PROCESSTRACE_HANDLE;
        std::thread worker;
        std::vector<BYTE> properties;
        bool kernel = false;
        std::atomic<bool> finished{false};
        std::atomic<ULONG> processResult{ERROR_SUCCESS};
        ULONG startResult = ERROR_SUCCESS, openResult = ERROR_SUCCESS;
        ULONG eventsLost = 0, buffersLost = 0, buffersWritten = 0;
        ULONG queryResult = ERROR_NOT_READY;
        quint64 lastQuery = 0;
        bool cancelledTail = false;
        EVENT_TRACE_PROPERTIES *config() { return reinterpret_cast<EVENT_TRACE_PROPERTIES *>(properties.data()); }
    };
    struct Provider { GUID guid; const char *name, *category; ULONG result = ERROR_NOT_READY; quint64 observed = 0; };
    bool requestedSyscalls, started = false, profilePrivilege = false, debugPrivilege = false;
    std::map<quint64, QString> syscallNames;
    std::mutex control, data;
    std::vector<std::unique_ptr<Session>> sessions;
    std::array<Provider, 5> providers{{{WmiGuid, "Microsoft-Windows-WMI-Activity", "wmi"},
                                    {FileGuid, "Microsoft-Windows-Kernel-File", "file"},
                                    {RegistryGuid, "Microsoft-Windows-Kernel-Registry", "registry"},
                                    {NetworkGuid, "Microsoft-Windows-Kernel-Network", "network"},
                                    {ProcessGuid, "Microsoft-Windows-Kernel-Process", "process"}}};
    std::unordered_map<quint32, std::vector<std::shared_ptr<Target>>> targets;
    std::unordered_map<quint32, std::vector<ThreadOwner>> threads;
    std::unordered_map<ULONG, std::deque<CpuThread>> cpuThreads;
    std::unordered_map<quint32, std::unordered_set<quint32>> processThreads;
    std::unordered_map<quint64, ProcessHistory> processHistory;
    std::unordered_map<quint32, std::deque<PendingCall>> pendingCalls;
    std::priority_queue<PendingFront, std::vector<PendingFront>, std::greater<PendingFront>> pendingFronts;
    size_t pendingCallCount = 0;
    quint64 pendingCallSerial = 0;
    std::deque<PendingEvent> pendingEvents;
    std::unordered_set<quint32> observerThreads;
    std::unordered_map<quint32, NegativeProcess> negativePids;
    std::unordered_map<quint32, quint64> unresolvedThreads;
    std::unordered_map<quint64, QString> fileNames;
    struct RegistryName { QString name; quint64 observed = 0; };
    std::unordered_map<QString, RegistryName> registryNames;
    std::unordered_map<QString, std::shared_ptr<std::vector<BYTE>>> schemas;
    std::unordered_map<QString, std::weak_ptr<Target>> wmiOperations;
    std::deque<Queued> queue;
    quint64 queuedBytes = 0, sequence = 0, accepted = 0, ignored = 0, ambiguous = 0;
    quint64 queueDropped = 0, decodeErrors = 0, callbackErrors = 0, syscallEvents = 0, unwatchDiscarded = 0;
    quint64 pendingCallEvicted = 0, pendingEventBytes = 0, pendingEventDropped = 0, historicalChildren = 0;
    quint64 contextSwitches = 0, cpuOrderAmbiguous = 0, replayedCalls = 0, latestEventTime = 0;
    quint64 foreignCallsDiscarded = 0, pendingCallHighWater = 0;
    quint64 lostEventNotifications = 0, lostBufferNotifications = 0, lostFileNotifications = 0;
    quint64 cpuContextResets = 0;
    quint64 lastPrune = 0;

    explicit Impl(bool syscalls) : requestedSyscalls(syscalls) { observerThreads.insert(GetCurrentThreadId()); }
    void captureThread(ThreadOwner &owner, quint32 tid, quint64 eventTime) {
        auto handle = std::make_shared<OwnedHandle>(OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                                              FALSE, tid));
        if (!handle->value || GetProcessIdOfThread(handle->value) != owner.pid) return;
        FILETIME creation{}, exit{}, kernel{}, user{};
        const auto checked = clockTime();
        if (!GetThreadTimes(handle->value, &creation, &exit, &kernel, &user)) return;
        const auto created = fileTime(creation);
        if (created > eventTime || created < owner.creation) return;
        owner.thread = std::move(handle);
        owner.threadCreation = created;
        owner.begin = created;
        owner.verifiedThrough = checked;
        if (fileTime(exit)) owner.end = fileTime(exit);
    }
    bool threadMatches(ThreadOwner &owner, quint32 tid, quint64 time) {
        if (!owner.thread) captureThread(owner, tid, time);
        if (!owner.thread) return owner.lifecycleStart && owner.lifecycleEnd &&
                                  time >= owner.begin && time <= owner.end;
        if (time >= owner.threadCreation && time <= owner.verifiedThrough)
            return !owner.end || time <= owner.end;
        FILETIME creation{}, exit{}, kernel{}, user{};
        const auto checked = clockTime();
        if (!GetThreadTimes(owner.thread->value, &creation, &exit, &kernel, &user) ||
            fileTime(creation) != owner.threadCreation || time < owner.threadCreation) return false;
        const auto ended = fileTime(exit);
        owner.verifiedThrough = checked;
        if (ended) owner.end = owner.end ? std::min(owner.end, ended) : ended;
        return !owner.end || time <= owner.end;
    }
    void loadSyscallNames() {
        // Use only the kernel image already installed by Windows. No symbol download, code execution,
        // kernel memory read, or approximate nearest-symbol association is needed.
        using Enumerate = BOOL(WINAPI *)(LPVOID *, DWORD, LPDWORD);
        using BaseName = DWORD(WINAPI *)(LPVOID, LPWSTR, DWORD);
        const auto kernel32 = GetModuleHandleW(L"kernel32.dll");
        const auto enumerate = reinterpret_cast<Enumerate>(GetProcAddress(kernel32, "K32EnumDeviceDrivers"));
        const auto basename = reinterpret_cast<BaseName>(GetProcAddress(kernel32, "K32GetDeviceDriverBaseNameW"));
        if (!enumerate || !basename) return;
        std::array<LPVOID, 2048> drivers{};
        DWORD needed = 0;
        if (!enumerate(drivers.data(), DWORD(sizeof(drivers)), &needed) || needed > sizeof(drivers)) return;
        quint64 kernelBase = 0;
        for (size_t index = 0; index < needed / sizeof(LPVOID); ++index) {
            wchar_t name[256]{};
            if (drivers[index] && basename(drivers[index], name, DWORD(std::size(name))) &&
                _wcsicmp(name, L"ntoskrnl.exe") == 0) { kernelBase = quint64(drivers[index]); break; }
        }
        if (!kernelBase) return;
        wchar_t windows[32768]{};
        auto length = GetWindowsDirectoryW(windows, DWORD(std::size(windows)));
        if (!length || length >= std::size(windows)) return;
        auto path = std::wstring(windows, length) + L"\\System32\\ntoskrnl.exe";
        OwnedHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (file.value == INVALID_HANDLE_VALUE) return;
        OwnedHandle mapping(CreateFileMappingW(file.value, nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr));
        if (!mapping.value) return;
        const auto image = static_cast<const BYTE *>(MapViewOfFile(mapping.value, FILE_MAP_READ, 0, 0, 0));
        if (!image) return;
        struct View { const void *value; ~View() { UnmapViewOfFile(value); } } release{image};
        const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(image);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || dos->e_lfanew > 1024 * 1024) return;
        const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(image + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return;
        const auto size = nt->OptionalHeader.SizeOfImage;
        if (size < 4096 || size > 256 * 1024 * 1024) return;
        auto valid = [&](DWORD offset, quint64 bytes) { return offset < size && bytes <= quint64(size - offset); };
        const auto directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!valid(directory.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY))) return;
        const auto exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(image + directory.VirtualAddress);
        if (exports->NumberOfNames > 100000 || exports->NumberOfFunctions > 100000 ||
            !valid(exports->AddressOfNames, quint64(exports->NumberOfNames) * sizeof(DWORD)) ||
            !valid(exports->AddressOfNameOrdinals, quint64(exports->NumberOfNames) * sizeof(WORD)) ||
            !valid(exports->AddressOfFunctions, quint64(exports->NumberOfFunctions) * sizeof(DWORD))) return;
        const auto names = reinterpret_cast<const DWORD *>(image + exports->AddressOfNames);
        const auto ordinals = reinterpret_cast<const WORD *>(image + exports->AddressOfNameOrdinals);
        const auto functions = reinterpret_cast<const DWORD *>(image + exports->AddressOfFunctions);
        for (DWORD index = 0; index < exports->NumberOfNames; ++index) {
            if (ordinals[index] >= exports->NumberOfFunctions || !valid(names[index], 3)) continue;
            const auto name = reinterpret_cast<const char *>(image + names[index]);
            if (!((name[0] == 'N' && name[1] == 't') || (name[0] == 'Z' && name[1] == 'w'))) continue;
            size_t count = 0;
            const auto maximum = std::min<DWORD>(256, size - names[index]);
            while (count < maximum && name[count]) ++count;
            const auto rva = functions[ordinals[index]];
            if (!count || count == maximum || !valid(rva, 1) ||
                (rva >= directory.VirtualAddress && quint64(rva) < quint64(directory.VirtualAddress) + directory.Size)) continue;
            auto current = syscallNames.find(kernelBase + rva);
            if (current == syscallNames.end() || name[0] == 'N')
                syscallNames[kernelBase + rva] = QString::fromLatin1(name, qsizetype(count));
        }
    }
    static void WINAPI receive(EVENT_RECORD *event) noexcept {
        auto session = static_cast<Session *>(event->UserContext);
        if (!session || !session->owner) return;
        try {
            if (guidEqual(event->EventHeader.ProviderId, LostGuid)) {
                std::lock_guard lock(session->owner->data);
                const auto opcode = event->EventHeader.EventDescriptor.Opcode;
                if (opcode == 32) ++session->owner->lostEventNotifications;
                else if (opcode == 33) ++session->owner->lostBufferNotifications;
                else if (opcode == 34) ++session->owner->lostFileNotifications;
                else return;
                session->owner->traceGap(*session, "realtime_loss_notification", opcode);
            } else session->owner->event(*event, session->kernel);
        }
        catch (...) { std::lock_guard lock(session->owner->data); ++session->owner->callbackErrors; }
    }
    std::unique_ptr<Session> createSession(bool kernel) {
        auto session = std::make_unique<Session>();
        session->owner = this;
        session->kernel = kernel;
        auto uuid = QUuid::createUuid().toString(QUuid::WithoutBraces);
        session->name = QString(kernel ? "NativeBox.Syscalls." : "NativeBox.Activity.") + uuid;
        session->nativeName = session->name.toStdWString();
        session->properties.resize(sizeof(EVENT_TRACE_PROPERTIES) + (session->nativeName.size() + 1) * sizeof(wchar_t));
        auto config = session->config();
        config->Wnode.BufferSize = ULONG(session->properties.size());
        config->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        config->Wnode.ClientContext = 1; // QPC; ProcessTrace converts timestamps to FILETIME for consumers.
        config->Wnode.Guid = randomGuid();
        config->BufferSize = kernel ? 256 : 128;
        config->MinimumBuffers = kernel ? 32 : 16;
        config->MaximumBuffers = kernel ? 128 : 64;
        config->FlushTimer = 1;
        config->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | (kernel ? EVENT_TRACE_SYSTEM_LOGGER_MODE : 0);
        config->EnableFlags = kernel ? EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD | EVENT_TRACE_FLAG_CSWITCH |
                                          EVENT_TRACE_FLAG_SYSTEMCALL | EVENT_TRACE_FLAG_NO_SYSCONFIG : 0;
        config->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        std::memcpy(session->properties.data() + config->LoggerNameOffset, session->nativeName.c_str(),
                    (session->nativeName.size() + 1) * sizeof(wchar_t));
        session->startResult = StartTraceW(&session->controller, session->nativeName.c_str(), config);
        if (session->startResult != ERROR_SUCCESS) { session->controller = 0; return session; }
        EVENT_TRACE_LOGFILEW log{};
        log.LoggerName = session->nativeName.data();
        log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        log.EventRecordCallback = &Impl::receive;
        log.Context = session.get();
        session->consumer = OpenTraceW(&log);
        if (session->consumer == INVALID_PROCESSTRACE_HANDLE) {
            session->openResult = GetLastError();
            ControlTraceW(session->controller, session->nativeName.c_str(), config, EVENT_TRACE_CONTROL_STOP);
            session->controller = 0;
            return session;
        }
        auto pointer = session.get();
        session->worker = std::thread([pointer] {
            {
                std::lock_guard lock(pointer->owner->data);
                pointer->owner->observerThreads.insert(GetCurrentThreadId());
            }
            TRACEHANDLE handle = pointer->consumer;
            pointer->processResult.store(ProcessTrace(&handle, 1, nullptr, nullptr));
            pointer->finished.store(true);
        });
        return session;
    }
    void querySession(Session &session, ULONG action = EVENT_TRACE_CONTROL_QUERY) {
        if (!session.controller) return;
        // QUERY/STOP return both the logger and backing-file name. The small StartTrace buffer
        // reserves only our input logger name and can return ERROR_MORE_DATA instead of counters.
        // Use independent output storage; never let an unsuccessful query mutate start settings.
        constexpr size_t nameCharacters = 32768;
        std::vector<BYTE> output(sizeof(EVENT_TRACE_PROPERTIES) + 2 * nameCharacters * sizeof(wchar_t));
        auto config = reinterpret_cast<EVENT_TRACE_PROPERTIES *>(output.data());
        config->Wnode.BufferSize = ULONG(output.size());
        config->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        config->LogFileNameOffset = ULONG(sizeof(EVENT_TRACE_PROPERTIES) + nameCharacters * sizeof(wchar_t));
        const auto result = ControlTraceW(session.controller, session.nativeName.c_str(), config, action);
        session.queryResult = result;
        session.lastQuery = clockTime();
        if (result == ERROR_SUCCESS) {
            if (config->EventsLost > session.eventsLost ||
                config->LogBuffersLost + config->RealTimeBuffersLost > session.buffersLost) {
                std::lock_guard lock(data);
                traceGap(session, "session_loss_counter_increase", 0);
            }
            session.eventsLost = config->EventsLost;
            session.buffersLost = config->LogBuffersLost + config->RealTimeBuffersLost;
            session.buffersWritten = config->BuffersWritten;
        }
    }
    void traceGap(const Session &session, const char *reason, quint32 opcode) {
        // A missed close/create or operation boundary invalidates object and WMI correlations.
        // Preserve raw event fields, but never carry a readable annotation across a known gap.
        fileNames.clear();
        registryNames.clear();
        wmiOperations.clear();
        if (session.kernel) {
            cpuThreads.clear();
            ++cpuContextResets;
            // A lost ThreadEnd/ThreadStart can hide TID reuse. Handle-backed generations can still
            // be proved by their immutable creation/exit times; historical-only ones cannot.
            for (auto &[tid, history] : threads) {
                (void)tid;
                for (auto &owner : history) if (!owner.thread && !owner.end) owner.lifecycleStart = false;
            }
        }
        const auto time = clockTime();
        for (const auto &[pid, history] : targets) for (const auto &target : history) {
            if (!target->root || target->retired) continue;
            enqueue({{"schema", 2}, {"source", "windows_etw"}, {"sandbox", target->sandbox},
                {"runId", target->run}, {"pid", qint64(pid)}, {"creationTime", QString::number(target->creation)},
                {"threadId", 0}, {"fileTime", QString::number(time)}, {"category", "telemetry"},
                {"operation", "EtwTraceGap"}, {"provider", "Windows ETW loss notification"},
                {"providerGuid", guidText(LostGuid)}, {"eventId", 0}, {"opcode", int(opcode)},
                {"properties", QJsonObject{{"reason", reason}, {"session", session.name},
                    {"systemLogger", session.kernel}, {"exactLostCountAvailable", false},
                    {"cpuContextInvalidated", session.kernel}, {"correlationCachesInvalidated", true}}}});
        }
    }
    void pruneTargets(bool force = false) {
        const auto now = clockTime();
        if (!force && now >= lastPrune && now - lastPrune < 10000000) return;
        lastPrune = now;
        for (auto map = targets.begin(); map != targets.end();) {
            auto &history = map->second;
            for (auto &target : history) {
                if (target->process && !target->end && WaitForSingleObject(target->process->value, 0) == WAIT_OBJECT_0) {
                    FILETIME creation{}, end{}, kernel{}, user{};
                    if (GetProcessTimes(target->process->value, &creation, &end, &kernel, &user))
                        target->end = fileTime(end);
                }
            }
            std::erase_if(history, [&](const auto &target) {
                if (target->retired) return true;
                if (!target->end || now <= target->end || now - target->end <= 30 * 10000000ULL)
                    return false;
                if (!target->root || !target->job) return true;
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
                // A launcher may exit while its children continue running. Only retire its root
                // identity after the entire owned job is empty and the buffered-tail window elapsed.
                return QueryInformationJobObject(target->job->value, JobObjectBasicAccountingInformation,
                                                  &accounting, sizeof(accounting), nullptr) &&
                       accounting.ActiveProcesses == 0;
            });
            if (history.empty()) map = targets.erase(map);
            else ++map;
        }
        decltype(processThreads) rebuiltThreads;
        for (auto map = threads.begin(); map != threads.end();) {
            for (auto &thread : map->second) if (thread.thread && !thread.end) {
                FILETIME creation{}, exit{}, kernel{}, user{};
                if (GetThreadTimes(thread.thread->value, &creation, &exit, &kernel, &user) && fileTime(exit))
                    thread.end = fileTime(exit);
            }
            std::erase_if(map->second, [&](const auto &thread) {
                return thread.end && now > thread.end && now - thread.end > 30 * 10000000ULL;
            });
            if (map->second.empty()) {
                map = threads.erase(map);
            }
            else {
                for (const auto &owner : map->second) rebuiltThreads[owner.pid].insert(map->first);
                ++map;
            }
        }
        processThreads.swap(rebuiltThreads);
        for (auto it = pendingCalls.begin(); it != pendingCalls.end();) {
            auto &calls = it->second;
            const auto oldFront = calls.empty() ? 0 : calls.front().serial;
            while (!calls.empty() && now > calls.front().time &&
                   now - calls.front().time > 30 * 10000000ULL) {
                calls.pop_front(); --pendingCallCount; ++pendingCallEvicted;
            }
            if (calls.empty()) it = pendingCalls.erase(it);
            else {
                if (calls.front().serial != oldFront) indexPendingFront(it->first, calls);
                ++it;
            }
        }
        if (pendingFronts.size() > 4 * pendingCalls.size() + 8192) rebuildPendingIndex();
    }
    void stop() {
        std::lock_guard controller(control);
        for (auto &session : sessions) {
            if (session->controller) {
                querySession(*session, EVENT_TRACE_CONTROL_STOP);
                session->controller = 0;
            }
            if (session->worker.joinable()) {
                for (unsigned count = 0; count < 100 && !session->finished.load(); ++count)
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                if (!session->finished.load() && session->consumer != INVALID_PROCESSTRACE_HANDLE) {
                    session->cancelledTail = true;
                    CloseTrace(session->consumer);
                    session->consumer = INVALID_PROCESSTRACE_HANDLE;
                }
                session->worker.join();
            }
            if (session->consumer != INVALID_PROCESSTRACE_HANDLE) {
                CloseTrace(session->consumer);
                session->consumer = INVALID_PROCESSTRACE_HANDLE;
            }
        }
        started = false;
    }
    std::shared_ptr<Target> identify(quint32 pid, quint64 time) {
        auto existing = targets.find(pid);
        if (existing != targets.end()) {
            for (auto target = existing->second.rbegin(); target != existing->second.rend(); ++target) {
                if ((*target)->retired) continue;
                if (time < (*target)->creation) continue;
                if ((*target)->process && !(*target)->end && time > (*target)->verifiedThrough) {
                    FILETIME start{}, end{}, kernel{}, user{};
                    const auto checked = clockTime();
                    if (GetProcessTimes((*target)->process->value, &start, &end, &kernel, &user)) {
                        (*target)->end = fileTime(end);
                        (*target)->verifiedThrough = checked;
                    } else continue;
                }
                if ((*target)->end && time > (*target)->end) continue;
                if (!(*target)->process && !(*target)->end) continue;
                if (!(*target)->end && time > (*target)->verifiedThrough) continue;
                return *target;
            }
        }
        auto now = clockTime();
        auto negative = negativePids.find(pid);
        if (negative != negativePids.end() && now >= negative->second.checked &&
            now - negative->second.checked < 10000000) return {};
        NegativeProcess rejection{now};
        auto process = std::make_shared<OwnedHandle>(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
        if (process->value) {
            FILETIME start{}, exit{}, kernel{}, user{};
            if (GetProcessTimes(process->value, &start, &exit, &kernel, &user)) {
                const auto creation = fileTime(start), end = fileTime(exit);
                rejection.creation = creation;
                rejection.end = end;
                if (creation <= time && (!end || time <= end)) {
                    bool allQueried = true;
                    for (const auto &[rootPid, histories] : targets) {
                        (void)rootPid;
                        for (const auto &root : histories) {
                            if (root->retired || !root->job || time < root->creation) continue;
                            BOOL member = FALSE;
                            if (!IsProcessInJob(process->value, root->job->value, &member)) {
                                allQueried = false;
                                continue;
                            }
                            if (member) {
                                if (targets.size() >= 8192) { ++ambiguous; return {}; }
                                auto target = std::make_shared<Target>();
                                target->pid = pid; target->creation = creation; target->end = end;
                                target->verifiedThrough = now;
                                target->sandbox = root->sandbox; target->run = root->run;
                                target->process = process; target->job = root->job;
                                // Insert only after scanning: unordered_map insertion may invalidate the loop.
                                targets[pid].push_back(target);
                                return target;
                            }
                        }
                    }
                    rejection.provedForeign = allQueried;
                }
            }
        }
        if (negativePids.size() >= 16384) negativePids.clear();
        negativePids[pid] = rejection;
        return {};
    }
    bool foreignProcessAt(quint32 pid, quint64 time) const {
        const auto found = negativePids.find(pid);
        if (found == negativePids.end()) return false;
        const auto &proof = found->second;
        return proof.provedForeign && time >= proof.creation &&
               time <= (proof.end ? proof.end : proof.checked);
    }
    bool foreignThreadSnapshotAt(const ThreadOwner &owner, quint64 time) const {
        if (!foreignProcessAt(owner.pid, time) || time < owner.begin ||
            (owner.end && time > owner.end)) return false;
        return (owner.lifecycleStart && owner.lifecycleEnd) ||
               (owner.threadCreation && time >= owner.threadCreation && time <= owner.verifiedThrough);
    }
    bool foreignThreadAt(ThreadOwner &owner, quint32 tid, quint64 time) {
        if (!foreignProcessAt(owner.pid, time)) return false;
        if (foreignThreadSnapshotAt(owner, time)) return true;
        const auto checked = clockTime();
        if (owner.queryAttempt && checked >= owner.queryAttempt &&
            checked - owner.queryAttempt < 10000000) return false;
        owner.queryAttempt = checked;
        OwnedHandle handle(OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, tid));
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!handle.value || GetProcessIdOfThread(handle.value) != owner.pid ||
            !GetThreadTimes(handle.value, &created, &exited, &kernel, &user)) return false;
        const auto creation = fileTime(created), exit = fileTime(exited);
        if ((owner.threadCreation && owner.threadCreation != creation) || creation > time ||
            (exit && time > exit)) return false;
        owner.threadCreation = creation;
        owner.verifiedThrough = checked;
        return foreignThreadSnapshotAt(owner, time);
    }
    QJsonObject decode(EVENT_RECORD &event, QString &operation, QString &provider, bool &partial) {
        const auto &descriptor = event.EventHeader.EventDescriptor;
        auto key = guidText(event.EventHeader.ProviderId) + ':' + QString::number(descriptor.Id) + ':' +
                   QString::number(descriptor.Version) + ':' + QString::number(descriptor.Opcode) + ':' +
                   QString::number(descriptor.Task);
        auto found = schemas.find(key);
        std::shared_ptr<std::vector<BYTE>> storage;
        if (found == schemas.end()) {
            ULONG size = 0;
            auto code = TdhGetEventInformation(&event, 0, nullptr, nullptr, &size);
            if (code != ERROR_INSUFFICIENT_BUFFER || size < sizeof(TRACE_EVENT_INFO) || size > 1024 * 1024) {
                partial = true;
                return {{"tdhError", qint64(code)}};
            }
            storage = std::make_shared<std::vector<BYTE>>(size);
            auto info = reinterpret_cast<TRACE_EVENT_INFO *>(storage->data());
            code = TdhGetEventInformation(&event, 0, nullptr, info, &size);
            if (code != ERROR_SUCCESS) { partial = true; return {{"tdhError", qint64(code)}}; }
            if (schemas.size() >= 4096) schemas.clear();
            schemas.emplace(key, storage);
        } else storage = found->second;
        const auto info = reinterpret_cast<TRACE_EVENT_INFO *>(storage->data());
        provider = informationString(*storage, info->ProviderNameOffset);
        operation = informationString(*storage, info->EventNameOffset);
        if (operation.isEmpty()) operation = informationString(*storage, info->TaskNameOffset);
        const auto opcode = informationString(*storage, info->OpcodeNameOffset);
        if (!opcode.isEmpty() && opcode != operation) operation += '/' + opcode;
        const auto count = std::min<ULONG>(info->TopLevelPropertyCount, 256);
        if (offsetof(TRACE_EVENT_INFO, EventPropertyInfoArray) + size_t(info->PropertyCount) * sizeof(EVENT_PROPERTY_INFO) > storage->size()) {
            partial = true;
            return {{"tdhError", qint64(ERROR_INVALID_DATA)}};
        }
        QJsonObject result;
        for (ULONG index = 0; index < count; ++index) {
            const auto &property = info->EventPropertyInfoArray[index];
            const auto name = informationString(*storage, property.NameOffset);
            if (name.isEmpty()) { partial = true; continue; }
            if (property.Flags & PropertyStruct) { partial = true; continue; }
            auto native = name.toStdWString();
            PROPERTY_DATA_DESCRIPTOR query{};
            query.PropertyName = reinterpret_cast<ULONGLONG>(native.c_str());
            query.ArrayIndex = ULONG_MAX;
            if ((property.Flags & PropertyParamLength) &&
                property.nonStructType.InType == TDH_INTYPE_BINARY &&
                property.lengthPropertyIndex < info->PropertyCount) {
                const auto lengthName = informationString(*storage,
                    info->EventPropertyInfoArray[property.lengthPropertyIndex].NameOffset);
                const auto length = result.value(lengthName);
                if (length.isDouble() && length.toInteger(-1) == 0) {
                    result[name] = QJsonObject{{"encoding", "base64"}, {"data", ""}};
                    continue;
                }
            }
            ULONG size = 0;
            auto code = TdhGetPropertySize(&event, 0, nullptr, 1, &query, &size);
            if (code != ERROR_SUCCESS || size > 65536) { partial = true; continue; }
            if (size == 0 && property.nonStructType.InType == TDH_INTYPE_BINARY) {
                result[name] = QJsonObject{{"encoding", "base64"}, {"data", ""}};
                continue;
            }
            QByteArray bytes(qsizetype(size), '\0');
            code = TdhGetProperty(&event, 0, nullptr, 1, &query, size, reinterpret_cast<PBYTE>(bytes.data()));
            if (code != ERROR_SUCCESS) { partial = true; continue; }
            if (!(property.Flags & PropertyParamCount) && property.count > 1) {
                result[name] = QJsonObject{{"encoding", "base64"}, {"data", QString::fromLatin1(bytes.toBase64())},
                                           {"elements", int(property.count)}};
            } else result[name] = decodeValue(bytes, property.nonStructType.InType);
        }
        if (count != info->TopLevelPropertyCount) partial = true;
        return result;
    }
    void threadEvent(EVENT_RECORD &event, quint64 time) {
        const auto opcode = event.EventHeader.EventDescriptor.Opcode;
        if (opcode == 36 && event.UserDataLength >= 8) {
            DWORD next = 0;
            std::memcpy(&next, event.UserData, sizeof(next));
            const auto processor = GetEventProcessorIndex(&event);
            auto &history = cpuThreads[processor];
            // Some classic events arrive out of timestamp order. Keep a bounded switch history
            // instead of letting one later switch invalidate all earlier callbacks on this CPU.
            auto insertion = std::upper_bound(history.begin(), history.end(), time,
                [](quint64 stamp, const CpuThread &entry) { return stamp < entry.begin; });
            history.insert(insertion, {next, time});
            if (history.size() > 256) history.pop_front();
            ++contextSwitches;
            return;
        }
        if (event.UserDataLength < 8 || (opcode != 1 && opcode != 2 && opcode != 3 && opcode != 4)) return;
        DWORD pid = 0, tid = 0;
        std::memcpy(&pid, event.UserData, 4);
        std::memcpy(&tid, static_cast<BYTE *>(event.UserData) + 4, 4);
        if (!pid || !tid) return;
        if (opcode == 2) {
            auto found = threads.find(tid);
            if (found != threads.end()) {
                for (auto owner = found->second.rbegin(); owner != found->second.rend(); ++owner)
                    if (owner->pid == pid && owner->begin <= time && (!owner->end || time <= owner->end)) {
                        owner->end = time;
                        owner->lifecycleEnd = true;
                        break;
                    }
                }
            auto target = knownTarget(pid);
            if (target) replayPending(target);
            return;
        }
        if (opcode == 4) return; // DC end is enumeration, not proof that a thread exited.
        unresolvedThreads.erase(tid);
        auto target = identify(pid, time);
        if (threads.size() >= 65536 && !threads.contains(tid)) { ++ambiguous; return; }
        auto &history = threads[tid];
        if (opcode == 3 && !history.empty() && history.back().pid == pid && !history.back().end) return;
        ThreadOwner owner{pid, target ? target->creation : 0, time};
        owner.lifecycleStart = opcode == 1;
        if (target) captureThread(owner, tid, time);
        const auto insert = std::upper_bound(history.begin(), history.end(), owner.begin,
            [](quint64 stamp, const ThreadOwner &entry) { return stamp < entry.begin; });
        const auto position = size_t(insert - history.begin());
        if (position && (!history[position - 1].end || history[position - 1].end > owner.begin))
            history[position - 1].end = owner.begin;
        if (position < history.size() && (!owner.end || owner.end > history[position].begin))
            owner.end = history[position].begin;
        history.insert(history.begin() + ptrdiff_t(position), std::move(owner));
        if (history.size() > 4) history.erase(history.begin());
        processThreads[pid].insert(tid);
        if (target) replayPending(target);
    }
    std::shared_ptr<Target> knownTarget(quint32 pid, quint64 creation = 0) {
        auto found = targets.find(pid);
        if (found == targets.end()) return {};
        for (auto item = found->second.rbegin(); item != found->second.rend(); ++item)
            if (!(*item)->retired && (!creation || (*item)->creation == creation)) return *item;
        return {};
    }
    void bindThreads(const std::shared_ptr<Target> &target) {
        const auto found = processThreads.find(target->pid);
        if (found == processThreads.end()) return;
        for (const auto tid : found->second) {
            auto history = threads.find(tid);
            if (history == threads.end()) continue;
            for (auto &owner : history->second)
                if (owner.pid == target->pid && (!owner.creation || owner.creation < target->creation) &&
                    owner.begin >= target->creation &&
                    (!target->end || owner.begin <= target->end)) owner.creation = target->creation;
        }
    }
    void processMetadata(EVENT_RECORD &event, const QJsonObject &properties, quint64 time) {
        const auto eventId = event.EventHeader.EventDescriptor.Id;
        if (eventId != 1 && eventId != 2) return;
        const auto pid = quint32(propertyNumber(properties, {"ProcessID"}));
        const auto creation = propertyNumber(properties, {"CreateTime"});
        const auto sequenceNumber = propertyNumber(properties, {"ProcessSequenceNumber"});
        if (!pid || !creation || creation > time) return;
        if (eventId == 1 && sequenceNumber) {
            if (processHistory.size() >= 65536) processHistory.clear();
            processHistory[sequenceNumber] = {pid, quint32(propertyNumber(properties, {"ParentProcessID"})),
                creation, 0, sequenceNumber, propertyNumber(properties, {"ParentProcessSequenceNumber"}), time};
            if (auto known = knownTarget(pid, creation)) known->processSequence = sequenceNumber;
        } else if (eventId == 2) {
            auto known = knownTarget(pid, creation);
            const auto exit = propertyNumber(properties, {"ExitTime"});
            if (known && exit >= creation) known->end = exit;
            if (sequenceNumber) {
                auto history = processHistory.find(sequenceNumber);
                if (history != processHistory.end() && history->second.pid == pid &&
                    history->second.creation == creation) history->second.exit = exit;
            }
            if (known) replayPending(known);
        }
        // Kernel process metadata is historical proof even for a child that exited before ETW's
        // buffer arrived. PID alone is never sufficient: parent sequence, lifetime and actual
        // non-breakaway job policy must all match the already verified parent registration.
        for (unsigned pass = 0; pass < 8; ++pass) {
            bool changed = false;
            for (const auto &[key, child] : processHistory) {
                (void)key;
                if (!child.parentSequence || knownTarget(child.pid, child.creation)) continue;
                auto parent = knownTarget(child.parent);
                if (!parent || parent->processSequence != child.parentSequence || !parent->job ||
                    child.creation < parent->creation || (parent->end && child.creation > parent->end)) continue;
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
                if (!QueryInformationJobObject(parent->job->value, JobObjectExtendedLimitInformation,
                                               &limits, sizeof(limits), nullptr) ||
                    (limits.BasicLimitInformation.LimitFlags &
                     (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK))) continue;
                if (targets.size() >= 8192) { ++ambiguous; continue; }
                auto target = std::make_shared<Target>();
                target->pid = child.pid; target->creation = child.creation; target->end = child.exit;
                target->verifiedThrough = time;
                target->sandbox = parent->sandbox; target->run = parent->run; target->job = parent->job;
                target->processSequence = child.sequence;
                target->admissionProof = "kernel_parent_sequence_and_nonbreakaway_job_inheritance";
                auto handle = std::make_shared<OwnedHandle>(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                                                       FALSE, child.pid));
                if (handle->value) {
                    FILETIME created{}, exited{}, kernelTime{}, userTime{};
                    BOOL member = FALSE;
                    if (GetProcessTimes(handle->value, &created, &exited, &kernelTime, &userTime) &&
                        fileTime(created) == child.creation &&
                        IsProcessInJob(handle->value, parent->job->value, &member) && member) {
                        target->process = std::move(handle);
                        target->end = fileTime(exited);
                    }
                }
                targets[child.pid].push_back(target);
                negativePids.erase(child.pid);
                bindThreads(target);
                ++historicalChildren;
                changed = true;
                replayPending(target);
            }
            if (!changed) break;
        }
    }
    void replayPending(const std::shared_ptr<Target> &target) {
        if (!target || target->retired) return;
        const auto targetThreads = processThreads.find(target->pid);
        if (targetThreads != processThreads.end()) for (const auto tid : targetThreads->second) {
          auto pending = pendingCalls.find(tid);
          if (pending == pendingCalls.end()) continue;
          std::deque<PendingCall> remainingCalls;
          auto calls = std::move(pending->second);
          pendingCalls.erase(pending);
          while (!calls.empty()) {
            auto call = calls.front();
            calls.pop_front();
            bool match = false;
            if (call.time >= target->creation && (!target->end || call.time <= target->end)) {
                auto owners = threads.find(call.tid);
                if (owners != threads.end()) for (auto &owner : owners->second) {
                    if (owner.pid == target->pid && owner.creation == target->creation &&
                        threadMatches(owner, call.tid, call.time) && identify(owner.pid, call.time)) {
                        match = true;
                        break;
                    }
                }
            }
            if (!match) { remainingCalls.push_back(call); continue; }
            --pendingCallCount;
            EVENT_RECORD record{};
            record.EventHeader.ProviderId = PerfGuid;
            record.EventHeader.EventDescriptor.Opcode = UCHAR(call.opcode);
            record.EventHeader.Flags = call.flags | EVENT_HEADER_FLAG_PROCESSOR_INDEX;
            record.EventHeader.TimeStamp.QuadPart = LONGLONG(call.time);
            record.EventHeader.ThreadId = call.tid;
            record.BufferContext.ProcessorIndex = USHORT(call.processor);
            record.UserData = &call.value;
            record.UserDataLength = call.opcode == 52 ? 4 : (call.flags & EVENT_HEADER_FLAG_32_BIT_HEADER ? 4 : 8);
            eventLocked(record, true, false, true);
            ++replayedCalls;
          }
          if (!remainingCalls.empty()) {
              auto inserted = pendingCalls.emplace(tid, std::move(remainingCalls));
              indexPendingFront(tid, inserted.first->second);
          }
        }
        std::deque<PendingEvent> remainingEvents;
        while (!pendingEvents.empty()) {
            auto saved = std::move(pendingEvents.front());
            pendingEvents.pop_front();
            if (saved.pid != target->pid || saved.creation != target->creation ||
                (!target->process && !target->end)) { remainingEvents.push_back(std::move(saved)); continue; }
            pendingEventBytes -= quint64(saved.payload.size()) + sizeof(PendingEvent);
            EVENT_RECORD record{};
            record.EventHeader = saved.header;
            record.BufferContext = saved.buffer;
            record.UserData = saved.payload.data();
            record.UserDataLength = USHORT(saved.payload.size());
            eventLocked(record, false, false, true);
        }
        pendingEvents.swap(remainingEvents);
    }
    void indexPendingFront(quint32 tid, const std::deque<PendingCall> &calls) {
        if (!calls.empty()) pendingFronts.push({calls.front().time, calls.front().serial, tid});
    }
    void rebuildPendingIndex() {
        decltype(pendingFronts) replacement;
        for (const auto &[tid, calls] : pendingCalls)
            if (!calls.empty()) replacement.push({calls.front().time, calls.front().serial, tid});
        pendingFronts.swap(replacement);
    }
    bool evictOldestPending() {
        while (!pendingFronts.empty()) {
            const auto head = pendingFronts.top();
            pendingFronts.pop();
            auto bucket = pendingCalls.find(head.tid);
            if (bucket == pendingCalls.end() || bucket->second.empty() ||
                bucket->second.front().serial != head.serial) continue;
            bucket->second.pop_front();
            --pendingCallCount;
            ++pendingCallEvicted;
            if (bucket->second.empty()) pendingCalls.erase(bucket);
            else indexPendingFront(head.tid, bucket->second);
            return true;
        }
        return false;
    }
    void pendCall(PendingCall call) {
        // Only unresolved thread generations reach here. Foreign processes are eliminated before
        // formatting or buffering. Indexing by TID prevents replay from scanning the machine's
        // unrelated calls on every target lifecycle event.
        constexpr size_t totalLimit = 512 * 1024, threadLimit = 64 * 1024;
        while (pendingCallCount >= totalLimit) {
            if (!evictOldestPending()) { rebuildPendingIndex(); if (!evictOldestPending()) break; }
        }
        auto found = pendingCalls.find(call.tid);
        if (found == pendingCalls.end()) {
            while (pendingCalls.size() >= 8192)
                if (!evictOldestPending()) { ++pendingCallEvicted; return; }
            found = pendingCalls.emplace(call.tid, std::deque<PendingCall>()).first;
        }
        auto &calls = found->second;
        const auto oldFront = calls.empty() ? 0 : calls.front().serial;
        while (!calls.empty() && call.time > calls.front().time &&
               call.time - calls.front().time > 30 * 10000000ULL) {
            calls.pop_front(); --pendingCallCount; ++pendingCallEvicted;
        }
        if (calls.size() >= threadLimit) {
            calls.pop_front(); --pendingCallCount; ++pendingCallEvicted;
        }
        if (pendingCallCount >= totalLimit) { ++pendingCallEvicted; return; }
        call.serial = ++pendingCallSerial;
        calls.push_back(call);
        ++pendingCallCount;
        if (calls.front().serial != oldFront) indexPendingFront(call.tid, calls);
        pendingCallHighWater = std::max<quint64>(pendingCallHighWater, pendingCallCount);
    }
    void discardForeignPending(quint32 tid) {
        auto pending = pendingCalls.find(tid);
        if (pending == pendingCalls.end()) return;
        const auto owners = threads.find(tid);
        if (owners == threads.end()) return;
        auto &calls = pending->second;
        const auto oldFront = calls.empty() ? 0 : calls.front().serial;
        std::erase_if(calls, [&](const PendingCall &call) {
            for (const auto &owner : owners->second) {
                if (call.time < owner.begin || (owner.end && call.time > owner.end)) continue;
                if (!foreignThreadSnapshotAt(owner, call.time)) continue;
                --pendingCallCount;
                ++foreignCallsDiscarded;
                return true;
            }
            return false;
        });
        if (calls.empty()) pendingCalls.erase(pending);
        else if (calls.front().serial != oldFront) indexPendingFront(tid, calls);
    }
    void discoverThread(quint32 tid, quint64 time) {
        const auto now = clockTime();
        const auto previous = unresolvedThreads.find(tid);
        if (previous != unresolvedThreads.end() && now >= previous->second &&
            now - previous->second < 10000000) return;
        if (unresolvedThreads.size() >= 16384) unresolvedThreads.clear();
        unresolvedThreads[tid] = now;
        OwnedHandle handle(OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, tid));
        if (!handle.value) return;
        const auto pid = GetProcessIdOfThread(handle.value);
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!pid || !GetThreadTimes(handle.value, &created, &exited, &kernel, &user) ||
            fileTime(created) > time || (fileTime(exited) && fileTime(exited) < time)) return;
        if (threads.size() >= 65536 && !threads.contains(tid)) return;
        auto target = identify(pid, time);
        ThreadOwner owner{pid, target ? target->creation : 0, fileTime(created), fileTime(exited)};
        owner.threadCreation = fileTime(created);
        owner.verifiedThrough = now;
        owner.queryAttempt = now;
        if (target) {
            owner.thread = std::make_shared<OwnedHandle>(handle.value);
            handle.value = nullptr;
            owner.threadCreation = fileTime(created);
            owner.verifiedThrough = now;
        }
        auto &history = threads[tid];
        if (history.size() >= 4) history.erase(history.begin());
        history.push_back(std::move(owner));
        processThreads[pid].insert(tid);
    }
    std::shared_ptr<Target> syscallTarget(quint32 tid, quint64 time, bool &foreign) {
        foreign = false;
        auto found = threads.find(tid);
        if (found == threads.end()) {
            discoverThread(tid, time);
            found = threads.find(tid);
        }
        if (found == threads.end()) return {};
        for (auto history = found->second.rbegin(); history != found->second.rend(); ++history) {
            if (time < history->begin || (history->end && time > history->end)) continue;
            // Check process ownership before touching a thread handle. Most calls in the system
            // belong to foreign processes; opening/querying their threads creates more trace load.
            auto target = identify(history->pid, time);
            if (!target) { foreign = foreignThreadAt(*history, tid, time); return {}; }
            if (!history->creation && history->begin >= target->creation)
                history->creation = target->creation;
            if (target->creation != history->creation || !threadMatches(*history, tid, time)) return {};
            return target;
        }
        return {};
    }
    void enqueue(QJsonObject event) {
        event["sequence"] = QString::number(sequence++);
        const auto bytes = quint64(QJsonDocument(event).toJson(QJsonDocument::Compact).size());
        if (bytes > 256 * 1024 - 2048 || queue.size() >= QueueRecords || queuedBytes + bytes > QueueBudget) {
            ++queueDropped;
            return;
        }
        queuedBytes += bytes;
        queue.push_back({std::move(event), bytes});
        ++accepted;
    }
    void event(EVENT_RECORD &event, bool kernel) {
        std::lock_guard lock(data);
        eventLocked(event, kernel);
    }
    void eventLocked(EVENT_RECORD &event, bool kernel, bool allowPending = true, bool replayed = false) {
        const auto time = quint64(event.EventHeader.TimeStamp.QuadPart);
        if (time < 116444736000000000ULL) { ++ambiguous; return; }
        latestEventTime = std::max(latestEventTime, time);
        if (kernel && guidEqual(event.EventHeader.ProviderId, ThreadGuid)) { threadEvent(event, time); return; }
        // Queries needed to prove TID lifetime themselves generate syscalls. Ignore our own consumer
        // threads before any thread query, preventing feedback even when kernel headers omit PID.
        if (event.EventHeader.ProcessId == GetCurrentProcessId() ||
            observerThreads.contains(event.EventHeader.ThreadId)) { ++ignored; return; }
        const auto opcode = event.EventHeader.EventDescriptor.Opcode;
        const bool syscall = kernel && guidEqual(event.EventHeader.ProviderId, PerfGuid) && (opcode == 51 || opcode == 52);
        if (kernel && !syscall) return;
        Provider *providerEntry = nullptr;
        for (auto &provider : providers)
            if (guidEqual(provider.guid, event.EventHeader.ProviderId)) { providerEntry = &provider; break; }
        if (!kernel && !providerEntry) return;
        if (providerEntry) ++providerEntry->observed;
        quint32 pid = event.EventHeader.ProcessId, tid = event.EventHeader.ThreadId;
        bool processorRecovered = false;
        if (syscall && (!tid || tid == ULONG_MAX)) {
            auto current = cpuThreads.find(GetEventProcessorIndex(&event));
            if (current == cpuThreads.end() || current->second.empty() || current->second.front().begin > time) {
                ++cpuOrderAmbiguous;
                return;
            }
            const auto switchAfter = std::upper_bound(current->second.begin(), current->second.end(), time,
                [](quint64 stamp, const CpuThread &entry) { return stamp < entry.begin; });
            const auto selected = std::prev(switchAfter);
            if (selected != current->second.begin() && selected->begin == time &&
                std::prev(selected)->begin == time && std::prev(selected)->tid != selected->tid) {
                ++cpuOrderAmbiguous;
                return;
            }
            tid = selected->tid;
            if (!tid) { ++ignored; return; }
            processorRecovered = true;
            if (observerThreads.contains(tid)) { ++ignored; return; }
        }
        std::shared_ptr<Target> target;
        if (syscall) {
            bool foreign = false;
            target = syscallTarget(tid, time, foreign);
            if (!target) {
                if (foreign) { ++foreignCallsDiscarded; discardForeignPending(tid); }
                else if (allowPending && tid && tid != ULONG_MAX && !targets.empty()) {
                    quint64 raw = 0;
                    const auto width = opcode == 52 || (event.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4u : 8u;
                    if (event.UserDataLength >= width) {
                        std::memcpy(&raw, event.UserData, width);
                        pendCall({time, raw, tid, GetEventProcessorIndex(&event), opcode, event.EventHeader.Flags});
                    } else ++decodeErrors;
                }
                ++ignored;
                return;
            }
            pid = target->pid;
        }
        QString operation, provider = syscall ? "Windows Kernel PerfInfo" : QString(providerEntry->name);
        QJsonObject properties;
        bool partial = false;
        if (syscall) {
            operation = opcode == 51 ? "SysCallEnter" : "SysCallExit";
            if (opcode == 51) {
                quint64 address = 0;
                const auto width = event.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER ? 4u : 8u;
                if (event.UserDataLength >= width) {
                    std::memcpy(&address, event.UserData, width);
                    properties["SysCallAddress"] = "0x" + QString::number(address, 16);
                    auto name = syscallNames.find(address);
                    if (name != syscallNames.end()) {
                        properties["functionNameCandidate"] = name->second;
                        properties["functionNameResolved"] = false;
                        properties["nameResolution"] = "local_kernel_export_rva_candidate";
                        properties["liveKernelImageIdentityVerified"] = false;
                    }
                } else partial = true;
            } else {
                DWORD status = 0;
                if (event.UserDataLength >= sizeof(status)) {
                    std::memcpy(&status, event.UserData, sizeof(status));
                    properties["SysCallNtStatus"] = "0x" + QString::number(status, 16);
                } else partial = true;
            }
            properties["argumentsAvailable"] = false;
            if (!properties.contains("functionNameResolved")) properties["functionNameResolved"] = false;
        } else {
            // WMI and network events can be emitted by service/system processes; decode their real
            // client PID before attribution. Other providers use caller/header PID when available.
            if (guidEqual(providerEntry->guid, WmiGuid) || guidEqual(providerEntry->guid, NetworkGuid) ||
                (guidEqual(providerEntry->guid, FileGuid) &&
                 (event.EventHeader.EventDescriptor.Id == 10 || event.EventHeader.EventDescriptor.Id == 11)) ||
                guidEqual(providerEntry->guid, ProcessGuid))
                properties = decode(event, operation, provider, partial);
            if (guidEqual(providerEntry->guid, ProcessGuid)) processMetadata(event, properties, time);
        }
        QString attribution = syscall ? "processor_context_switch_and_thread_process_lifetime"
                                      : "header_pid_and_process_lifetime";
        if (syscall) {
            if (!processorRecovered && !replayed) attribution = "thread_lifecycle_and_process_creation";
        } else if (providerEntry && guidEqual(providerEntry->guid, WmiGuid)) {
            pid = quint32(propertyNumber(properties, {"ClientProcessId", "ClientProcessID"}));
            const auto group = propertyNumber(properties, {"GroupOperationId", "GroupOperationID"});
            const auto operationId = propertyNumber(properties, {"OperationId", "OperationID"});
            const auto correlation = group ? "G:" + QString::number(group)
                                           : operationId ? "O:" + QString::number(operationId) : QString();
            if (pid) target = identify(pid, time);
            const auto clientCreation = propertyNumber(properties, {"ClientProcessCreationTime"});
            if (!target && pid && clientCreation) {
                auto history = targets.find(pid);
                if (history != targets.end()) for (const auto &known : history->second) {
                    if (known->retired || known->creation != clientCreation || time < known->creation)
                        continue;
                    if (known->end && time > known->end && time - known->end > 30 * 10000000ULL)
                        continue;
                    target = known;
                    break;
                }
            }
            if (target && clientCreation && target->creation != clientCreation) {
                ++ambiguous;
                target.reset();
            }
            else if (!pid && !correlation.isEmpty()) {
                auto found = wmiOperations.find(correlation);
                if (found != wmiOperations.end()) target = found->second.lock();
                if (target && (target->retired || time < target->creation ||
                               (target->end && time > target->end &&
                                time - target->end > 30 * 10000000ULL))) target.reset();
            }
            attribution = pid ? "wmi_client_pid_and_process_lifetime" : "wmi_operation_correlation";
            if (target && target->end && time > target->end) {
                attribution = pid ? "wmi_exact_client_creation_service_tail" : "wmi_operation_correlation_service_tail";
                properties["clientExitTime"] = QString::number(target->end);
                properties["serviceTailAfterClientExit"] = true;
            }
            if (target && !correlation.isEmpty()) {
                if (wmiOperations.size() >= 65536) wmiOperations.clear();
                wmiOperations[correlation] = target;
                if (group) wmiOperations["G:" + QString::number(group)] = target;
                if (operationId) wmiOperations["O:" + QString::number(operationId)] = target;
            }
        } else {
            if (providerEntry && guidEqual(providerEntry->guid, NetworkGuid)) {
                auto payloadPid = quint32(propertyNumber(properties, {"PID", "ProcessId", "ProcessID"}));
                if (payloadPid) { pid = payloadPid; attribution = "network_payload_pid_and_process_lifetime"; }
            }
            if (providerEntry && guidEqual(providerEntry->guid, ProcessGuid)) {
                auto payloadPid = quint32(propertyNumber(properties, {"ProcessID", "ProcessId"}));
                if (payloadPid) { pid = payloadPid; attribution = "process_payload_pid_and_process_lifetime"; }
                if (event.EventHeader.EventDescriptor.Id == 1 || event.EventHeader.EventDescriptor.Id == 2)
                    target = knownTarget(pid, propertyNumber(properties, {"CreateTime"}));
            }
            if (!target && pid && pid != ULONG_MAX) target = identify(pid, time);
            const bool fileEvent = providerEntry && guidEqual(providerEntry->guid, FileGuid);
            const bool headerUnknown = !pid || pid == ULONG_MAX;
            if (!target && (headerUnknown || (fileEvent && pid == 4))) {
                if (providerEntry && guidEqual(providerEntry->guid, FileGuid)) {
                    // Only inspect the issuing-thread property for an otherwise unattributable file
                    // event. Do not fully format the machine's unrelated file traffic.
                    auto issuing = quint32(propertyNumber(properties, {"IssuingThreadId", "IssuingThreadID", "ThreadId"}));
                    if (!issuing) {
                        for (const wchar_t *name : {L"IssuingThreadId", L"ThreadId"}) {
                            PROPERTY_DATA_DESCRIPTOR query{};
                            query.PropertyName = reinterpret_cast<ULONGLONG>(name);
                            query.ArrayIndex = ULONG_MAX;
                            ULONG size = 0;
                            if (TdhGetPropertySize(&event, 0, nullptr, 1, &query, &size) == ERROR_SUCCESS && size <= 8) {
                                quint64 value = 0;
                                if (TdhGetProperty(&event, 0, nullptr, 1, &query, size,
                                                   reinterpret_cast<PBYTE>(&value)) == ERROR_SUCCESS) {
                                    issuing = quint32(value);
                                    break;
                                }
                            }
                        }
                    }
                    if (issuing) tid = issuing;
                }
                auto found = threads.find(tid);
                if (found != threads.end()) {
                    for (auto history = found->second.rbegin(); history != found->second.rend(); ++history) {
                        if (time < history->begin || (history->end && time > history->end)) continue;
                        if (!threadMatches(*history, tid, time)) { ++ambiguous; continue; }
                        auto candidate = identify(history->pid, time);
                        if (candidate && candidate->creation == history->creation) target = candidate;
                        break;
                    }
                }
                if (target) attribution = processorRecovered || replayed
                    ? "processor_context_switch_and_thread_process_lifetime"
                    : "thread_lifecycle_and_process_creation";
            }
        }
        if (target && !syscall && properties.isEmpty()) properties = decode(event, operation, provider, partial);
        if (providerEntry && guidEqual(providerEntry->guid, FileGuid)) {
            const auto object = propertyNumber(properties, {"FileObject", "FileKey"});
            const auto name = propertyText(properties, {"FileName", "OpenPath", "FilePath"});
            if (object && !name.isEmpty()) {
                if (fileNames.size() >= 131072) fileNames.clear();
                fileNames[object] = name;
            }
            if (object && name.isEmpty()) {
                auto found = fileNames.find(object);
                if (found == fileNames.end()) {
                    const auto fileKey = propertyNumber(properties, {"FileKey"});
                    found = fileNames.find(fileKey);
                }
                if (found != fileNames.end()) properties["CorrelatedFileName"] = found->second;
            }
            if (event.EventHeader.EventDescriptor.Id == 11 || event.EventHeader.EventDescriptor.Id == 14)
                fileNames.erase(object);
        }
        if (!target) {
            if (allowPending && providerEntry && !guidEqual(providerEntry->guid, ProcessGuid)) {
                auto known = knownTarget(pid);
                if (!known) {
                    auto owner = threads.find(tid);
                    if (owner != threads.end()) for (const auto &history : owner->second) {
                        if (time >= history.begin && (!history.end || time <= history.end)) {
                            known = knownTarget(history.pid, history.creation);
                            if (known) break;
                        }
                    }
                }
                if (known && !known->retired && !known->process && !known->end && time >= known->creation) {
                    const auto bytes = quint64(event.UserDataLength) + sizeof(PendingEvent);
                    if (pendingEventBytes + bytes <= 32 * 1024 * 1024) {
                        PendingEvent saved;
                        saved.header = event.EventHeader;
                        saved.buffer = event.BufferContext;
                        saved.payload = QByteArray(static_cast<const char *>(event.UserData), event.UserDataLength);
                        saved.pid = known->pid;
                        saved.creation = known->creation;
                        pendingEventBytes += bytes;
                        pendingEvents.push_back(std::move(saved));
                    } else ++pendingEventDropped;
                }
            }
            ++ignored;
            return;
        }
        if (providerEntry && guidEqual(providerEntry->guid, RegistryGuid)) {
            const auto object = propertyNumber(properties, {"KeyObject"});
            const auto prefix = QString::number(target->pid) + ':' + QString::number(target->creation) + ':';
            const auto cacheKey = prefix + QString::number(object);
            auto name = propertyText(properties, {"KeyName"});
            const auto relative = propertyText(properties, {"RelativeName"});
            auto base = propertyText(properties, {"BaseName"});
            if (name.isEmpty() && !relative.isEmpty()) {
                if (relative.startsWith('\\')) name = relative;
                else {
                    const auto baseObject = propertyNumber(properties, {"BaseObject"});
                    auto found = registryNames.find(prefix + QString::number(baseObject));
                    if (base.isEmpty() && baseObject && found != registryNames.end() && found->second.observed <= time)
                        base = found->second.name;
                    if (!base.isEmpty()) name = base + (base.endsWith('\\') ? "" : "\\") + relative;
                }
            }
            const auto status = propertyNumber(properties, {"Status"});
            const bool success = !(status & 0x80000000ULL);
            if (object && !name.isEmpty() && success) {
                auto found = registryNames.find(cacheKey);
                if (found == registryNames.end() || found->second.observed <= time) {
                    if (registryNames.size() >= 65536) registryNames.clear();
                    registryNames[cacheKey] = {name, time};
                }
            }
            if (object && name.isEmpty()) {
                auto found = registryNames.find(cacheKey);
                if (found != registryNames.end() && found->second.observed <= time) name = found->second.name;
            }
            if (!name.isEmpty()) {
                properties["CorrelatedKeyName"] = name;
                properties["keyNameCorrelation"] = "same_process_creation_key_object_history";
            } else if (!relative.isEmpty()) properties["keyNameUnresolvedRelative"] = true;
            if (object && success && (opcode == 34 || opcode == 44)) registryNames.erase(cacheKey);
        }
        if (providerEntry && guidEqual(providerEntry->guid, NetworkGuid)) {
            for (const auto pair : {std::pair{"saddr", "sourceAddress"}, std::pair{"daddr", "destinationAddress"}}) {
                const auto raw = properties.value(pair.first);
                if (!raw.isDouble()) continue;
                const auto address = quint32(raw.toInteger());
                properties[pair.second] = QString::number(address & 255) + '.' +
                    QString::number((address >> 8) & 255) + '.' + QString::number((address >> 16) & 255) + '.' +
                    QString::number((address >> 24) & 255);
            }
            for (const auto pair : {std::pair{"sport", "sourcePort"}, std::pair{"dport", "destinationPort"}}) {
                const auto raw = properties.value(pair.first);
                if (!raw.isDouble() || raw.toInteger(-1) < 0 || raw.toInteger() > 65535) continue;
                const auto port = quint16(raw.toInteger());
                properties[pair.second] = int(((port & 255) << 8) | (port >> 8));
            }
        }
        if (operation.isEmpty()) operation = QString(providerEntry ? providerEntry->category : "syscall") +
                                             '/' + QString::number(event.EventHeader.EventDescriptor.Id) +
                                             '/' + QString::number(opcode);
        if (partial) {
            ++decodeErrors;
            properties["payloadDecodedPartially"] = true;
            properties["rawPayloadBase64"] = QString::fromLatin1(QByteArray(static_cast<const char *>(event.UserData), event.UserDataLength).toBase64());
        }
        if (syscall) ++syscallEvents;
        if (syscall) properties["processorIndex"] = int(GetEventProcessorIndex(&event));
        if (processorRecovered) properties["threadRecoveredFromContextSwitch"] = true;
        if (replayed) properties["replayedAfterHistoricalIdentityProof"] = true;
        auto path = propertyText(properties, {"FileName", "OpenPath", "FilePath", "CorrelatedFileName", "KeyName", "CorrelatedKeyName", "RelativeName", "Path", "ObjectName", "NamespaceName", "Namespace"});
        QJsonObject record{{"schema", 2}, {"source", "windows_etw"}, {"sandbox", target->sandbox},
                           {"runId", target->run}, {"pid", qint64(target->pid)},
                           {"creationTime", QString::number(target->creation)}, {"threadId", qint64(tid)},
                           {"fileTime", QString::number(time)},
                           {"timeUtc", QDateTime::fromMSecsSinceEpoch(qint64((time - 116444736000000000ULL) / 10000), QTimeZone::UTC).toString(Qt::ISODateWithMs)},
                           {"provider", provider}, {"providerGuid", guidText(event.EventHeader.ProviderId)},
                           {"eventId", int(event.EventHeader.EventDescriptor.Id)}, {"opcode", int(opcode)},
                           {"category", syscall ? QString("syscall") : QString(providerEntry->category)},
                           {"operation", operation.left(256)}, {"path", path}, {"attribution", attribution},
                           {"processAdmissionProof", target->admissionProof},
                           {"properties", properties}};
        enqueue(std::move(record));
    }
};

AuditEtw::AuditEtw(bool systemCalls) : impl_(std::make_unique<Impl>(systemCalls)) {}
AuditEtw::~AuditEtw() { impl_->stop(); }
QJsonObject AuditEtw::start() {
    {
        std::lock_guard controller(impl_->control);
        if (!impl_->started) {
            // A failed start can be retried after privileges change; failed session names are never reused.
            impl_->sessions.clear();
            impl_->profilePrivilege = enablePrivilege(SE_SYSTEM_PROFILE_NAME);
            if (impl_->requestedSyscalls) {
                impl_->debugPrivilege = enablePrivilege(SE_DEBUG_NAME);
                impl_->loadSyscallNames();
            }
            auto manifest = impl_->createSession(false);
            if (manifest->controller) {
                ENABLE_TRACE_PARAMETERS parameters{};
                parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
                for (auto &provider : impl_->providers) {
                    provider.result = EnableTraceEx2(manifest->controller, &provider.guid,
                        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0xffffffffffffffffULL,
                        0, 0, &parameters);
                }
            } else for (auto &provider : impl_->providers) provider.result = manifest->startResult;
            impl_->started = manifest->controller != 0;
            impl_->sessions.push_back(std::move(manifest));
            if (impl_->requestedSyscalls) {
                auto kernel = impl_->createSession(true);
                impl_->started = impl_->started || kernel->controller != 0;
                impl_->sessions.push_back(std::move(kernel));
            }
        }
    }
    return status();
}
void AuditEtw::stop() { impl_->stop(); }
bool AuditEtw::watch(quint32 pid, quint64 expectedCreationTime, const QString &sandbox, const QString &runId,
                     HANDLE job, QString *error) {
    auto reject = [&](const QString &reason) { if (error) *error = reason; return false; };
    if (!pid || !expectedCreationTime || QUuid(sandbox).isNull() || QUuid(runId).isNull())
        return reject("Invalid process creation identity or sandbox/run ID");
    if (pid == GetCurrentProcessId()) return reject("The ETW observer cannot observe its own process");
    auto process = std::make_shared<OwnedHandle>(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
    if (!process->value) return reject("Open observed process failed: " + QString::number(GetLastError()));
    FILETIME creation{}, exit{}, kernel{}, user{};
    const auto processChecked = clockTime();
    if (!GetProcessTimes(process->value, &creation, &exit, &kernel, &user) || fileTime(creation) != expectedCreationTime)
        return reject("Observed PID has a different creation identity");
    std::shared_ptr<OwnedHandle> ownedJob;
    if (job) {
        ownedJob = std::make_shared<OwnedHandle>();
        if (!DuplicateHandle(GetCurrentProcess(), job, GetCurrentProcess(), &ownedJob->value,
                              JOB_OBJECT_QUERY, FALSE, 0)) return reject("Duplicate observed job failed");
        BOOL member = FALSE;
        if (!IsProcessInJob(process->value, ownedJob->value, &member) || !member)
            return reject("Observed process is not a member of the supplied job");
    }
    std::lock_guard lock(impl_->data);
    impl_->pruneTargets(true);
    auto found = impl_->targets.find(pid);
    if (found != impl_->targets.end())
        for (const auto &existing : found->second)
            if (existing->creation == expectedCreationTime)
                return existing->sandbox == sandbox && existing->run == runId && !existing->retired;
    if (impl_->targets.size() >= 8192) return reject("Observed process identity capacity reached");
    auto target = std::make_shared<Impl::Target>();
    target->pid = pid; target->creation = expectedCreationTime; target->end = fileTime(exit);
    target->root = true;
    target->verifiedThrough = processChecked;
    target->sandbox = sandbox; target->run = runId; target->process = std::move(process); target->job = std::move(ownedJob);
    for (const auto &[sequence, history] : impl_->processHistory)
        if (history.pid == pid && history.creation == expectedCreationTime) target->processSequence = sequence;
    impl_->targets[pid].push_back(target);
    // A newly registered job changes the set against which foreign membership was proved.
    impl_->negativePids.clear();
    impl_->bindThreads(target);
    OwnedHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (snapshot.value != INVALID_HANDLE_VALUE) {
        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        if (Thread32First(snapshot.value, &entry)) do {
            if (entry.th32OwnerProcessID == pid)
            {
                Impl::ThreadOwner owner{pid, expectedCreationTime, expectedCreationTime};
                impl_->captureThread(owner, entry.th32ThreadID, clockTime());
                if (owner.thread) {
                    impl_->threads[entry.th32ThreadID].push_back(std::move(owner));
                    impl_->processThreads[pid].insert(entry.th32ThreadID);
                }
            }
        } while (Thread32Next(snapshot.value, &entry));
    }
    return true;
}
void AuditEtw::unwatch(quint32 pid, quint64 creationTime) {
    std::lock_guard lock(impl_->data);
    auto found = impl_->targets.find(pid);
    if (found == impl_->targets.end()) return;
    for (auto &target : found->second) if (target->creation == creationTime) {
        target->retired = true;
        if (!target->end) target->end = clockTime();
    }
}
void AuditEtw::unwatchSession(const QString &sandbox, const QString &runId) {
    std::lock_guard lock(impl_->data);
    std::vector<std::shared_ptr<Impl::Target>> removed;
    for (auto &[pid, histories] : impl_->targets) {
        (void)pid;
        for (auto &target : histories)
            if (target->sandbox == sandbox && target->run == runId) {
                target->retired = true;
                if (!target->end) target->end = clockTime();
                removed.push_back(target);
            }
    }
    for (auto it = impl_->queue.begin(); it != impl_->queue.end();) {
        if (it->record.value("sandbox").toString() == sandbox && it->record.value("runId").toString() == runId) {
            impl_->queuedBytes -= it->bytes;
            ++impl_->unwatchDiscarded;
            it = impl_->queue.erase(it);
        } else ++it;
    }
    std::erase_if(impl_->pendingEvents, [&](const Impl::PendingEvent &saved) {
        for (const auto &target : removed) {
            if (saved.pid != target->pid || saved.creation != target->creation) continue;
            impl_->pendingEventBytes -= quint64(saved.payload.size()) + sizeof(Impl::PendingEvent);
            ++impl_->unwatchDiscarded;
            return true;
        }
        return false;
    });
    for (auto it = impl_->pendingCalls.begin(); it != impl_->pendingCalls.end();) {
        auto owners = impl_->threads.find(it->first);
        if (owners == impl_->threads.end()) { ++it; continue; }
        auto &calls = it->second;
        std::erase_if(calls, [&](const Impl::PendingCall &call) {
            for (const auto &target : removed) {
                if (call.time < target->creation || call.time > target->end) continue;
                for (auto &owner : owners->second) {
                    if (owner.pid != target->pid || owner.creation != target->creation ||
                        !impl_->threadMatches(owner, it->first, call.time)) continue;
                    --impl_->pendingCallCount;
                    ++impl_->unwatchDiscarded;
                    return true;
                }
            }
            return false;
        });
        if (calls.empty()) it = impl_->pendingCalls.erase(it); else ++it;
    }
    impl_->rebuildPendingIndex();
    impl_->pruneTargets(true);
}
QJsonArray AuditEtw::drain(int maxRecords) {
    std::lock_guard lock(impl_->data);
    impl_->pruneTargets();
    QJsonArray records;
    maxRecords = std::clamp(maxRecords, 1, 4096);
    quint64 bytes = 2;
    while (!impl_->queue.empty() && records.size() < maxRecords) {
        const auto next = impl_->queue.front().bytes + (records.isEmpty() ? 0 : 1);
        if (bytes + next > 448 * 1024) break;
        bytes += next;
        auto entry = std::move(impl_->queue.front());
        impl_->queue.pop_front();
        impl_->queuedBytes -= entry.bytes;
        records.append(std::move(entry.record));
    }
    return records;
}
QJsonObject AuditEtw::status() {
    std::lock_guard controller(impl_->control);
    QJsonArray sessions, providers;
    quint64 eventsLost = 0, buffersLost = 0;
    bool syscallReady = false, cancelledTail = false, active = false, manifestActive = false;
    bool anyStartedSession = false, allStartedSessionsFinal = true;
    for (auto &session : impl_->sessions) {
        impl_->querySession(*session);
        eventsLost += session->eventsLost;
        buffersLost += session->buffersLost;
        cancelledTail = cancelledTail || session->cancelledTail;
        const bool sessionActive = session->controller != 0 && !session->finished.load();
        const bool countersFinal = session->controller == 0 && session->startResult == ERROR_SUCCESS &&
                                   session->queryResult == ERROR_SUCCESS;
        if (session->startResult == ERROR_SUCCESS) {
            anyStartedSession = true;
            allStartedSessionsFinal = allStartedSessionsFinal && countersFinal;
        }
        active = active || sessionActive;
        if (!session->kernel) manifestActive = manifestActive || sessionActive;
        if (session->kernel && session->controller && !session->finished.load()) syscallReady = true;
        sessions.append(QJsonObject{{"name", session->name}, {"systemLogger", session->kernel},
            {"active", session->controller != 0 && !session->finished.load()},
            {"startError", qint64(session->startResult)}, {"consumerOpenError", qint64(session->openResult)},
            {"consumerResult", qint64(session->processResult.load())}, {"eventsLost", qint64(session->eventsLost)},
            {"buffersLost", qint64(session->buffersLost)}, {"buffersWritten", qint64(session->buffersWritten)},
            {"counterQueryError", qint64(session->queryResult)}, {"counterQueryFileTime", QString::number(session->lastQuery)},
            {"lossCountersFinal", countersFinal},
            {"shutdownTailMayBeIncomplete", session->cancelledTail}});
    }
    std::lock_guard lock(impl_->data);
    impl_->pruneTargets();
    bool allProviders = manifestActive;
    for (const auto &provider : impl_->providers) {
        allProviders = allProviders && provider.result == ERROR_SUCCESS;
        providers.append(QJsonObject{{"name", provider.name}, {"guid", guidText(provider.guid)},
                                     {"category", provider.category}, {"enableError", qint64(provider.result)},
                                     {"observedSystemEvents", QString::number(provider.observed)}});
    }
    return {{"source", "windows_etw"}, {"running", active}, {"providers", providers},
            {"sessions", sessions}, {"profilePrivilegeEnabled", impl_->profilePrivilege},
            {"debugPrivilegeEnabled", impl_->debugPrivilege}, {"localKernelExportNames", qint64(impl_->syscallNames.size())},
            {"systemCallsRequested", impl_->requestedSyscalls}, {"systemCallsReady", syscallReady},
            {"allRequestedProvidersReady", allProviders}, {"completeAudit", false},
            {"eventsAccepted", QString::number(impl_->accepted)}, {"eventsIgnored", QString::number(impl_->ignored)},
            {"ambiguousEvents", QString::number(impl_->ambiguous)}, {"queueDropped", QString::number(impl_->queueDropped)},
            {"eventsLost", QString::number(eventsLost)}, {"buffersLost", QString::number(buffersLost)},
            {"decodeErrors", QString::number(impl_->decodeErrors)}, {"callbackErrors", QString::number(impl_->callbackErrors)},
            {"systemCallEvents", QString::number(impl_->syscallEvents)}, {"queuedRecords", qint64(impl_->queue.size())},
            {"unwatchDiscarded", QString::number(impl_->unwatchDiscarded)},
            {"historicalChildren", QString::number(impl_->historicalChildren)},
            {"contextSwitchEvents", QString::number(impl_->contextSwitches)},
            {"cpuOrderAmbiguous", QString::number(impl_->cpuOrderAmbiguous)},
            {"cpuContextResets", QString::number(impl_->cpuContextResets)},
            {"realtimeLostEventNotifications", QString::number(impl_->lostEventNotifications)},
            {"realtimeLostBufferNotifications", QString::number(impl_->lostBufferNotifications)},
            {"realtimeLostFileNotifications", QString::number(impl_->lostFileNotifications)},
            {"liveLossCountersProvisional", !anyStartedSession || !allStartedSessionsFinal},
            {"lossCountersFinal", anyStartedSession && allStartedSessionsFinal},
            {"pendingUnattributedSystemCalls", qint64(impl_->pendingCallCount)},
            {"pendingSystemCallThreads", qint64(impl_->pendingCalls.size())},
            {"pendingSystemCallsHighWater", QString::number(impl_->pendingCallHighWater)},
            {"pendingSystemCallBudget", 512 * 1024},
            {"pendingEvictionsMayIncludeOwnedTraffic", impl_->pendingCallEvicted != 0},
            {"foreignSystemCallsDiscarded", QString::number(impl_->foreignCallsDiscarded)},
            {"pendingUnattributedEvicted", QString::number(impl_->pendingCallEvicted)},
            {"pendingTargetRecords", qint64(impl_->pendingEvents.size())},
            {"pendingTargetDropped", QString::number(impl_->pendingEventDropped)},
            {"systemCallsReplayed", QString::number(impl_->replayedCalls)},
            {"queuedBytes", qint64(impl_->queuedBytes)}, {"shutdownTailMayBeIncomplete", cancelledTail},
            {"queueByteBudget", qint64(QueueBudget)}, {"queueRecordBudget", qint64(QueueRecords)},
            {"coverage", "Passive OS WMI, kernel file/registry/network/process providers; optional kernel system-call entry/address and exit/status, without arguments"},
            {"limitations", "ETW providers may omit operations; buffers or consumer queue can lose events. Unattributable service activity is discarded. Syscall arguments are unavailable; names resolve only for exact exported addresses in the installed kernel. Events are filtered by owned process/job and creation-time proof. No universal completeness guarantee."}};
}
}
