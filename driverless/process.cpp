#include "driverless/process.h"
#include <psapi.h>
#include <array>
#include <shellapi.h>

namespace nb {
namespace {
struct LaunchObserver {
    std::function<void(HANDLE, HANDLE)> *callback;
    HANDLE job;
    std::exception_ptr error;
};
BOOL WINAPI registerObserver(void *context, const PROCESS_INFORMATION *process) noexcept {
    auto &observer = *static_cast<LaunchObserver *>(context);
    try {
        if (*observer.callback) (*observer.callback)(process->hProcess, observer.job);
        return TRUE;
    } catch (...) {
        observer.error = std::current_exception();
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }
}
}
QString quoteArgument(const QString &argument) {
    QString result = "\"";
    int backslashes = 0;
    for (QChar character : argument) {
        if (character == '\\') {
            ++backslashes;
            continue;
        }
        if (character == '"')
            result += QString(backslashes * 2 + 1, '\\') + '"';
        else
            result += QString(backslashes, '\\') + character;
        backslashes = 0;
    }
    return result + QString(backslashes * 2, '\\') + '"';
}
QStringList parseArguments(const QString &arguments) {
    if (arguments.contains(QChar(0)) || arguments.size() > 32750)
        fail("argument", "Invalid Windows argument string");
    auto command = ("nativebox " + arguments).toStdWString();
    int count = 0;
    auto values = CommandLineToArgvW(command.c_str(), &count);
    wincheck(values != nullptr, "Parse Windows arguments");
    auto release = qScopeGuard([&] { LocalFree(values); });
    QStringList result;
    for (int index = 1; index < count; ++index)
        result.append(QString::fromWCharArray(values[index]));
    return result;
}
RuntimeSession::RuntimeSession(const QString &executable, const QStringList &arguments,
                               const QString &directory, const runtime::Configuration *configuration,
                               const QString &runtimeLibrary, const QString &runtimeSha256,
                               std::function<void(HANDLE, HANDLE)> beforeResume)
    : job_(CreateJobObjectW(nullptr, nullptr)) {
    wincheck(bool(job_), "Create application job");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    wincheck(SetInformationJobObject(job_.get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
             "Configure application job");
    QString command = quoteArgument(QDir::toNativeSeparators(executable));
    for (const auto &argument : arguments) {
        if (argument.contains(QChar(0)))
            fail("argument", "NUL in process argument");
        command += ' ' + quoteArgument(argument);
    }
    if (command.size() > 32766)
        fail("argument", "Windows command line exceeds the limit");
    auto nativeExecutable = QDir::toNativeSeparators(executable).toStdWString();
    auto nativeDirectory = QDir::toNativeSeparators(directory).toStdWString();
    auto nativeCommand = command.toStdWString();
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    if (!size)
        fail("job", "Cannot size launch attributes");
    QByteArray storage(qsizetype(size), Qt::Uninitialized);
    auto attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    wincheck(InitializeProcThreadAttributeList(attributes, 1, 0, &size), "Initialize launch attributes");
    auto release = qScopeGuard([&] { DeleteProcThreadAttributeList(attributes); });
    HANDLE ownedJob = job_.get();
    wincheck(UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &ownedJob,
                                       sizeof(ownedJob), nullptr, nullptr),
             "Assign owned job before execution");
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attributes;
    PROCESS_INFORMATION info{};
    LaunchObserver observer{&beforeResume, job_.get(), {}};
    if (configuration) {
        rejectReparse(runtimeLibrary);
        auto libraryPath = QDir::toNativeSeparators(runtimeLibrary).toStdWString();
        Handle libraryPin(CreateFileW(libraryPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        wincheck(bool(libraryPin), "Pin runtime module before controlled launch");
        if (digest(runtimeLibrary) != runtimeSha256)
            fail("runtime_integrity", "Runtime module changed after preflight");
        HMODULE library = LoadLibraryExW(libraryPath.c_str(), nullptr,
                                         LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        wincheck(library != nullptr, "Load instrumented process bootstrap");
        auto unload = qScopeGuard([&] { FreeLibrary(library); });
        auto launch = reinterpret_cast<BOOL(WINAPI *)(const runtime::Launch *)>(
            GetProcAddress(library, "NativeBoxLaunchW"));
        if (!launch)
            fail("runtime_version", "Runtime does not export the required launch ABI");
        STARTUPINFOW basic{};
        basic.cb = sizeof(basic);
        runtime::Launch request{.configuration = configuration,
                                .application = nativeExecutable.c_str(),
                                .commandLine = nativeCommand.data(),
                                .directory = nativeDirectory.c_str(),
                                .job = job_.get(),
                                .startup = &basic,
                                .process = &info,
                                .observerContext = &observer,
                                .beforeResume = beforeResume ? registerObserver : nullptr};
        const auto launched = launch(&request);
        if (observer.error) std::rethrow_exception(observer.error);
        wincheck(launched, "Initialize runtime before target entry without fallback");
        runtimeAttached_ = true;
        runId_ = QString::fromWCharArray(configuration->runId);
    } else
        wincheck(CreateProcessW(nativeExecutable.c_str(), nativeCommand.data(), nullptr, nullptr, FALSE,
                                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, nullptr,
                                nativeDirectory.c_str(), &startup.StartupInfo, &info),
                 "Create application");
    process_ = Handle(info.hProcess);
    Handle thread(info.hThread);
    pid_ = info.dwProcessId;
    auto rollback = qScopeGuard([&] {
        TerminateJobObject(job_.get(), 1);
        WaitForSingleObject(process_.get(), 5000);
    });
    BOOL member = FALSE;
    wincheck(IsProcessInJob(process_.get(), job_.get(), &member) && member, "Verify owned application job");
    FILETIME exit{}, kernel{}, user{};
    wincheck(GetProcessTimes(process_.get(), &creation_, &exit, &kernel, &user),
             "Capture process creation identity");
    if (!runtimeAttached_) {
        if (beforeResume) beforeResume(process_.get(), job_.get());
        wincheck(ResumeThread(thread.get()) != DWORD(-1), "Start application");
    }
    rollback.dismiss();
}
bool RuntimeSession::active() const {
    return activeCount() != 0;
}
DWORD RuntimeSession::activeCount() const {
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information{};
    wincheck(QueryInformationJobObject(job_.get(), JobObjectBasicAccountingInformation, &information,
                                       sizeof(information), nullptr),
             "Read application accounting");
    return information.ActiveProcesses;
}
QJsonObject RuntimeSession::status() const {
    DWORD code = STILL_ACTIVE;
    wincheck(GetExitCodeProcess(process_.get(), &code), "Read application exit status");
    QJsonObject result{{"pid", qint64(pid_)},
                       {"creationTime",
                        QString::number((quint64(creation_.dwHighDateTime) << 32) | creation_.dwLowDateTime)},
                       {"active", active()},
                       {"activeProcessCount", qint64(activeCount())},
                       {"rootExitCode", qint64(code)},
                       {"runtimeAttached", runtimeAttached_},
                       {"runId", runId_},
                       {"identitySource", "owned_process_handle_and_creation_time"}};
    QJsonObject metrics{{"scope", "owned root process only"}};
    PROCESS_MEMORY_COUNTERS_EX memory{};
    memory.cb = sizeof(memory);
    if (K32GetProcessMemoryInfo(process_.get(), reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&memory),
                                sizeof(memory))) {
        metrics["privateBytes"] = qint64(memory.PrivateUsage);
        metrics["workingSetBytes"] = qint64(memory.WorkingSetSize);
    }
    DWORD handles = 0;
    if (GetProcessHandleCount(process_.get(), &handles))
        metrics["handles"] = qint64(handles);
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (GetProcessTimes(process_.get(), &creation, &exit, &kernel, &user)) {
        metrics["kernelTime100ns"] =
            QString::number((quint64(kernel.dwHighDateTime) << 32) | kernel.dwLowDateTime);
        metrics["userTime100ns"] = QString::number((quint64(user.dwHighDateTime) << 32) | user.dwLowDateTime);
    }
    result["metrics"] = metrics;
    QJsonArray modules;
    DWORD required = 0;
    std::array<HMODULE, 512> values{};
    bool live = WaitForSingleObject(process_.get(), 0) == WAIT_TIMEOUT;
    bool observed = live && K32EnumProcessModulesEx(process_.get(), values.data(), DWORD(sizeof(values)),
                                                    &required, LIST_MODULES_ALL);
    qsizetype moduleCharacters = 0;
    bool truncated = required > sizeof(values);
    if (observed)
        for (DWORD index = 0; index < qMin(required / DWORD(sizeof(HMODULE)), DWORD(values.size()));
             ++index) {
            std::array<wchar_t, 32768> path{};
            DWORD count =
                K32GetModuleFileNameExW(process_.get(), values[index], path.data(), DWORD(path.size()));
            if (moduleCharacters + count > 32768) {
                truncated = true;
                break;
            }
            if (count && count < path.size()) {
                modules.append(QString::fromWCharArray(path.data(), int(count)));
                moduleCharacters += count;
            }
        }
    result["modules"] = modules;
    result["moduleObservation"] = QJsonObject{{"source", "owned_root_process_handle"},
                                              {"available", observed},
                                              {"truncated", truncated},
                                              {"scope", "root only, while alive"}};
    return result;
}
void RuntimeSession::stop() {
    wincheck(TerminateJobObject(job_.get(), 0), "Stop owned application tree");
}
}
