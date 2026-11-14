#include "driverless/audit_export.h"
#include "driverless/common.h"
#include <algorithm>
#include <limits>
#include <optional>
#include <vector>

namespace nb {
namespace {
constexpr DWORD ChunkSize = 1024 * 1024;

[[noreturn]] void exportError(const QString &message) {
    fail("audit_export", message);
}
void checked(bool success, const QString &operation) {
    if (!success) exportError(operation + " (Win32 " + QString::number(GetLastError()) + ')');
}
QString cleanLocal(const QString &input) {
    auto path = privatePath(input);
    const auto original = QDir::fromNativeSeparators(input);
    // Do not silently normalize an unsafe input into a different permitted destination.
    for (const auto &part : original.mid(3).split('/')) {
        if (part == "." || part == ".." || part.endsWith('.') || part.endsWith(' '))
            exportError("Journal paths cannot contain dot components or trailing dots/spaces");
        const auto device = part.section('.', 0, 0).toUpper();
        static const QRegularExpression devices("^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$");
        if (devices.match(device).hasMatch()) exportError("Journal paths cannot name DOS devices");
    }
    if (path.size() == 3) exportError("Journal storage/destination cannot be a drive root");
    return path;
}
std::wstring physical(const QString &path) {
    return ("\\\\?\\" + QDir::toNativeSeparators(path)).toStdWString();
}
QString finalPath(HANDLE file) {
    const auto needed = GetFinalPathNameByHandleW(file, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    checked(needed != 0, "Resolve pinned journal path");
    std::wstring buffer(size_t(needed) + 1, L'\0');
    const auto length = GetFinalPathNameByHandleW(file, buffer.data(), DWORD(buffer.size()),
                                                 FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    checked(length && length < buffer.size(), "Resolve pinned journal path");
    auto value = QString::fromWCharArray(buffer.data(), int(length));
    value.replace('\\', '/');
    if (!value.startsWith("//?/") || value.size() < 7 || value[5] != ':')
        exportError("Journal export requires a local drive path: " + value);
    return QDir::cleanPath(value.mid(4));
}
bool beneath(const QString &path, const QString &base) {
    return path.compare(base, Qt::CaseInsensitive) == 0 ||
           path.startsWith(base + '/', Qt::CaseInsensitive);
}
BY_HANDLE_FILE_INFORMATION information(HANDLE file) {
    BY_HANDLE_FILE_INFORMATION result{};
    checked(GetFileInformationByHandle(file, &result), "Inspect pinned journal file");
    if (result.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        exportError("Journal export cannot traverse a reparse point");
    return result;
}
bool sameIdentity(const BY_HANDLE_FILE_INFORMATION &left, const BY_HANDLE_FILE_INFORMATION &right) {
    return left.dwVolumeSerialNumber == right.dwVolumeSerialNumber &&
           left.nFileIndexHigh == right.nFileIndexHigh && left.nFileIndexLow == right.nFileIndexLow;
}
quint64 sizeOf(const BY_HANDLE_FILE_INFORMATION &info) {
    return (quint64(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
}
QString identityOf(const BY_HANDLE_FILE_INFORMATION &info) {
    return QString::number(info.dwVolumeSerialNumber, 16) + ':' +
           QString::number((quint64(info.nFileIndexHigh) << 32) | info.nFileIndexLow, 16);
}

// Denying FILE_SHARE_DELETE on every ancestor prevents replacement/rename of a pinned tree.
// FILE_SHARE_WRITE permits the existing append-only runtime/ETW writers to continue normally.
QString pinDirectories(const QString &path, std::vector<Handle> &pins) {
    QString current = path.left(3);
    auto pin = [&](const QString &part) {
        Handle file(CreateFileW(physical(part).c_str(), FILE_READ_ATTRIBUTES,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        checked(bool(file), "Pin journal directory " + part);
        const auto info = information(file.get());
        if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            exportError("A journal ancestor is not a directory");
        auto resolved = finalPath(file.get());
        pins.push_back(std::move(file));
        return resolved;
    };
    auto resolved = pin(current);
    for (const auto &part : path.mid(3).split('/', Qt::SkipEmptyParts)) {
        current = QDir(current).filePath(part);
        resolved = pin(current);
    }
    return resolved;
}

struct Source {
    QString path, relative, resolved, snapshotUtc;
    Handle file;
    BY_HANDLE_FILE_INFORMATION identity{};
    quint64 bytes = 0;
};
void snapshotDirectory(const QString &sandboxRoot, const QString &name, std::vector<Handle> &pins,
                       std::vector<Source> &sources) {
    const auto directory = sandboxRoot + '/' + name;
    const auto attributes = GetFileAttributesW(physical(directory).c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const auto error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return;
        SetLastError(error);
        checked(false, "Inspect journal source directory");
    }
    pinDirectories(directory, pins);
    WIN32_FIND_DATAW entry{};
    auto search = FindFirstFileExW(physical(directory + "/*.jsonl").c_str(), FindExInfoBasic,
                                   &entry, FindExSearchNameMatch, nullptr, 0);
    if (search == INVALID_HANDLE_VALUE) {
        const auto error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND) return;
        SetLastError(error);
        checked(false, "Enumerate journal source files");
    }
    auto release = qScopeGuard([&] { FindClose(search); });
    std::vector<QString> names;
    do {
        const auto filename = QString::fromWCharArray(entry.cFileName);
        if (entry.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
            exportError("A journal source is a directory or reparse point");
        if (filename.contains('/') || filename.contains('\\') || filename.contains(':'))
            exportError("Unsafe journal source filename");
        names.push_back(filename);
    } while (FindNextFileW(search, &entry));
    checked(GetLastError() == ERROR_NO_MORE_FILES, "Enumerate complete journal source list");
    std::sort(names.begin(), names.end(), [](const QString &left, const QString &right) {
        return left.compare(right, Qt::CaseSensitive) < 0;
    });
    for (const auto &filename : names) {
        Source source;
        source.relative = name + '/' + filename;
        source.path = directory + '/' + filename;
        source.file = Handle(CreateFileW(physical(source.path).c_str(), GENERIC_READ,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                                        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
        checked(bool(source.file), "Pin journal source " + source.relative);
        source.identity = information(source.file.get());
        if (source.identity.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            exportError("Journal source must be a regular file");
        source.resolved = finalPath(source.file.get());
        if (!beneath(source.resolved, sandboxRoot + '/' + name))
            exportError("Pinned journal source escaped its archive directory");
        source.bytes = sizeOf(source.identity);
        source.snapshotUtc = now();
        sources.push_back(std::move(source));
    }
}

void seek(HANDLE file, quint64 offset) {
    if (offset > quint64(std::numeric_limits<LONGLONG>::max())) exportError("Journal exceeds addressable file size");
    LARGE_INTEGER position{};
    position.QuadPart = LONGLONG(offset);
    checked(SetFilePointerEx(file, position, nullptr, FILE_BEGIN), "Seek pinned journal source");
}
DWORD readSome(HANDLE file, char *buffer, DWORD requested) {
    DWORD count = 0;
    checked(ReadFile(file, buffer, requested, &count, nullptr), "Read pinned journal source");
    if (count == 0 && requested) exportError("Journal source was truncated after its size snapshot");
    return count;
}
quint64 completeBytes(const Source &source, QByteArray &buffer) {
    quint64 end = source.bytes;
    while (end) {
        const auto start = end > ChunkSize ? end - ChunkSize : 0;
        seek(source.file.get(), start);
        const auto requested = DWORD(end - start);
        DWORD received = 0;
        while (received < requested)
            received += readSome(source.file.get(), buffer.data() + received, requested - received);
        for (DWORD index = requested; index > 0; --index)
            if (buffer[int(index - 1)] == '\n') return start + index;
        end = start;
    }
    return 0;
}
void verifySource(const Source &source) {
    const auto current = information(source.file.get());
    if (!sameIdentity(current, source.identity) || sizeOf(current) < source.bytes ||
        finalPath(source.file.get()).compare(source.resolved, Qt::CaseInsensitive))
        exportError("Pinned journal identity/path changed or the source was truncated");
}
}

QJsonObject exportJournal(QString storageRoot, QString sandbox, QString destination) {
    sandbox = validateId(sandbox);
    storageRoot = cleanLocal(storageRoot);
    destination = cleanLocal(destination);
    if (beneath(destination, storageRoot)) exportError("Export destination must be outside private storage");
    std::vector<Handle> directories;
    storageRoot = pinDirectories(storageRoot, directories);
    const auto sandboxRoot = pinDirectories(storageRoot + "/driverless/sandboxes/" + sandbox, directories);
    if (!beneath(sandboxRoot, storageRoot)) exportError("Sandbox source escaped private storage");
    const auto parent = pinDirectories(QFileInfo(destination).absolutePath(), directories);
    destination = parent + '/' + QFileInfo(destination).fileName();
    if (beneath(destination, storageRoot)) exportError("Resolved export destination is inside private storage");

    const auto planStartedUtc = now();
    std::vector<Source> sources;
    snapshotDirectory(sandboxRoot, "telemetry", directories, sources);
    snapshotDirectory(sandboxRoot, "audit", directories, sources);
    const auto planCompletedUtc = now();
    quint64 sourceBytes = 0;
    for (const auto &source : sources) sourceBytes += source.bytes;

    // Inspect existing destinations without following a reparse point. QSaveFile later replaces
    // the directory entry atomically and never falls back to truncating that existing file.
    auto destinationIdentity = [&]() -> std::optional<BY_HANDLE_FILE_INFORMATION> {
        Handle existing(CreateFileW(physical(destination).c_str(), FILE_READ_ATTRIBUTES,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                    FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!existing) {
            const auto error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND) return std::nullopt;
            SetLastError(error);
            checked(false, "Inspect journal destination");
        }
        const auto info = information(existing.get());
        if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) exportError("Export destination is a directory");
        if (beneath(finalPath(existing.get()), storageRoot)) exportError("Destination resolves into private storage");
        for (const auto &source : sources)
            if (sameIdentity(info, source.identity)) exportError("Destination aliases a journal source file");
        return info;
    };
    const auto priorDestination = destinationIdentity();
    QSaveFile output(destination);
    output.setDirectWriteFallback(false);
    if (!output.open(QIODevice::WriteOnly)) exportError("Cannot open atomic journal export: " + output.errorString());
    QByteArray buffer(ChunkSize, Qt::Uninitialized);
    QCryptographicHash hash(QCryptographicHash::Sha256);
    quint64 bytes = 0, rows = 0, fragments = 0, fragmentBytes = 0;
    QJsonArray files;
    for (const auto &source : sources) {
        verifySource(source);
        const auto boundary = completeBytes(source, buffer);
        seek(source.file.get(), 0);
        quint64 copied = 0, fileRows = 0;
        while (copied < boundary) {
            const auto count = readSome(source.file.get(), buffer.data(), DWORD(std::min<quint64>(ChunkSize, boundary - copied)));
            if (output.write(buffer.constData(), count) != count) exportError("Incomplete atomic journal write: " + output.errorString());
            hash.addData(QByteArrayView(buffer.constData(), count));
            fileRows += quint64(std::count(buffer.constData(), buffer.constData() + count, '\n'));
            copied += count;
        }
        verifySource(source);
        const auto partial = source.bytes - boundary;
        bytes += copied;
        rows += fileRows;
        fragments += partial != 0;
        fragmentBytes += partial;
        files.append(QJsonObject{{"source", source.relative}, {"identity", identityOf(source.identity)},
                                 {"snapshotUtc", source.snapshotUtc}, {"sourceBytes", qint64(source.bytes)},
                                 {"bytes", qint64(copied)}, {"rows", qint64(fileRows)},
                                 {"partialFragmentBytes", qint64(partial)}});
    }
    const auto currentDestination = destinationIdentity();
    if (priorDestination.has_value() != currentDestination.has_value() ||
        (priorDestination && !sameIdentity(*priorDestination, *currentDestination)))
        exportError("Destination changed while exporting; the original destination was preserved");
    if (!output.commit()) exportError("Atomic journal commit failed: " + output.errorString());
    return {{"ok", true}, {"sandbox", sandbox}, {"destination", destination}, {"format", "raw_jsonl"},
            {"sourcePolicy", "all_complete_rows_preserved_verbatim_including_invalid_json"},
            {"order", "telemetry_then_audit_filename_order"}, {"planStartedUtc", planStartedUtc},
            {"planCompletedUtc", planCompletedUtc}, {"completedUtc", now()}, {"files", files},
            {"fileCount", qint64(sources.size())}, {"sourceBytes", qint64(sourceBytes)},
            {"bytes", qint64(bytes)}, {"rows", qint64(rows)}, {"partialFragments", qint64(fragments)},
            {"partialFragmentBytes", qint64(fragmentBytes)}, {"sha256", QString::fromLatin1(hash.result().toHex())},
            {"memoryBufferBytes", qint64(ChunkSize)}, {"snapshot", "per_file_size_before_copy_append_only_writers"}};
}
}
