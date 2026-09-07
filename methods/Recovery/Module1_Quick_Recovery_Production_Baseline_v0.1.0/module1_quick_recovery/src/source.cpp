#include "quick/source.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <array>
#include <cstring>
#include <limits>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace quick {

class FileSource final : public ISource {
    std::ifstream f_;
    std::uint64_t size_{};
    std::string identity_;
public:
    explicit FileSource(const std::string& path, std::string& error) {
        f_.open(path, std::ios::binary);
        if (!f_) { error = "cannot open source: " + path; return; }
        f_.seekg(0, std::ios::end);
        auto p = f_.tellg();
        if (p < 0) { error = "cannot determine source size"; return; }
        size_ = static_cast<std::uint64_t>(p);
        f_.seekg(0, std::ios::beg);
        identity_ = path + ":" + std::to_string(size_);
    }
    bool read_at(std::uint64_t offset, std::span<std::byte> out) override {
        if (offset > size_ || out.size() > size_ - offset) return false;
        f_.clear();
        f_.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        if (!f_) return false;
        f_.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
        return f_.good() || f_.gcount() == static_cast<std::streamsize>(out.size());
    }
    std::uint64_t size() const override { return size_; }
    std::string identity() const override { return identity_; }
};

#ifdef _WIN32
class PhysicalDeviceSource final : public ISource {
    HANDLE h_{INVALID_HANDLE_VALUE};
    std::uint64_t size_{};
    std::string identity_;
public:
    explicit PhysicalDeviceSource(const std::string& path, std::string& error) {
        h_ = CreateFileA(path.c_str(), GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         nullptr, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, nullptr);
        if (h_ == INVALID_HANDLE_VALUE) { error = "cannot open physical device read-only"; return; }
        GET_LENGTH_INFORMATION li{};
        DWORD got = 0;
        if (!DeviceIoControl(h_, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0, &li, sizeof(li), &got, nullptr)) {
            error = "cannot query physical device size"; CloseHandle(h_); h_ = INVALID_HANDLE_VALUE; return;
        }
        size_ = static_cast<std::uint64_t>(li.Length.QuadPart);
        identity_ = path + ":" + std::to_string(size_);
    }
    ~PhysicalDeviceSource() override { if (h_ != INVALID_HANDLE_VALUE) CloseHandle(h_); }
    bool read_at(std::uint64_t offset, std::span<std::byte> out) override {
        if (offset > size_ || out.size() > size_ - offset) return false;
        if (out.empty()) return true;

        LARGE_INTEGER li{};
        li.QuadPart = static_cast<LONGLONG>(offset);
        if (!SetFilePointerEx(h_, li, nullptr, FILE_BEGIN)) return false;

        constexpr std::size_t kMaxRead = static_cast<std::size_t>(std::numeric_limits<DWORD>::max());
        std::size_t done = 0;
        while (done < out.size()) {
            const std::size_t remaining = out.size() - done;
            const DWORD request = static_cast<DWORD>(remaining > kMaxRead ? kMaxRead : remaining);
            DWORD got = 0;
            if (!ReadFile(h_, out.data() + done, request, &got, nullptr) || got != request) return false;
            done += got;
        }
        return true;
    }
    std::uint64_t size() const override { return size_; }
    std::string identity() const override { return identity_; }
};
#endif

std::unique_ptr<ISource> open_source(const std::string& path, std::string& error) {
#ifdef _WIN32
    if (path.rfind(R"(\\.\PhysicalDrive)", 0) == 0) {
        auto p = std::make_unique<PhysicalDeviceSource>(path, error);
        if (!error.empty()) return {};
        return p;
    }
#endif
    auto p = std::make_unique<FileSource>(path, error);
    if (!error.empty()) return {};
    return p;
}

bool read_exact(ISource& src, std::uint64_t offset, std::vector<std::byte>& out) {
    return src.read_at(offset, std::span<std::byte>(out.data(), out.size()));
}

} // namespace quick
