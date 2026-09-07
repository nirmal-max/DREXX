#include "forensic/acquire.hpp"
#include "forensic/sha256.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

namespace forensic {

bool acquire_file(const std::string& src,
                  const std::string& dst,
                  std::uint64_t& size,
                  std::string& e) {
    namespace fs = std::filesystem;
    size = 0;

    std::error_code ec;
    const auto source = fs::weakly_canonical(src, ec);
    if (ec) {
        e = "cannot resolve source path";
        return false;
    }

    const auto destination = fs::weakly_canonical(dst, ec);
    if (!ec && source == destination) {
        e = "source and evidence destination resolve to the same path";
        return false;
    }

    std::ifstream in(src, std::ios::binary);
    if (!in) {
        e = "cannot open source read-only";
        return false;
    }

    const fs::path final_path(dst);
    const fs::path parent = final_path.has_parent_path()
        ? final_path.parent_path()
        : fs::current_path();

    fs::create_directories(parent, ec);
    if (ec) {
        e = "cannot create evidence directory";
        return false;
    }

    const auto nonce = static_cast<unsigned long long>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count());
    const fs::path temp_path = parent /
        (final_path.filename().string() + ".tmp-" + std::to_string(nonce));

    std::ofstream out(temp_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        e = "cannot create temporary evidence copy";
        return false;
    }

    char buf[1024 * 1024];
    while (in) {
        in.read(buf, sizeof(buf));
        const auto n = in.gcount();
        if (n > 0) {
            out.write(buf, n);
            if (!out) {
                out.close();
                fs::remove(temp_path, ec);
                e = "evidence write error";
                return false;
            }
            size += static_cast<std::uint64_t>(n);
        }
        if (in.bad()) {
            out.close();
            fs::remove(temp_path, ec);
            e = "source read error";
            return false;
        }
    }

    out.flush();
    if (!out) {
        out.close();
        fs::remove(temp_path, ec);
        e = "evidence flush error";
        return false;
    }
    out.close();

    const auto written_size = fs::file_size(temp_path, ec);
    if (ec || written_size != size) {
        fs::remove(temp_path, ec);
        e = "temporary evidence size verification failed";
        return false;
    }

    fs::rename(temp_path, final_path, ec);
    if (ec) {
        fs::remove(temp_path, ec);
        e = "cannot commit evidence copy";
        return false;
    }

    return true;
}

HashResult hash_file(const std::string& p) {
    HashResult r{};
    std::string e;
    r.sha256 = sha256_file(p, r.size, e);
    r.ok = e.empty();
    return r;
}

}
