#include <Cli.hpp>
#include <filesystem>
#include <iostream>
#include <limits>
#include <string>
#include <cstdlib>

namespace Cli {

namespace {

#ifndef _WIN32
std::string ShellQuote(const std::string& value) {
    std::string result = "'";
    for (const char character : value) {
        if (character == '\'') result += "'\\''";
        else result += character;
    }
    return result + '\'';
}
#endif

}

int Autorun(const std::string& absPath, bool toWindows, const std::string& launcherPath) {
    if (!toWindows && launcherPath.empty()) {
        std::filesystem::permissions(absPath,
            std::filesystem::perms::owner_exec |
            std::filesystem::perms::group_exec |
            std::filesystem::perms::others_exec,
            std::filesystem::perm_options::add);
    }

#ifdef _WIN32
    const std::string cmd = launcherPath.empty() ? "\"" + absPath + "\"" : "\"" + launcherPath + "\" \"" + absPath + "\"";
#else
    const std::string cmd = launcherPath.empty() ? ShellQuote(absPath) : ShellQuote(launcherPath) + " " + ShellQuote(absPath);
#endif
    const int rawCode = std::system(cmd.c_str());

    int exitCode = rawCode;
#ifdef _WIN32
    std::cout << "\nExit code: " << rawCode << '\n';
#else
    if (rawCode != -1) {
        const int signal = rawCode & 0x7F;
        exitCode = signal ? 128 + signal : (rawCode >> 8) & 0xFF;
    }
    std::cout << "\nRaw exit code: " << rawCode << "; Unpacked: " << exitCode << '\n';
#endif

    std::cout << "\nPress Enter to exit...\n";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    return exitCode;
}

}
