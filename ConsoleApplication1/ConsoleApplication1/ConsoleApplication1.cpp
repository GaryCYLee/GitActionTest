﻿// ConsoleApplication1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <tchar.h>
#include <fstream>
#include <time.h>
#include <list>
#include <unordered_set>
#include <filesystem>
#include <iostream>
#include <functional>
#include <Shlwapi.h>
#include "libXLogRProto.h"

using namespace std;
namespace fs = filesystem;

const string currentDateTime() {
    time_t     now = time(0);
    struct tm  tstruct;
    char       buf[80];
    localtime_s(&tstruct, &now);
    strftime(buf, sizeof(buf), "%Y-%m-%d.%X ", &tstruct);

    return buf;
}

typedef struct _DRIVER_PROTECTED_ITEM
{
    ULONG ulType;
    wstring wstrPath;
} DRIVER_PROTECTED_ITEM, * PDRIVER_PROTECTED_ITEM;

DWORD WINAPI ThreadFunc(LPVOID pParam) {
    TCHAR* filename = (TCHAR*)pParam;
    wstring strFile = &filename[0];
    //Sleep(20000);

    return 0;
}


// Recursively copies all files and folders from src to target and overwrites existing files in target.
void CopyRecursive(const fs::path& src, const fs::path& target) noexcept
{
    try
    {
        fs::copy(src, target, fs::copy_options::overwrite_existing | fs::copy_options::recursive);
    }
    catch (exception& e)
    {
        cout << e.what();
    }
}

wstring ExePath() {
    TCHAR buffer[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, buffer, MAX_PATH);
    wstring::size_type pos = wstring(buffer).find_last_of(L"\\/");
    return wstring(buffer).substr(0, pos);
}

BOOL GetProcessPathByPID(DWORD dwPID, wstring& wstrProcessPath)
{
    BOOL bFound = FALSE;

    // Get process path by Windows API
    DWORD lastError = 0;
    if (!bFound)
    {
        if (dwPID == 4)
        {
            wstrProcessPath = L"system";
            bFound = TRUE;
        }
        else
        {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPID);
            if (hProcess != NULL)
            {
                wchar_t wszProcessImageFile[MAX_PATH] = { 0 };
                DWORD dwSize = _countof(wszProcessImageFile);
                if (QueryFullProcessImageName(hProcess, 0, wszProcessImageFile, &dwSize))
                {
                    bFound = TRUE;
                    wstrProcessPath = wszProcessImageFile;

                    
                }
                else
                {
                    lastError = GetLastError();
                }
                CloseHandle(hProcess);
            }
            else
            {
                lastError = GetLastError();
            }
        }
    }


    return bFound;
}

#include <fstream>
#include "json/json.h"
#include "curl/curl.h"

wstring s2ws(string s)
{
    int wideLen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring wideStr(wideLen, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &wideStr[0], wideLen);
    return wideStr;
}

string ws2s(wstring s)
{
    int mbLen = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string mbStr(mbLen, 0);
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, &mbStr[0], mbLen, nullptr, nullptr);
    return mbStr;
}

std::size_t callback(
    const char* in,
    std::size_t size,
    std::size_t num,
    std::string* out)
{
    const std::size_t totalBytes(size * num);
    out->append(in, totalBytes);
    return totalBytes;
}

void getScriptFromAzureTest(Json::Value& responsebody, Json::Value requestbody) {

    int ret = 0;
    CURL* curl;
    CURLcode res;
    Json::Value  resjson;
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();

    char szJsonData[1024];
    memset(szJsonData, 0, sizeof(szJsonData));

    std::string szjsonoutput = requestbody.toStyledString();
    cout << "[XBC_Integration] request body = " << szjsonoutput;

    if (curl)
    {
        std::unique_ptr<std::string> httpData(new std::string());

        string url = "https://scriptserver20230412102200.azurewebsites.net/api/makescript";
        //string url = "https://scriptserver20230412102200.azurewebsites.net/api/MakeScriptTest";

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "x-functions-key: 9XFnAPwfkmMah2P03EGntqS-Abu9pNBEPupwVXqLVla6AzFu60u2LA==");
        //headers = curl_slist_append(headers, "x-functions-key: l2xRGIjYIicJUQLAv3igPVwwGPogdIvwZwcihWo7ewsbAzFuJwWulw==");
        headers = curl_slist_append(headers, "charsets: utf-8");

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, szjsonoutput.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);


        res = curl_easy_perform(curl);

        if (res == CURLE_OK)
        {
            cout << "[XBC_Integration] CURL OK!";
            Json::Reader jReader;

            cout << res << endl;

            string retTemp = (*httpData.get()).c_str();

            cout << retTemp << endl;

            if (jReader.parse(retTemp, resjson)) {

                cout << "[XBC_Integration] response = " << resjson.toStyledString() << endl;
                const int errorcode = stoi(resjson["errorcode"].asString());
                const std::string errordescription = resjson["errordescription"].asString();
                if (errorcode != 200)
                    cout << "[XBC_Integration] script server internal error = " << errordescription << endl;
                else
                    responsebody = resjson["data"];
            }
            else {
                wcout << "[XBC_Integration] response json went wrong" << endl;
            }
        }
        else {
            wcout << "[XBC_Integration] CURL failed, res = " << res << endl;

        }
        curl_easy_cleanup(curl);
        curl_global_cleanup();

    }
}
#include <wincrypt.h>

int atat(char* s)
{
    string s2 = s;
    return 0;
}

#define REGHEADER 		L"SOFTWARE\\TrendMicro\\PC-cillinNTCorp\\CurrentVersion"
#define REG32(X) (X | KEY_WOW64_32KEY)
BOOL rtGetRegistryKeyValue(LPCTSTR szKey, LPCTSTR szValue, DWORD* pdwValue)
{
    HKEY	hKey;
    DWORD	dw, dwType, dwValue = 0;
    TCHAR	szKeyValue[MAX_PATH];
    BOOL	bRet = TRUE;

    if (szKey == NULL)
        _tcscpy_s(szKeyValue, _countof(szKeyValue), REGHEADER); // fix klocwork
    else
        wsprintf(szKeyValue, _T("%s\\%s"), REGHEADER, szKey);

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKeyValue, 0, REG32(KEY_READ), &hKey) == ERROR_SUCCESS)
    {
        dw = sizeof(DWORD);
        if (RegQueryValueEx(hKey, szValue, 0, &dwType, (BYTE*)&(dwValue), &dw) != ERROR_SUCCESS)
            //dwValue = 999;
            bRet = FALSE;
        RegCloseKey(hKey);
        hKey = 0;
    }
    // [SEGTT-133428] Migrating Servers
    // Leo Lee 2008/03/27
    // If RegOpenKeyEx failed, return FALSE
    // [SEGTT-133428] Begin
    else
    {
        bRet = FALSE;
    }
    // [SEGTT-133428] End

    //return dwValue;
    *pdwValue = dwValue;
    return bRet;
}
BOOL WINAPI rtGetRegistryKeyValue2(LPCTSTR szKey, LPCTSTR szValue, LPTSTR szBuf, int nLen)
{
    HKEY	hKey = NULL;
    DWORD	dw = 0, dwType = 0;
    TCHAR	szKeyValue[MAX_PATH] = { 0 };
    //char	szTmp[MAX_PATH];
    // [SEGTRK-68451] 2005/2/15 Edward Yu, Open tunnel of PFW
    TCHAR	szTmp[2048] = { 0 };
    BOOL	bRet = TRUE;

    *szBuf = _T('\0');
    dw = sizeof(szTmp);
    ZeroMemory(szTmp, dw);
    ZeroMemory(szKeyValue, sizeof(szKeyValue));

    if (szKey == NULL)
        wsprintf(szKeyValue, _T("%s"), REGHEADER);
    else
        wsprintf(szKeyValue, _T("%s\\%s"), REGHEADER, szKey);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKeyValue, 0, REG32(KEY_READ), &hKey) == ERROR_SUCCESS)
    {
        if (RegQueryValueEx(hKey, szValue, 0, &dwType, (BYTE*)&(szTmp), &dw) == ERROR_SUCCESS)
            lstrcpy(szBuf, szTmp);
        else
            bRet = FALSE;
        RegCloseKey(hKey);
        hKey = 0;
    }
    else
    {
        bRet = FALSE;
    }
    return bRet;
}
#define _REG_MISC_SERVER_ID_KEY_NAME			_T("ServerID")
#define _REG_MISC_SECTION_NAME                  _T("Misc.")
#define _REG_ICRC_INTERNAL_NON_CRC_PTN_VER			_T("InternalNonCrcPatternVer")
#pragma comment(lib, "crypt32.lib")
int main(int argc, char* argv[])
{
    Json::Value item;

    item["guid"] = Json::Value("00000000-0000-THIS-0is0-serverid0000");
    item["arch"] = Json::Value("x86");
    item["filename"] = Json::Value("agentX86.exe");
    item["dllink"] = Json::Value("http://123:8080/asd/aaa.exe");
    item["checksum"] = Json::Value("TESTWRITECHECKSUM!@#$%^&");
    item["instanceid"] = Json::Value("00000000-0000-THIS-0is0-instanceid00");

    Json::Value jsRoot;
    getScriptFromAzureTest(jsRoot, item);

    DWORD szRegPatternNumber;
    if (rtGetRegistryKeyValue(_REG_MISC_SECTION_NAME, _REG_ICRC_INTERNAL_NON_CRC_PTN_VER, &szRegPatternNumber))
    {
        wstring wstrRegPatternNumber = to_wstring(szRegPatternNumber);
    }
    else
    {
        wcout << L"0" << endl;
    }



    TCHAR szOFCScanINI[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, szOFCScanINI, MAX_PATH);
    std::wstring appDir = szOFCScanINI;
    appDir = appDir.substr(0, appDir.find_last_of(L"\\/")) + L"\\HLog\\A\\B\\C\\";
    std::wstring wstrFName = L"abc.txt";
    std::wstring wstrVirusJson = L"FUCKCKCKCK";
    std::wstring wstrVirusLogTemp = appDir + wstrFName;

    if (!fs::exists(appDir))
    {
        if (fs::create_directories(appDir))
        {
            std::cout << "A：" << std::endl;
        }
    }
    std::wofstream output_file(wstrVirusLogTemp);
    if (!output_file.is_open()) {
        return 0;
    }
    output_file.write(wstrVirusJson.c_str(), wstrVirusJson.size());
    output_file.close();





    TCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName) / sizeof(TCHAR);

    if (GetComputerNameW(computerName, &size))
    {
        std::wcout << "Computer Name: " << computerName << std::endl;
    }
    else
    {
        std::cerr << "Failed to get computer name. Error code: " << GetLastError() << std::endl;
    }


    TCHAR szRegServerID[256] = { 0 };
    rtGetRegistryKeyValue2(_REG_MISC_SECTION_NAME, _REG_MISC_SERVER_ID_KEY_NAME, szRegServerID, _countof(szRegServerID) - 1);
    wstring wstrProductGUID(szRegServerID);


    char szFile[MAX_PATH] = { 0 };
    szFile[0] = '0';
    szFile[1] = '1';
    szFile[2] = '2';
    atat(szFile);
    //const wchar_t* filePath = L"C:\\Users\\gary_cy_lee\\Desktop\\PDFs\\OfcPIPC_64x.dll";
    const wchar_t* filePath = L"C:\\Users\\gary_cy_lee\\Desktop\\PDFs\\TmListenShare_64x.dll";

    DWORD dwEncoding, dwContentType, dwFormatType;
    HCERTSTORE hCertStore = NULL;
    HCRYPTMSG hCryptMsg = NULL;
    const void* pvContext = NULL;

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0, &dwEncoding, &dwContentType, &dwFormatType, &hCertStore, &hCryptMsg, &pvContext)) {
        std::cout << "Failed to query object." << std::endl;
        return 1;
    }

    DWORD cbDecoded;
    if (dwContentType == CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED) {
        DWORD dwSignerInfoCount = 0;
        if (!CryptMsgGetParam(hCryptMsg, CMSG_SIGNER_COUNT_PARAM, 0, &dwSignerInfoCount, &cbDecoded)) {
            std::cout << "Failed to get signer count." << std::endl;
            CryptMsgClose(hCryptMsg);
            CertCloseStore(hCertStore, 0);
            return 1;
        }

        std::cout << "Number of signers: " << dwSignerInfoCount << std::endl;
    }
    else {
        std::cout << "The object is not a signed PKCS#7 file." << std::endl;
    }

    CryptMsgClose(hCryptMsg);
    CertCloseStore(hCertStore, 0);




    XLogRProto::Proto::get_ins().WriteBuf2File("00000000-0000-THIS-0is0-serverid0000");



    //TCHAR buffer[MAX_PATH];
    //GetModuleFileName(NULL, buffer, MAX_PATH);
    //std::wstring exePath(buffer);
    //std::wstring exeDir = exePath.substr(0, exePath.find_last_of(L"\\") + 1);
    //
    //std::wstring bPath = exeDir + L"endpointbasecamp.exe";
    //int retval3 = ::_tsystem(bPath.c_str());
    //
    //std::wstring aPath = exeDir + L"agent_cloud_x64.exe /s";
    //int retval4 = ::_tsystem(aPath.c_str());
    

    //ifstream ifs(argv[1], ifstream::in);
    //string tempstr;
    //string str;
    //while (getline(ifs, tempstr))
    //{
    //    str += tempstr;
    //    str += "\n";
    //}
    //cout << str << endl;
    //ifs.close();
    //
    //string tokentoreplace = argv[2];
    //string contenttoreplace = argv[3];
    //int pos = 0;
    //while (1) {
    //    pos = str.find(tokentoreplace, pos);
    //    if (pos == -1) break;
    //
    //    str.replace(pos, tokentoreplace.length(), contenttoreplace);
    //    pos += contenttoreplace.length();
    //}
    //cout << str << endl;
    //
    //ofstream ofs(argv[1]);
    //ofs << str;
    //ofs.close();
    //
    //string sssss = "Check";
    //if (sssss == "Check")
    //{
    //    int bbbbbb = 0;
    //}
    //wstring p = L"";
    //GetProcessPathByPID(16524, p);
    //
    //DWORD dwMatchedProcessType = 0;
    //wstring wstrProcessNameInLowerCase = PathFindFileName(p.c_str());
    //transform(wstrProcessNameInLowerCase.begin(), wstrProcessNameInLowerCase.end(), wstrProcessNameInLowerCase.begin(), ::towlower);
    ////wstring source = ExePath();
    ////source += L"\\Log";
    //wstring target = ExePath();
    ////target += L"\\Test";
    ////CopyRecursive(source, target);
    //
    //wstring cur_log_dir = L"C:\\Program Files (x86)\\Trend Micro\\Security Agent\\Temp\\LogServer\\Log";
    //wstring cur_log_dir_copy = target;
    //cur_log_dir_copy.append(L"\\CurrentLog");
    //CopyRecursive(cur_log_dir, cur_log_dir_copy);
    //
    //HANDLE hEvent = NULL;
    //hEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, _T("Global\\PccntupdStopService"));
    //
    //if (hEvent)
    //{
    //    ::SetEvent(hEvent);
    //    Sleep(5000);
    //    ::CloseHandle(hEvent);
    //}
    //
    //
    //int retval2 = ::_tsystem(_T("taskkill /F /T /IM ntrtscan.exe"));
    //int retval1 = ::_tsystem(_T("taskkill /F /T /IM tmlisten.exe"));
    //printf("123");
    //
    //
    //wstring strFile = L"C:\\Ntrtscan.exe";
    //TCHAR cmd[MAX_PATH];
    //swprintf_s(cmd, L"del /f %s", strFile.c_str());
    //int ret = _wsystem(cmd);

    //wstring strFile2 = L"ASDFG";
    //TCHAR pstrFile[MAX_PATH];
    //swprintf_s(pstrFile, L"del /f %s", strFile2.c_str());
    //
    //
    //HANDLE hThread = CreateThread(NULL, 0, ThreadFunc, (LPVOID)pstrFile, 0, NULL);
    //if (hThread) {
    //    DWORD dwRethInitLogServer = WaitForSingleObject(hThread, 10000);
    //    if (dwRethInitLogServer == WAIT_TIMEOUT)
    //    {
    //        wstring strFile123 = L"ASDFG";
    //    }
    //    CloseHandle(hThread);
    //}
    //
    //HANDLE hFile = CreateFile(L"C:\\Ntrtscan.exe", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL);
    //
    //CloseHandle(hFile);
    //wstring wstrTMicroDir = L"C:\\Program Files (x86)\\Trend Micro\\Security Agent\\";
    //wstrTMicroDir = wstrTMicroDir.substr(0, wstrTMicroDir.size() - 1);
    //wstrTMicroDir = wstrTMicroDir.substr(0, wstrTMicroDir.find_last_of(L"\\") + 1);
    //
    //wstring wstrSAgentDir = wstrTMicroDir + L"Security Agent";
    //wstring wstrBMDir = wstrTMicroDir + L"BM";
    //wstring wstriServiceDir = wstrTMicroDir + L"iService";
    //
    //
    //
    //wstring wwss = L"C:\\Program Files (x86)\\Trend Micro\\Security Agent\\";
    //wwss = wwss.substr(0, wwss.size() - 1);
    //wwss = wwss.substr(0, wwss.find_last_of(L"\\"));
    //
    //
    //wstring wstrClientDir = L"ABC\DEF";
    //wprintf(L"%s", wstrClientDir.c_str());
    //
    //unordered_set<wstring> s;
    //WCHAR szRegKey[MAX_PATH];
    //WCHAR szRegKey2[MAX_PATH];
    //WCHAR szRegKey3[MAX_PATH];
    //WCHAR szRegKey4[MAX_PATH];
    //swprintf_s(szRegKey, L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options");
    //swprintf_s(szRegKey2, L"HKLM\\SOFTWARE\\TrendMicro\\iACAgent\\");
    //swprintf_s(szRegKey3, L"HKLM\\SOFTWARE\\TrendMicro\\iACAgent\\*");
    //swprintf_s(szRegKey4, L"HKLM\\SOFTWARE\\Wow6432Node\\TrendMicro\\PC-cillinNTCorp\\*");
    //
    //wstring w1 = &szRegKey[0];
    //wstring w2 = &szRegKey2[0];
    //wstring w3 = &szRegKey3[0];
    //wstring w4 = &szRegKey4[0];
    //
    //if (w2.substr(w2.size() - 1) == L"\\")
    //{
    //    w2 = w2.substr(0, w2.size() - 1);
    //}
    //if (w3.substr(w3.size() - 1) == L"*")
    //{
    //    w3 = w3.substr(0, w3.size() - 2);
    //}
    //
    //s.insert(w1);
    //s.insert(w2);
    //s.insert(w3);
    //s.insert(w4);
    //s.insert(w4);
    //s.insert(w4);
    //s.insert(w4);
    //s.insert(w4);
    //s.insert(w4);
    //s.insert(w4);
    //
    //
    //list<DRIVER_PROTECTED_ITEM> m_listProtectedItems;
    //list<wstring> l;
    //for (unordered_set<wstring>::iterator itr = s.begin(); itr != s.end(); ++itr) {
    //
    //    m_listProtectedItems.push_back({ 4, *itr });
    //    wstring val = *itr;
    //    wprintf(L"%s", val.c_str());
    //    //wcout << " " << *itr;
    //}
    //
    //list<wstring> li;
    //li.push_back(L"ASD");
    //li.push_back(L"ASD");
    //
    //
    //wstring wstrDomainRba = L"530,536,533,554";
    //const WCHAR* wszSpyGrayReadOpID = L"531";
    //const WCHAR* wszSpyGrayWriteOpID = L"532";
    //
    //if (wstrDomainRba.find(wszSpyGrayReadOpID) != wstring::npos && wstrDomainRba.find(wszSpyGrayWriteOpID) != wstring::npos)
    //{
    //    int a = 0;
    //}
    //
    //
    //int a = 0;
    //a = (a << 1);
    //a = (a << 1);
    //a = (a << 1);
    //a = (a << 1);
    //
    //wstring wtrValue;
    //wtrValue = L"00";
    //if (wtrValue == L"00")
    //    wtrValue = L"0";
    //int nValue = _wtoi(wtrValue.c_str());
    //if (nValue == 0 && !wtrValue.empty() && wtrValue.compare(L"0") != 0)
    //{
    //    printf("123");
    //}
    //
    ////Service test
    //SC_HANDLE schSCManager;
    //// Open a handle to the SC Manager database...
    //schSCManager = OpenSCManager(
    //    NULL, // local machine
    //    NULL, // SERVICES_ACTIVE_DATABASE database is opened by default
    //    SC_MANAGER_ALL_ACCESS); // full access rights
    //
    //if (NULL == schSCManager)
    //    printf("OpenSCManager() failed, error: %d.\n", GetLastError());
    //else
    //    printf("OpenSCManager() looks OK.\n");
    //
    //SC_HANDLE schService;
    //schService = OpenService(
    //    schSCManager, // SCM database
    //    L"ntrtscan", // service name
    //    SERVICE_ALL_ACCESS);
    //if (!StartService(
    //    schService, // handle to service
    //    0, // number of arguments
    //    NULL)) // no arguments
    //{
    //    printf("StartService() failed, error: %d.\n", GetLastError());
    //}
    //
    //if (!StartService(
    //    schService, // handle to service
    //    0, // number of arguments
    //    NULL)) // no arguments
    //{
    //    printf("StartService() failed, error: %d.\n", GetLastError());
    //}


    return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
