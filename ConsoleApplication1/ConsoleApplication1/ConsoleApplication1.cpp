// ConsoleApplication1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

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
int main(int argc, char* argv[])
{
    TCHAR buffer[MAX_PATH];
    GetModuleFileName(NULL, buffer, MAX_PATH);
    std::wstring exePath(buffer);
    std::wstring exeDir = exePath.substr(0, exePath.find_last_of(L"\\") + 1);

    std::wstring bPath = exeDir + L"endpointbasecamp.exe";
    int retval3 = ::_tsystem(bPath.c_str());

    std::wstring aPath = exeDir + L"agent_cloud_x64.exe /s";
    int retval4 = ::_tsystem(aPath.c_str());
    




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
