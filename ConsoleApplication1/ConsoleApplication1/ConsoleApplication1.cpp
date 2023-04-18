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

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "x-functions-key: OCiJOiFmaAeB-7Xf7HtKGV5bXsVgrAfBvio5ylQWGz0HAzFuH845dw==");
        //headers = curl_slist_append(headers, "x-functions-key: 9XFnAPwfkmMah2P03EGntqS-Abu9pNBEPupwVXqLVla6AzFu60u2LA==");
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

typedef struct {
    PUBLICKEYSTRUC  PublicKeyStruc;
    ALG_ID Algid;
    BYTE bEncryptedKey[32];
} ENC_EX;
#define CRYPT_TITLE_EX      "!CRYPTEX!"
#define CRYPT_TITLE_EX_W    L"!CRYPTEX!"
#define CRYPT_TITLE_EX_LEN  9
#define CRYPT_TITLE_EX3      "!CRYPTEX3!"
#define CRYPT_TITLE_EX3_W    L"!CRYPTEX3!"
#define CRYPT_TITLE_EX3_LEN  10
#define ENCEX_SALT_LEN      3
#include "cmnsrc_Base64Coder.h"
#define REG32(X) (X)
void Base64Decode_StrToBin(LPCSTR pszInputStr, int nStrBufferLenInByte, LPBYTE pbData, LPDWORD pcbData)
{
    Base64Coder decoder;
    decoder.Decode(pszInputStr);

    if (*pcbData == 0 ||
        *pcbData < decoder.DecodedDataLen() ||
        pbData == NULL)
    {
        *pcbData = decoder.DecodedDataLen();
    }
    else
    {
        *pcbData = decoder.DecodedDataLen();
        memcpy(pbData, decoder.DecodedMessage(), decoder.DecodedDataLen());
    }

}
inline unsigned char ConvertCharToByte(char c1, char c2)
{
    unsigned char value = 0;
    if (c1 >= '0' && c1 <= '9')
        value = (c1 - '0');
    else if (c1 >= 'A' && c1 <= 'F')
        value = (c1 - 'A' + 10);
    else if (c1 >= 'a' && c1 <= 'f')
        value = (c1 - 'a' + 10);

    value = (value << 4);

    if (c2 >= '0' && c2 <= '9')
        value += (c2 - '0');
    else if (c2 >= 'A' && c2 <= 'F')
        value += (c2 - 'A' + 10);
    else if (c2 >= 'a' && c2 <= 'f')
        value += (c2 - 'a' + 10);

    return value;
}
void StrToBin(LPCSTR pszInputStr, int nStrBufferLenInByte, LPBYTE pbData, DWORD cbData)
{
    unsigned char c = 0;

    for (int i = 0; i < nStrBufferLenInByte; i += 2)
    {
        *(pbData) = ConvertCharToByte(pszInputStr[i], pszInputStr[i + 1]);
        pbData++;
    }
}
void VarInit(ENC_EX& EncEX, BYTE(&bIV)[16])
{
    EncEX.Algid = 32;
    EncEX.PublicKeyStruc.aiKeyAlg = CALG_AES_256;
    EncEX.PublicKeyStruc.bType = PLAINTEXTKEYBLOB;
    EncEX.PublicKeyStruc.bVersion = CUR_BLOB_VERSION;
    EncEX.PublicKeyStruc.reserved = 0;
    EncEX.bEncryptedKey[5] = 22;
    bIV[11] = 102;
    EncEX.bEncryptedKey[15] = 221;
    EncEX.bEncryptedKey[2] = 233;
    EncEX.bEncryptedKey[8] = 137;
    bIV[7] = 186;
    EncEX.bEncryptedKey[31] = 115;
    bIV[14] = 18;
    bIV[4] = 57;
    bIV[10] = 206;
    EncEX.bEncryptedKey[23] = 231;
    EncEX.bEncryptedKey[0] = 235;
    EncEX.bEncryptedKey[18] = 7;
    bIV[15] = 174;
    EncEX.bEncryptedKey[10] = 61;
    EncEX.bEncryptedKey[11] = 252;
    EncEX.bEncryptedKey[12] = 114;
    EncEX.bEncryptedKey[21] = 244;
    bIV[5] = 137;
    EncEX.bEncryptedKey[9] = 112;
    EncEX.bEncryptedKey[14] = 255;
    EncEX.bEncryptedKey[4] = 108;
    EncEX.bEncryptedKey[29] = 202;
    bIV[9] = 98;
    EncEX.bEncryptedKey[25] = 137;
    EncEX.bEncryptedKey[17] = 173;
    bIV[1] = 105;
    EncEX.bEncryptedKey[19] = 191;
    EncEX.bEncryptedKey[1] = 6;
    EncEX.bEncryptedKey[22] = 162;
    bIV[13] = 5;
    EncEX.bEncryptedKey[13] = 83;
    EncEX.bEncryptedKey[30] = 75;
    bIV[2] = 46;
    EncEX.bEncryptedKey[24] = 160;
    EncEX.bEncryptedKey[20] = 18;
    bIV[8] = 155;
    EncEX.bEncryptedKey[3] = 199;
    EncEX.bEncryptedKey[6] = 29;
    bIV[0] = 21;
    EncEX.bEncryptedKey[26] = 252;
    EncEX.bEncryptedKey[7] = 108;
    EncEX.bEncryptedKey[16] = 113;
    bIV[3] = 252;
    EncEX.bEncryptedKey[28] = 166;
    bIV[6] = 74;
    bIV[12] = 201;
    EncEX.bEncryptedKey[27] = 124;
}

int NewDecryptStrExReal(LPSTR pszEncryptStr)
{
    int nRet = -1;
    ENC_EX EncEX;
    HCRYPTPROV hCryptProv = NULL;
    HCRYPTKEY hKey = NULL;
    DWORD dwInputLen = strlen(pszEncryptStr);
    PBYTE pbInputBinary = NULL;

    LPCSTR pszProvider = MS_ENH_RSA_AES_PROV_A;
    DWORD dwPadding = PKCS5_PADDING;
    DWORD dwBase64Decode = FALSE;
    BYTE bIV[16] = { 0 };
    int nPrefixLength = -1;

    if (0 == strncmp(CRYPT_TITLE_EX, pszEncryptStr, CRYPT_TITLE_EX_LEN))
    {
        //CryptEx align with PLM2.1, so OSCE doesn't use Base64Decode.
        nPrefixLength = CRYPT_TITLE_EX_LEN;
        dwBase64Decode = FALSE;
    }

    if (0 == strncmp(CRYPT_TITLE_EX3, pszEncryptStr, CRYPT_TITLE_EX3_LEN))
    {
        nPrefixLength = CRYPT_TITLE_EX3_LEN;
        dwBase64Decode = TRUE;
    }

    if (dwInputLen > nPrefixLength &&
        nPrefixLength > 0)
    {
        //query the actual decoded buffer size
        DWORD dwBufferLen = 0;
        if (dwBase64Decode == TRUE)
        {
            Base64Decode_StrToBin(pszEncryptStr + nPrefixLength, dwInputLen - nPrefixLength, NULL, &dwBufferLen);
        }
        else
        {
            dwBufferLen = (dwInputLen - nPrefixLength) / 2;
        }

        pbInputBinary = (PBYTE)malloc(sizeof(BYTE) * dwBufferLen);
        if (NULL != pbInputBinary)
        {
            VarInit(EncEX, bIV);

            if (dwBase64Decode == TRUE)
            {
                Base64Decode_StrToBin(pszEncryptStr + nPrefixLength, dwInputLen - nPrefixLength, pbInputBinary, &dwBufferLen);
            }
            else
            {
                StrToBin(pszEncryptStr + nPrefixLength, dwInputLen - nPrefixLength, pbInputBinary, dwBufferLen);
            }

            if (!CryptAcquireContextA(&hCryptProv, NULL, pszProvider, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
            {
            }
            else if (!CryptImportKey(hCryptProv, (const BYTE*)&EncEX, sizeof(ENC_EX), NULL, 0, &hKey))
            {
            }
            else if (!CryptSetKeyParam(hKey, KP_IV, bIV, 0))
            {
            }
            else if (!CryptSetKeyParam(hKey, KP_PADDING, (PBYTE)&dwPadding, 0))
            {
            }
            else if (!CryptDecrypt(hKey, NULL, TRUE, 0, pbInputBinary, &dwBufferLen))
            {
            }
            else
            {
                memcpy_s(pszEncryptStr, dwInputLen, pbInputBinary + ENCEX_SALT_LEN, dwBufferLen - ENCEX_SALT_LEN);
                pszEncryptStr[dwBufferLen - ENCEX_SALT_LEN] = '\0';
                nRet = 1;
            }
        }
    }

    if (NULL != hKey)
    {
        CryptDestroyKey(hKey);
    }

    if (NULL != hCryptProv)
    {
        CryptReleaseContext(hCryptProv, 0);
    }

    if (NULL != pbInputBinary)
    {
        free(pbInputBinary);
    }

    return nRet;
}

int main(int argc, char* argv[])
{
    Json::Value item;

    item["guid"] = Json::Value("00000000-0000-0000-0000-000000000000");
    item["arch"] = Json::Value("x86");
    item["filename"] = Json::Value("agentX86.exe");
    item["dllink"] = Json::Value("http://123:8080/asd/aaa.exe");
    item["checksum"] = Json::Value("VEWVGG$GT$");

    Json::Value jsRoot;
    getScriptFromAzureTest(jsRoot, item);

    DWORD dw = 0, dwType = 0;
    HKEY hKey;
    LONG nRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\TrendMicro\\PC-cillinNTCorp\\CurrentVersion\\Misc.", 0, REG32(KEY_READ), &hKey);
    WCHAR wszBuffer[MAX_PATH] = { 0 };
    DWORD nBufferSize = _countof(wszBuffer);
    nRet = RegQueryValueEx(hKey, L"RoleSvc", 0, NULL, (BYTE*)wszBuffer, &nBufferSize);
    int size = WideCharToMultiByte(CP_ACP, 0, wszBuffer, -1, NULL, 0, NULL, NULL);
    LPSTR lstr = new char[size];
    WideCharToMultiByte(CP_ACP, 0, wszBuffer, -1, lstr, size, NULL, NULL);
    NewDecryptStrExReal(lstr);



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
