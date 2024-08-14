// ConsoleApplication1.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <tchar.h>
#include <map>
#include <sstream>
#include <fstream>
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
#include <fstream>
#include "curl/curl.h"
#include <json.h>

#define XDR_DATA     L"data"
#define XDR_GROUP    L"group"
#define SLF_ProductGUID   1001
#define SLF_ParentGUID    2022
#define SLF_ServerGUID    3048
#define SLF_Info          3001

std::wstring TUIDConvertToGUID(const std::wstring& strID)
{
    std::wstring strResult = strID;
    strResult.erase(std::remove(strResult.begin(), strResult.end(), '-'), strResult.end());
    if (strResult.length() != 32) {
        return strID;
    }
    strResult.insert(8, L"-");
    strResult.insert(13, L"-");
    strResult.insert(18, L"-");
    strResult.insert(23, L"-");

    return strResult;
}

std::wstring AddBackslash(std::wstring &wstr)
{
    std::wstring reservedChars = L"\\\"";
    std::wstring Val = L"";
    for (wchar_t c : wstr) {
        if (reservedChars.find(c) != std::wstring::npos) {
            Val += L'\\';
        }
        Val += c;
    }
    return Val;
}

BOOL FormatDatalakeJsonBody(std::vector<std::pair<std::wstring, std::pair<std::wstring, std::wstring>>> &vector, std::wstring& body)
{
    std::wstring JS = L"{";
    std::wstring SLF = L"";
    std::wstring Val = L"";
    std::wstring InnerJS = L"";
    std::wstring wstrTemp = L"";
    TCHAR tch_temp[3100] = { 0 };
    std::vector<std::pair<std::wstring, std::pair<std::wstring, std::wstring>>> inner_vector;
    try
    {
        for (int i = 0; i < vector.size(); i++)
        {
            SLF = L"";
            Val = L"";
            SLF = vector.at(i).second.first;
            Val = AddBackslash(vector.at(i).second.second);
            if (vector.at(i).first == XDR_GROUP && Val == L"1")
            {
                // Group data case
                
                // Group data "BaseSLF"
                SLF = vector.at(i).second.first;

                // Check if next SLF is "SLF_Info(3001)", data is "group" and value == "1"
                if (!(vector.at(i + 1).first == XDR_GROUP && vector.at(i + 1).second.first == to_wstring(SLF_Info) && vector.at(i + 1).second.second == L"1"))
                {
                    return FALSE;
                }

                // Next iterator in inner loop
                int j = i + 2;

                // Inner loop value
                Val = L"";
                while (true)
                {
                    inner_vector.clear();

                    // Push inner value until stop sign (SLF is "SLF_Info(3001)" and value == "0")
                    while (!(vector.at(j).first == XDR_GROUP && vector.at(j).second.first == to_wstring(SLF_Info) && vector.at(j).second.second == L"0"))
                    {
                        inner_vector.push_back(std::make_pair(vector[j].first, vector[j].second));
                        j++;
                    }

                    // Format inner json recursive
                    if (!FormatDatalakeJsonBody(inner_vector, InnerJS))
                    {
                        return FALSE;
                    }
                    Val += AddBackslash(InnerJS) + L",";

                    // Next iterator is group SLF_Info(3001) and value == "1", go to next inner round
                    if (vector.at(j + 1).first == XDR_GROUP && vector.at(j + 1).second.first == to_wstring(SLF_Info) && vector.at(j + 1).second.second == L"1")
                    {
                        j += 2;
                        continue;
                    }
                    // Next iterator is "BaseSLF" and value == 0, stop inner loop
                    else if ((vector.at(j + 1).first == XDR_GROUP && vector.at(j + 1).second.first == SLF && vector.at(j + 1).second.second == L"0"))
                    {
                        // Assign inner value to "BaseSLF"
                        Val.erase(Val.end() - 1);
                        if (Val.size() < 3000)
                        {
                            swprintf_s(tch_temp, L"\"%s\":\"[%s]\",", SLF.c_str(), Val.c_str());
                            JS.append(tch_temp);
                        }
                        else
                        {
                            wstrTemp = L"\"" + SLF + L"\":\"[" + Val + L"]\",";
                            JS.append(wstrTemp);
                        }
                        // Move to next iterator
                        i = j + 1;
                        break;
                    }
                    // Format error
                    else
                    {
                        return FALSE;
                    }
                }
            }
            else
            {
                // Normal data base case
                if (SLF == L"0" || SLF == L"1" || SLF == L"2" || SLF == L"3" || SLF == to_wstring(SLF_ProductGUID) || SLF == to_wstring(SLF_ParentGUID) || SLF == to_wstring(SLF_ServerGUID))
                {
                    Val = TUIDConvertToGUID(Val);
                }
                if (Val.size() < 3000)
                {
                    swprintf_s(tch_temp, L"\"%s\":\"%s\",", SLF.c_str(), Val.c_str());
                    JS.append(tch_temp);
                }
                else
                {
                    wstrTemp = L"\"" + SLF + L"\":\"" + Val + L"\",";
                    JS.append(wstrTemp);
                }
            }
        }

        JS.erase(JS.end() - 1);
        JS += L"}";
    }
    catch (const std::out_of_range& e)
    {
        wprintf(L"%s", std::wstring(e.what(), e.what() + strlen(e.what())));
        return FALSE;
    }
    body = JS;
    return TRUE;
}

int main(int argc, char* argv[])
{
    std::vector<std::pair<std::wstring, std::pair<std::wstring, std::wstring>>> vector;
    //for (int i = 0; i < 10; i++)
    {
        vector.push_back(std::make_pair(XDR_DATA, std::make_pair(L"1001", L"399E85840114-694DBF9D-44CC-65D3-0162")));
        vector.push_back(std::make_pair(XDR_DATA, std::make_pair(L"2001", L"2019-11-20 06:38:39")));

        vector.push_back(std::make_pair(XDR_GROUP, std::make_pair(L"3008", L"1")));

        vector.push_back(std::make_pair(XDR_GROUP, std::make_pair(L"3001", L"1")));
        vector.push_back(std::make_pair(XDR_DATA, std::make_pair(L"2265", L"0")));
        vector.push_back(std::make_pair(XDR_DATA, std::make_pair(L"2022", L"A1CD51A12529-4E548E7E-6CC7-8043-F118")));
        vector.push_back(std::make_pair(XDR_GROUP, std::make_pair(L"3001", L"0")));

        vector.push_back(std::make_pair(XDR_GROUP, std::make_pair(L"3001", L"1")));
        vector.push_back(std::make_pair(XDR_DATA, std::make_pair(L"2265", L"0")));
        vector.push_back(std::make_pair(XDR_DATA, std::make_pair(L"2022", L"A1CD51A12529-4E548E7E-6CC7-8043-F118")));
        vector.push_back(std::make_pair(XDR_GROUP, std::make_pair(L"3001", L"0")));

        vector.push_back(std::make_pair(XDR_GROUP, std::make_pair(L"3001", L"1")));
        vector.push_back(std::make_pair(XDR_DATA, std::make_pair(L"2265", L"0")));
        vector.push_back(std::make_pair(XDR_DATA, std::make_pair(L"2022", L"A1CD51A12529-4E548E7E-6CC7-8043-F118")));
        vector.push_back(std::make_pair(XDR_GROUP, std::make_pair(L"3001", L"0")));

        vector.push_back(std::make_pair(XDR_GROUP, std::make_pair(L"3001", L"1")));
        vector.push_back(std::make_pair(XDR_DATA, std::make_pair(L"2265", L"0")));
        vector.push_back(std::make_pair(XDR_DATA, std::make_pair(L"2022", L"A1CD51A12529-4E548E7E-6CC7-8043-F118")));
        vector.push_back(std::make_pair(XDR_GROUP, std::make_pair(L"3001", L"0")));

        vector.push_back(std::make_pair(XDR_GROUP, std::make_pair(L"3008", L"0")));

        vector.push_back(std::make_pair(XDR_DATA, std::make_pair(L"18", L"C:\\Windows\\Temp")));
        vector.push_back(std::make_pair(XDR_DATA, std::make_pair(L"19", L"中ぽ한`-=\\[];',./ ~!@#$%^&*()_+|{}:\"<>?")));
        vector.push_back(std::make_pair(XDR_DATA, std::make_pair(L"20", L"789")));
        vector.push_back(std::make_pair(XDR_DATA, std::make_pair(L"client_hostname", L"GGGGGAAAAARRRRYYYYY")));
        vector.push_back(std::make_pair(XDR_DATA, std::make_pair(L"client_ipaddress", L"10.0.0.1")));
        vector.push_back(std::make_pair(XDR_DATA, std::make_pair(L"client_macaddress", L"00-50-56-97-74-FB")));
    }

    DWORD t = GetTickCount();
    std::wstring JS;
    std::wstring JSBody;
    if (FormatDatalakeJsonBody(vector, JSBody))
    {

    }
    printf("ms: %d", GetTickCount() - t);
    system("pause");
    return 0;


    return 0;
}