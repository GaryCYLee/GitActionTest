#ifndef JSON_JSONHELPER_H_INCLUDED
# define JSON_JSONHELPER_H_INCLUDED
#include <string>
#include "json.h"
#include "stdlib.h"
namespace JsonHelper { 
    inline const std::wstring JsonToString(const Json::Value& v) { 
        wchar_t wszBuf[65] = {}; 
        if (v.isNull())
            return L"";
        else if (v.isString())
            return v.asString();
        else if (v.isIntegral())
            swprintf_s(wszBuf, _countof(wszBuf), L"%u", v.asUInt()); 
        else if (v.isDouble()) 
            swprintf_s(wszBuf, _countof(wszBuf), L"%-10.5f", v.asDouble()); 
        else if (v.isObject())
            return v.toStyledString();

        return wszBuf;
    }
    inline const unsigned int JsonToUInt(const Json::Value v) { return v.isNull()? 0 : (v.isIntegral()? v.asUInt() : (unsigned int) _wtoi(v.asString().c_str())); }
    inline const int JsonToInt(const Json::Value v) { return (int) JsonToUInt(v); }
    inline const bool JsonToBool(const Json::Value v) { return v.isNull()? 0 : (v.isIntegral()? v.asBool() : (unsigned int) _wtoi(v.asString().c_str()) != 0); }
}
#endif // JSON_JSONHELPER_H_INCLUDED
