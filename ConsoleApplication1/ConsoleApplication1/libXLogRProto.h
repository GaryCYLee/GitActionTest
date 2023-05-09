#pragma once

#include <Windows.h>
#include <string>
using namespace std;

namespace XLogRProto
{
    class Proto
    {
    private:
        Proto() {}
        Proto(const Proto&) = delete;
        Proto& operator=(const Proto&) = delete;

    public:
        static Proto&get_ins()
        {
            static Proto instance;
            return instance;
        }

        void Initial();
        void WriteBuf2File(string uid);
    };
};
