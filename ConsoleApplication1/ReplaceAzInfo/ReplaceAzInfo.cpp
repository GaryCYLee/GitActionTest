// ReplaceAzInfo.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <fstream>
#include <string>
using namespace std;

int main(int argc, char* argv[])
{
    if (argc != 4)
    {
        cout << "arg error" << endl;
        return 0;
    }

    ifstream ifs(argv[1], ifstream::in);
    string tempstr;
    string str;
    while (getline(ifs, tempstr))
    {
        str += tempstr;
        str += "\n";
    }
    //cout << str << endl;
    ifs.close();

    string tokentoreplace = argv[2];
    string contenttoreplace = argv[3];
    int pos = 0;
    while (1) {
        pos = str.find(tokentoreplace, pos);
        if (pos == -1) break;

        str.replace(pos, tokentoreplace.length(), contenttoreplace);
        pos += contenttoreplace.length();
        break;
    }
    //cout << str << endl;

    ofstream ofs(argv[1]);
    ofs << str;
    ofs.close();
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
