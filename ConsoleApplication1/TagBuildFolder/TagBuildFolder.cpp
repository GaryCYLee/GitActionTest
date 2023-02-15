// TagBuildFolder.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <fstream>
#include <string>
using namespace std;

void replaceToken(string &content, string tokentoreplace, string contenttoreplace)
{
    int pos = 0;
    while (1) {
        pos = content.find(tokentoreplace, pos);
        if (pos == -1) break;

        content.replace(pos, tokentoreplace.length(), contenttoreplace);
        pos += contenttoreplace.length();
    }
    return;
}

string utcExample()
{
    time_t time = std::time({});
    char timeString[size("yyyy-mm-ddThh:mm:ssZ")];
    strftime(data(timeString), size(timeString), "%FT%TZ", gmtime(&time));
    return timeString;
}

int main(int argc, char* argv[])
{
    string TempMDPath = argv[1];
    TempMDPath += "\\ReleaseNoteTemplate.md";
    string NewMDPath = argv[1];
    NewMDPath += "\\tagMessage.md";
    ifstream ifs(TempMDPath, ifstream::in);
    string tempstr;
    string str;
    while (getline(ifs, tempstr))
    {
        str += tempstr;
        str += "\n";
    }
    ifs.close();

    string BUILD_NUMBER = argv[2];
    string PACKAGE_NAME = argv[3];
    string SHA = argv[6];
    PACKAGE_NAME += "_" + SHA.substr(0, 8);
    PACKAGE_NAME += "_" + BUILD_NUMBER + ".7z";

    string date = utcExample() + " UTC";

    string CI_RP_SAS_TOKEN = argv[10];
    string delimiter = "se=";
    string delimiter2 = "Z&st";
    string EXPIRE_DATE = CI_RP_SAS_TOKEN.substr(CI_RP_SAS_TOKEN.find(delimiter)).substr(3);
    EXPIRE_DATE = EXPIRE_DATE.substr(0, EXPIRE_DATE.find(delimiter2));

    string TAG_NAME = "SCPPackage_" + BUILD_NUMBER;

    replaceToken(str, "<!--BUILD_NUMBER-->", BUILD_NUMBER);
    replaceToken(str, "<!--SCP_NAME-->", argv[3]);
    replaceToken(str, "<!--CASE_ID-->", argv[4]);
    replaceToken(str, "<!--RP_CONTAINER_NAME-->", argv[5]);
    replaceToken(str, "<!--PACKAGE_NAME-->", PACKAGE_NAME);
    replaceToken(str, "<!--SUBMITTER-->", argv[7]);
    replaceToken(str, "<!--BUILD_BRANCH-->", argv[8]);
    replaceToken(str, "<!--BUILD_HASH-->", SHA.substr(0, 8));
    replaceToken(str, "<!--DATE_TIME_NOW-->", date);
    replaceToken(str, "<!--BUILD_MACHINE-->", argv[9]);
    replaceToken(str, "<!--TOKEN_EXPIRE_DATE-->", EXPIRE_DATE);
    replaceToken(str, "<!--BUILD_TAG_NAME-->", TAG_NAME);
    replaceToken(str, "<!---BUILD_RELEASE_NOTE--->", argv[11]);

    cout << str << endl;
    ofstream ofs(NewMDPath);
    ofs << "\r\n\r\n";
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
