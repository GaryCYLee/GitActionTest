// SCPStringHelper.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <fstream>
#include <string>
using namespace std;

void replaceToken(string& content, string tokentoreplace, string contenttoreplace)
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
    if (argc < 2)
    {
        cout << "Please input first arg with \"ReplaceAzInfo\" , \"GetCompressedPackageName\" or \"GenerateMDFile\" :)";
        return 0;
    }

    string request = argv[1];
    if (request == "ReplaceAzInfo")
    {
        ifstream ifs(argv[2], ifstream::in);
        string tempstr;
        string str;
        while (getline(ifs, tempstr))
        {
            str += tempstr;
            str += "\n";
        }
        //cout << str << endl;
        ifs.close();

        string tokentoreplace = argv[3];
        string contenttoreplace = argv[4];
        int pos = 0;
        while (1) {
            pos = str.find(tokentoreplace, pos);
            if (pos == -1) break;

            str.replace(pos, tokentoreplace.length(), contenttoreplace);
            pos += contenttoreplace.length();
            break;
        }
        //cout << str << endl;

        ofstream ofs(argv[2]);
        ofs << str;
        ofs.close();

        return 0;
    }
    else if (request == "GetCompressedPackageName")
    {
        string TARGET_PACKAGE = argv[2];
        replaceToken(TARGET_PACKAGE, " ", "-");
        if (TARGET_PACKAGE.length() > 40) TARGET_PACKAGE = TARGET_PACKAGE.substr(0, 36);
        string SHA = argv[3];
        SHA = SHA.substr(0, 8);
        string RUN_NUMBER = argv[4];
        string PACKAGE_NAME = TARGET_PACKAGE + "_" + SHA + "_" + RUN_NUMBER + ".7z";
        string WORKINGSPACE = argv[5];
        string PACKAGE_FULL_PATH = WORKINGSPACE + "\\build\\publish\\" + PACKAGE_NAME;
        cout << PACKAGE_FULL_PATH;
    }
    else if (request == "GenerateMDFile")
    {
        string Usage = argv[2];
        string TempMDPath = argv[3];
        if (Usage == "Tag")
        {
            TempMDPath += "\\ReleaseNoteTemplate_GithubAction.md";
        }
        else if (Usage == "Mail")
        {
            TempMDPath += "\\ReleaseNoteTemplate_GithubAction.html";
        }
        string NewMDPath = argv[3];
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

        string RUN_NUMBER = argv[4];
        string TARGET_PACKAGE = argv[5];
        replaceToken(TARGET_PACKAGE, " ", "-");
        if (TARGET_PACKAGE.length() > 40) TARGET_PACKAGE = TARGET_PACKAGE.substr(0, 36);
        string SHA = argv[8];
        SHA = SHA.substr(0, 8);
        string PACKAGE_NAME = TARGET_PACKAGE + "_" + SHA + "_" + RUN_NUMBER + ".7z";

        string date = utcExample() + " UTC";

        string CI_RP_SAS_TOKEN = argv[12];
        string delimiter = "se=";
        string delimiter2 = "Z&st";
        string EXPIRE_DATE = CI_RP_SAS_TOKEN.substr(CI_RP_SAS_TOKEN.find(delimiter)).substr(delimiter.size());
        EXPIRE_DATE = EXPIRE_DATE.substr(0, EXPIRE_DATE.find(delimiter2));

        string TAG_NAME = "SCPPackage_" + RUN_NUMBER;

        replaceToken(str, "<!--BUILD_NUMBER-->", RUN_NUMBER);
        replaceToken(str, "<!--SCP_NAME-->", argv[5]);
        replaceToken(str, "<!--CASE_ID-->", argv[6]);
        replaceToken(str, "<!--RP_CONTAINER_NAME-->", argv[7]);
        replaceToken(str, "<!--PACKAGE_NAME-->", PACKAGE_NAME);
        replaceToken(str, "<!--SUBMITTER-->", argv[9]);
        replaceToken(str, "<!--BUILD_BRANCH-->", argv[10]);
        replaceToken(str, "<!--BUILD_HASH-->", SHA);
        replaceToken(str, "<!--DATE_TIME_NOW-->", date);
        replaceToken(str, "<!--BUILD_MACHINE-->", argv[11]);
        replaceToken(str, "<!--TOKEN_EXPIRE_DATE-->", EXPIRE_DATE);
        replaceToken(str, "<!--BUILD_TAG_NAME-->", TAG_NAME);
        replaceToken(str, "<!---BUILD_RELEASE_NOTE--->", argv[13]);

        cout << str << endl;
        if (Usage == "Tag")
        {
            ofstream ofs(NewMDPath);
            ofs << "\r\n\r\n";
            ofs << str;
            ofs.close();
        }
    }
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
