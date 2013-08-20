#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include "ffstorage.h"

namespace ffstorage
{

static void _scan_dir(const std::string &base, std::string dir, std::list<file_info> *result)
{
    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;

    dp = opendir((base + dir).c_str());
    if(dp == NULL)
        return;
    while((entry = readdir(dp)) != NULL)
    {
        std::string path;

        path = dir + std::string(entry->d_name);
        if(lstat((base + path).c_str(), &statbuf) < 0)
            continue;
        if(S_ISDIR(statbuf.st_mode))
        {
            if(strcmp(".", entry->d_name) == 0 ||
                    strcmp("..", entry->d_name) == 0)
                continue;

            file_info info;
            info.type = 'd';
            info.path = path;
            result->push_back(info);

            _scan_dir(base, path + "/", result);
        }
        else if(S_ISREG(statbuf.st_mode))
        {
            file_info info;
            info.type = 'f';
            info.path = path;
            result->push_back(info);
        }
    }
    closedir(dp);
}

bool prepare(const char *project_name)
{
    std::string path;

    path.assign(project_name);

    mkdir(project_name, 0775);
    mkdir((path + "/current").c_str(), 0775);
    return true;
}

void scan(const char *project_name, std::list<file_info> *result)
{
    std::string base;

    result->clear();
    base = std::string(project_name) + std::string("/current/");
    _scan_dir(base, std::string(), result);
}

}
