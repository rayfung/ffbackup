#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include "ffstorage.h"
#include "config.h"

extern server_config server_cfg;

namespace ffstorage
{

static void _scan_dir(const char *dir, std::list<file_info> *result)
{
    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;

    if((dp = opendir(dir)) == NULL || chdir(dir) < 0)
        return;
    while((entry = readdir(dp)) != NULL)
    {
        lstat(entry->d_name, &statbuf);
        if(S_ISDIR(statbuf.st_mode))
        {
            if(strcmp(".", entry->d_name) == 0 ||
                    strcmp("..", entry->d_name) == 0)
                continue;

            file_info info;
            info.type = 'd';
            if(result->size() > 0)
                info.path = result->back().path;
            info.path += std::string(entry->d_name);
            result->push_back(info);

            _scan_dir(entry->d_name, result);
        }
        else if(S_ISREG(statbuf.st_mode))
        {
            file_info info;
            info.type = 'f';
            if(result->size() > 0)
                info.path = result->back().path;
            info.path += std::string(entry->d_name);
            result->push_back(info);
        }
    }
    chdir("..");
    closedir(dp);
}

static bool chdir_project(const char *project_name)
{
    if(chdir(server_cfg.get_backup_root()) == -1)
        return false;
    if(chdir(project_name) == -1)
        return false;
    return true;
}

bool prepare(const char *project_name)
{
    if(chdir(server_cfg.get_backup_root()) == -1)
        return false;
    mkdir(project_name, 0775);
    if(chdir(project_name) == -1)
        return false;
    mkdir("current", 0775);
    mkdir("history", 0775);
    mkdir("cache", 0775);
    return true;
}

void scan(const char *project_name, std::list<file_info> *result)
{
    result->clear();
    chdir_project(project_name);
    _scan_dir("current", result);
}

}
