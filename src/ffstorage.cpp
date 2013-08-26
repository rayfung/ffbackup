#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>
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
    mkdir((path + "/cache").c_str(), 0775);
    return true;
}

void scan(const char *project_name, std::list<file_info> *result)
{
    std::string base;

    result->clear();
    base = std::string(project_name) + std::string("/current/");
    _scan_dir(base, std::string(), result);
}

int begin_add(const std::string &project_name, const std::string &path)
{
    return creat((project_name + "/cache/" + path).c_str(), 0644);
}

void end_add(const std::string &project_name, const std::string &path)
{
}

void dir_add(const std::string &project_name, const std::string &path)
{
    mkdir((project_name + "/cache/" + path).c_str(), 0775);
}

void mark_deletion(const std::string &project_name, const std::list<std::string> &file_list)
{
    std::list<std::string>::const_iterator iter;

    fprintf(stderr, "\n[BEGIN mark_deletion]\n");
    for(iter = file_list.begin(); iter != file_list.end(); ++iter)
        fprintf(stderr, "%s\n", iter->c_str());
    fprintf(stderr, "\n[END mark_deletion]\n");
}

bool hash_sha1(const std::string &project_name, const std::string &path, void *hash)
{
    SHA_CTX ctx;
    FILE *fp;
    std::string tmp = project_name + "/current/" + path;
    size_t ret;
    char buffer[1024];

    fp = fopen(tmp.c_str(), "rb");
    if(fp == NULL)
        return false;
    if(SHA1_Init(&ctx) == 0)
        return false;
    while((ret = fread(buffer, 1, sizeof(buffer), fp)) > 0)
    {
        if(SHA1_Update(&ctx, buffer, ret) == 0)
        {
            fclose(fp);
            return false;
        }
    }
    fclose(fp);
    if(SHA1_Final((unsigned char *)hash, &ctx) == 0)
        return false;
    return true;
}

}
