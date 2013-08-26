#ifndef FF_STORAGE_H
#define FF_STORAGE_H

#include <string>
#include <list>

class file_info
{
public:
    std::string path;
    char type;
};

namespace ffstorage
{

bool prepare(const char *project_name);
void scan(const char *project_name, std::list<file_info> *result);
int begin_add(const std::string &project_name, const std::string &path);
void end_add(const std::string &project_name, const std::string &path);
void dir_add(const std::string &project_name, const std::string &path);
void mark_deletion(const std::string &project_name, const std::list<std::string> &file_list);
bool hash_sha1(const std::string &project_name, const std::string &path, void *hash);

}

#endif
