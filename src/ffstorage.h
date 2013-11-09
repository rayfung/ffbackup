#ifndef FF_STORAGE_H
#define FF_STORAGE_H

#include <string>
#include <list>
#include <cstdio>

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
int begin_add(const std::string &project_name, size_t index);
void end_add(const std::string &project_name, const std::string &path);
void dir_add(const std::string &project_name, const std::string &path);
bool hash_sha1(const std::string &project_name, const std::string &path, void *hash);
FILE *rsync_sig(const std::string &project_name, const std::string &path);
int begin_delta(const std::string &project_name, size_t index);
bool end_delta(const std::string &project_name, const std::string &path, size_t index);
bool rsync_patch(const std::string &basis_file_path, const std::string &patch_file_path,
                 const std::string &new_file_path);
bool write_patch_list(const std::string &project_name, const std::list<file_info> &file_list);
bool write_del_list(const std::string &project_name, const std::list<file_info> &file_list);
bool write_add_list(const std::string &project_name, const std::list<file_info> &file_list);
char get_file_type(const std::string &project_name, const std::string &path);
size_t get_history_qty(const std::string &project_name);
bool write_info(const std::string &project_name, size_t index);
std::list<std::string> get_project_list();

}

#endif
