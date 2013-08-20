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

}

#endif
