#ifndef DATA_TYPES_H
#define DATA_TYPES_H

#include <string>

class file_info
{
public:
    std::string path;
    char type;
    char sha1[20];
};

#endif
