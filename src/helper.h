#ifndef HELPER_H
#define HELPER_H

#include <stdint.h>
#include <string>
#include <list>
#include <cstdio>
#include <time.h>

void dump_data(void *data, size_t size);

std::list<std::string> split_path(const std::string &path);
bool is_path_safe(const std::string &path);
bool is_project_name_safe(const char *prj);
uint64_t get_file_size(FILE *fp);
std::string size2string(size_t size);
bool rm_recursive(const std::string &path);
bool copy_file(const std::string &src_path, const std::string &dst_path);
struct timespec fftime_add(struct timespec a, struct timespec b);
struct timespec fftime_sub(struct timespec a, struct timespec b);

uint16_t ntoh16(uint16_t net);

uint16_t hton16(uint16_t host);

uint32_t ntoh32(uint32_t net);

uint32_t hton32(uint32_t host);

uint64_t ntoh64(uint64_t net);

uint64_t hton64(uint64_t host);

#endif
