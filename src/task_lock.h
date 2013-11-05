#ifndef TASK_LOCK_H
#define TASK_LOCK_H

#include <string>

bool ff_trylock(const std::string &project_name, uint64_t id);
bool ff_unlock(const std::string &project_name, uint64_t id);

#endif
