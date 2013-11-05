#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include "task_lock.h"

/* 获得一个互斥锁，second 表示超时时间，如果 second < 0，表示永不超时 */
bool _lock(const std::string &path, int second)
{
    int fd;
    time_t start;
    struct timespec ts;

    start = time(NULL);
    while(1)
    {
        fd = open(path.c_str(), O_CREAT | O_WRONLY | O_EXCL, 0644);
        if(fd >= 0)
        {
            close(fd);
            return true;
        }
        ts.tv_sec  = 0;
        ts.tv_nsec = 100000000L;
        nanosleep(&ts, NULL); //sleep 100 ms
        if(second >= 0 && time(NULL) > start + second)
            return false;
    }
}

/* 释放一个互斥锁，此函数并不检查也无法检查调用者是否拥有该互斥锁 */
bool _unlock(const std::string &path)
{
    return (unlink(path.c_str()) == 0);
}

/* 试图获得某个项目的(递归)互斥锁 */
bool ff_trylock(const std::string &project_name, uint64_t id)
{
    int fd;
    char buffer[32];
    bool ok;
    std::string lock_0 = project_name + "/lock.0";
    std::string lock_1 = project_name + "/lock.1";

    if(project_name.empty())
        return false;
    if(!_lock(lock_0, 10))
        return false;
    fd = open(lock_1.c_str(), O_CREAT | O_RDWR, 0644);
    if(fd < 0)
    {
        _unlock(lock_0);
        return false;
    }
    if(read(fd, buffer, 12) != 12)
    {
        uint32_t count = 1;
        lseek(fd, 0, SEEK_SET);
        write(fd, &id, 8);
        write(fd, &count, 4);
        ok = true;
    }
    else
    {
        if(id == *(uint64_t *)buffer)
        {
            uint32_t count;
            lseek(fd, 0, SEEK_SET);
            write(fd, &id, 8);
            count = 1 + *(uint32_t *)(buffer + 8);
            write(fd, &count, 4);
            ok = true;
        }
        else ok = false;
    }

    close(fd);
    _unlock(lock_0);
    return ok;
}

/* 释放某个项目的(递归)互斥锁 */
bool ff_unlock(const std::string &project_name, uint64_t id)
{
    int fd;
    char buffer[32];
    bool ok;
    std::string lock_0 = project_name + "/lock.0";
    std::string lock_1 = project_name + "/lock.1";

    if(project_name.empty())
        return false;
    if(!_lock(lock_0, 10))
        return false;
    fd = open(lock_1.c_str(), O_RDWR);
    if(fd < 0)
    {
        _unlock(lock_0);
        return false;
    }
    if(read(fd, buffer, 12) != 12)
        ok = false;
    else
    {
        if(id == *(uint64_t *)buffer)
        {
            uint32_t count;
            lseek(fd, 0, SEEK_SET);
            write(fd, &id, 8);
            count = *(uint32_t *)(buffer + 8);
            if(count > 1)
            {
                --count;
                write(fd, &count, 4);
            }
            else
                unlink(lock_1.c_str());
            ok = true;
        }
        else ok = false;
    }

    close(fd);
    _unlock(lock_0);
    return ok;
}
