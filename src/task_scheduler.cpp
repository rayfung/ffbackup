#include "task_scheduler.h"

ff_task::ff_task()
{
    pthread_mutex_init(&this->mutex, NULL);
    this->canceled = false;
}

void ff_task::cancel()
{
    pthread_mutex_lock(&this->mutex);
    this->canceled = true;
    pthread_mutex_unlock(&this->mutex);
}

bool ff_task::is_canceled()
{
    bool ret;

    pthread_mutex_lock(&this->mutex);
    ret = this->canceled;
    pthread_mutex_unlock(&this->mutex);
    return ret;
}

ff_task::~ff_task()
{
    pthread_mutex_destroy(&this->mutex);
}

static void *thread_routine(void *arg)
{
    task_scheduler *ts = (task_scheduler *)arg;
    ts->_run();
    return NULL;
}

task_scheduler::task_scheduler(int thread_num)
{
    pthread_mutex_init(&this->pending_mutex, NULL);
    pthread_mutex_init(&this->done_mutex, NULL);
    pthread_cond_init(&this->cond_ready, NULL);

    this->shutdown = 0;
    this->thread_count = thread_num;
    this->thread_id = new pthread_t[thread_num];

    for(int i = 0; i < thread_num; ++i)
        pthread_create(&this->thread_id[i], NULL, thread_routine, this);
}

void task_scheduler::_run()
{
    ff_task *task;
    bool canceled;

    while(1)
    {
        pthread_mutex_lock(&this->pending_mutex);
        while(this->pending_list.size() == 0 && !this->shutdown)
            pthread_cond_wait(&this->cond_ready, &this->pending_mutex);

        if(this->shutdown)
        {
            pthread_mutex_unlock(&this->pending_mutex);
            pthread_exit(NULL);
        }

        task = this->pending_list.front();
        this->pending_list.pop_front();
        pthread_mutex_unlock(&this->pending_mutex);

        task->run();

        canceled = false;
        pthread_mutex_lock(&this->done_mutex);
        if(task->is_canceled())
            canceled = true;
        else
            this->done_list.push_back(task);
        pthread_mutex_unlock(&this->done_mutex);
        if(canceled)
            delete task;
    }
}

/**
 * 功能：判断一个任务是否已经完成
 * 返回：假如一个任务已经完成并且尚未checkout，返回true，其它情况返回false
 */
bool task_scheduler::is_done(ff_task *task)
{
    bool done;
    std::list<ff_task *>::iterator iter;

    pthread_mutex_lock(&this->done_mutex);
    iter = std::find(this->done_list.begin(), this->done_list.end(), task);
    done = !(iter == this->done_list.end());
    pthread_mutex_unlock(&this->done_mutex);
    return done;
}

/**
 * 功能：从已完成任务列表中移除一个已完成的任务
 * 返回：假如指定的任务已完成并且尚未移除，则移除该任务并且返回true，否则返回false
 */
bool task_scheduler::checkout(ff_task *task)
{
    bool done;
    std::list<ff_task *>::iterator iter;

    pthread_mutex_lock(&this->done_mutex);
    iter = std::find(this->done_list.begin(), this->done_list.end(), task);
    done = !(iter == this->done_list.end());
    if(done)
        this->done_list.erase(iter);
    pthread_mutex_unlock(&this->done_mutex);
    return done;
}

/**
 * 功能：添加一个任务并通知线程池中空闲的线程去执行
 * 注意：不能将已提交的任务再次提交，除非它已经完成并且已经从完成列表中移除
 * 而且，传入的task指针必须指向堆内存，不能指向栈内存
 */
void task_scheduler::submit(ff_task *task)
{
    pthread_mutex_lock(&this->pending_mutex);
    this->pending_list.push_back(task);
    pthread_mutex_unlock(&this->pending_mutex);

    pthread_cond_signal(&this->cond_ready);
}

void task_scheduler::cancel(ff_task *task)
{
    bool ok;
    std::list<ff_task *>::iterator iter;

    ok = false;
    task->cancel();

    pthread_mutex_lock(&this->pending_mutex);
    iter = std::find(this->pending_list.begin(), this->pending_list.end(), task);
    if(iter != this->pending_list.end())
    {
        this->pending_list.erase(iter);
        ok = true;
    }
    pthread_mutex_unlock(&this->pending_mutex);
    if(ok)
    {
        delete task;
        return;
    }

    pthread_mutex_lock(&this->done_mutex);
    iter = std::find(this->done_list.begin(), this->done_list.end(), task);
    if(iter != this->done_list.end())
    {
        this->done_list.erase(iter);
        ok = true;
    }
    pthread_mutex_unlock(&this->done_mutex);
    if(ok)
        delete task;
}

/**
 * 功能：通知并等待线程池中的线程退出，然后释放占用的所有资源
 * 注意：假如有任务未被checkout，那么会自动delete该任务
 */
task_scheduler::~task_scheduler()
{
    std::list<ff_task *>::iterator iter;

    pthread_mutex_lock(&this->pending_mutex);
    this->shutdown = 1;
    pthread_mutex_unlock(&this->pending_mutex);

    pthread_cond_broadcast(&this->cond_ready);
    for(int i = 0; i < this->thread_count; ++i)
        pthread_join(this->thread_id[i], NULL);

    delete[] this->thread_id;

    for(iter = this->pending_list.begin(); iter != this->pending_list.end(); ++iter)
        delete *iter;
    for(iter = this->done_list.begin(); iter != this->done_list.end(); ++iter)
        delete *iter;

    pthread_mutex_destroy(&this->pending_mutex);
    pthread_mutex_destroy(&this->done_mutex);
    pthread_cond_destroy(&this->cond_ready);
}
