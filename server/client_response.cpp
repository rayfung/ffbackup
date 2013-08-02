#include "client_response.h"

client_response::client_response()
{
    this->version = -1;
    this->code = -1;
    this->common_header_ok = false;
}

client_response::~client_response()
{
}

int client_response::get_version() const
{
    return this->version;
}

int client_response::get_code() const
{
    return this->code;
}

enum client_response::result client_response::update_header(ffbuffer *response)
{
    unsigned char buf[2];
    size_t ret;

    if(this->common_header_ok)
        return client_response::OK;

    if(response->get_size() < 2)
        return client_response::AGAIN;

    ret = response->get(buf, 0, 2);
    if(ret != 2)
        return client_response::ERROR;

    this->version = buf[0];
    this->code = buf[1];
    this->common_header_ok = true;
    response->pop_front(2);
    return client_response::OK;
}
