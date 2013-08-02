#ifndef CLIENT_RESPONSE_H
#define CLIENT_RESPONSE_H

#include "ffbuffer.h"

class client_response
{
public:
    enum result {OK, ERROR, AGAIN};
    client_response();
    ~client_response();
    int get_version() const;
    int get_code() const;
    virtual enum result update_header(ffbuffer *response);
    virtual enum result update_body(ffbuffer *response) = 0;

private:
    int version;
    int code;
    bool common_header_ok;
};

#endif
