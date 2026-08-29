#ifndef HTTP_API_H
#define HTTP_API_H

#include <stdint.h>

void HTTP_API_Init(void);
void HTTP_API_BroadcastAlert(const char *json_line, uint16_t len);

#endif /* HTTP_API_H */