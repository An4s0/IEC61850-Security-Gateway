#ifndef HTTP_API_H
#define HTTP_API_H

#include <stdint.h>

#define HTTP_API_PORT 8080

void HTTP_API_Init(void);
void HTTP_API_BroadcastAlert(const char *json_line, uint16_t len);
uint8_t HTTP_API_IsListening(void);
void HTTP_API_EnsureListening(void);

#endif /* HTTP_API_H */