#ifndef _SILVERSE_AUTH_REQUESTS_H_
#define _SILVERSE_AUTH_REQUESTS_H_

#include <stddef.h>

#include "auth/auth.h"
#include "auth/config.h"

#define AUTH_HEADER_SIZE		1024
#define AUTH_REQUEST_SIZE		512
#define AUTH_RESPONSE_SIZE		1024

#ifdef __cplusplus
extern "C" {
#endif

#define REQUEST_RESULT_MAP(XX)			\
	XX(0,  NONE,      	None)			\
	XX(1,  FAILED,      Failed)			\
	XX(2,  BAD_STATUS,  Bad Status)

typedef enum RequestResult {

	#define XX(num, name, string) REQUEST_RESULT_##name = num,
	REQUEST_RESULT_MAP(XX)
	#undef XX

} RequestResult;

AUTH_PUBLIC const char *request_result_to_string (
	const RequestResult type
);

typedef struct AuthRequest {

	char auth_header[AUTH_HEADER_SIZE];

	char body[AUTH_REQUEST_SIZE];
	size_t body_len;

	char response[AUTH_RESPONSE_SIZE];
	size_t response_ptr;

} AuthRequest;

AUTH_PRIVATE void *auth_request_new (void);

AUTH_PRIVATE void auth_request_delete (void *request_ptr);

AUTH_PRIVATE void auth_request_create (
	AuthRequest *auth_request, const char *token, const char *source
);

AUTH_PRIVATE void auth_request_create_action (
	AuthRequest *auth_request, const char *token,
	const char *source, const char *action
);

AUTH_PRIVATE void auth_request_create_role (
	AuthRequest *auth_request,
	const char *token, const char *source,
	const char *action, const char *role
);

AUTH_PUBLIC RequestResult auth_request_authentication (
	const char *auth_service_address,
	AuthRequest *auth_request
);

#ifdef __cplusplus
}
#endif

#endif
