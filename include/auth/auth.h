#ifndef _SILVERSE_AUTH_H_
#define _SILVERSE_AUTH_H_

#include <stdbool.h>
#include <stdint.h>

#include <cerver/collections/dlist.h>

#include "auth/config.h"
#include "auth/token.h"
#include "auth/types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct _HttpReceive;
struct _HttpRequest;

#define SILVERSE_AUTH_TYPE_MAP(XX)		\
	XX(0,  NONE,      		None)			\
	XX(1,  TOKEN,      		Token)			\
	XX(2,  ACTION,      	Action)			\
	XX(3,  ROLE,  			Role)			\
	XX(4,  SERVICE,			Service)		\
	XX(5,  PERMISSIONS,		Permissions)	\
	XX(6,  MULTIPLE,		Multiple)		\
	XX(7,  COMPLETE,		Complete)

typedef enum SilverseAuthType {

	#define XX(num, name, string) SILVERSE_AUTH_TYPE_##name = num,
	SILVERSE_AUTH_TYPE_MAP(XX)
	#undef XX

} SilverseAuthType;

AUTH_PUBLIC const char *silverse_auth_type_to_string (
	const SilverseAuthType type
);

#define SILVERSE_AUTH_SCOPE_MAP(XX)	\
	XX(0,  NONE,      	None)			\
	XX(1,  SINGLE,      Single)			\
	XX(2,  MANAGEMENT,  Management)

typedef enum SilverseAuthScope {

	#define XX(num, name, string) SILVERSE_AUTH_SCOPE_##name = num,
	SILVERSE_AUTH_SCOPE_MAP(XX)
	#undef XX

} SilverseAuthScope;

AUTH_PUBLIC const char *silverse_auth_scope_to_string (
	const SilverseAuthScope scope
);

typedef struct SilverseAuth {

	SilverseAuthType type;
	SilverseAuthScope scope;

	char service[AUTH_ID_SIZE];

	bool super_admin;

	AuthToken token;

	int64_t mask;

} SilverseAuth;

AUTH_PUBLIC void silverse_auth_delete (void *auth_ptr);

AUTH_EXPORT const SilverseAuthType silverse_auth_get_type (
	const SilverseAuth *silverse_auth
);

AUTH_EXPORT const SilverseAuthScope silverse_auth_get_scope (
	const SilverseAuth *silverse_auth
);

AUTH_EXPORT const bool silverse_auth_get_admin (
	const SilverseAuth *silverse_auth
);

AUTH_EXPORT const char *silverse_auth_get_token_id (
	const SilverseAuth *silverse_auth
);

AUTH_EXPORT const SilverseTokenType silverse_auth_get_token_type (
	const SilverseAuth *silverse_auth
);

AUTH_EXPORT const char *silverse_auth_get_token_organization (
	const SilverseAuth *silverse_auth
);

AUTH_EXPORT const char *silverse_auth_get_token_permissions (
	const SilverseAuth *silverse_auth
);

AUTH_EXPORT const char *silverse_auth_get_token_role (
	const SilverseAuth *silverse_auth
);

AUTH_EXPORT const char *silverse_auth_get_token_user (
	const SilverseAuth *silverse_auth
);

AUTH_EXPORT const char *silverse_auth_get_token_username (
	const SilverseAuth *silverse_auth
);

AUTH_EXPORT const int64_t silverse_auth_get_mask (
	const SilverseAuth *silverse_auth
);

AUTH_PUBLIC SilverseAuth *silverse_auth_create (
	const SilverseAuthType type
);

AUTH_EXPORT void silverse_auth_print_token (
	const SilverseAuth *silverse_auth
);

AUTH_EXPORT unsigned int silverse_custom_authentication_handler (
	const struct _HttpReceive *http_receive,
	const struct _HttpRequest *request
);

#ifdef __cplusplus
}
#endif

#endif
