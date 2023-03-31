#ifndef _SILVERSE_AUTH_TOKEN_H_
#define _SILVERSE_AUTH_TOKEN_H_

#include <stddef.h>

#include "auth/config.h"
#include "auth/types.h"

#define AUTH_TOKEN_USERNAME_SIZE		128

#ifdef __cplusplus
extern "C" {
#endif

#define SILVERSE_TOKEN_TYPE_MAP(XX)		\
	XX(0,  NONE,      		None)			\
	XX(1,  NORMAL,      	Normal)			\
	XX(2,  TEMPORARY,      	Temporary)		\
	XX(3,  QUANTITY,  		Quantity)		\
	XX(4,  USER,			User)

typedef enum SilverseTokenType {

	#define XX(num, name, string) SILVERSE_TOKEN_TYPE_##name = num,
	SILVERSE_TOKEN_TYPE_MAP(XX)
	#undef XX

} SilverseTokenType;

AUTH_PUBLIC const char *silverse_token_type_to_string (
	const SilverseTokenType type
);

typedef struct AuthToken {

	char id[AUTH_ID_SIZE];

	SilverseTokenType type;

	char organization[AUTH_ID_SIZE];

	char permissions[AUTH_ID_SIZE];

	char role[AUTH_ID_SIZE];
	char user[AUTH_ID_SIZE];
	char username[AUTH_TOKEN_USERNAME_SIZE];

} AuthToken;

AUTH_PUBLIC void silverse_token_print (const AuthToken *auth_token);

#ifdef __cplusplus
}
#endif

#endif
