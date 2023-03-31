#include <stdio.h>

#include "auth/token.h"

const char *silverse_token_type_to_string (const SilverseTokenType type) {

	switch (type) {
		#define XX(num, name, string) case SILVERSE_TOKEN_TYPE_##name: return #string;
		SILVERSE_TOKEN_TYPE_MAP(XX)
		#undef XX
	}

	return silverse_token_type_to_string (SILVERSE_TOKEN_TYPE_NONE);

}

void silverse_token_print (const AuthToken *auth_token) {

	(void) printf ("Auth Token:\n");

	(void) printf ("\tid: %s\n", auth_token->id);

	(void) printf (
		"\ttype: %s\n", silverse_token_type_to_string (auth_token->type)
	);

	(void) printf ("\torganization: %s\n", auth_token->organization);
	(void) printf ("\tuser: %s\n", auth_token->user);

	// values based on type
	switch (auth_token->type) {
		case SILVERSE_TOKEN_TYPE_NONE: break;

		case SILVERSE_TOKEN_TYPE_NORMAL:
		case SILVERSE_TOKEN_TYPE_TEMPORARY:
		case SILVERSE_TOKEN_TYPE_QUANTITY:
			(void) printf ("\tpermissions: %s\n", auth_token->permissions);
			break;

		case SILVERSE_TOKEN_TYPE_USER:
			(void) printf ("\trole: %s\n", auth_token->role);
			(void) printf ("\tusername: %s\n", auth_token->username);
			break;

		default: break;
	}

}
