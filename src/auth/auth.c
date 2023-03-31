#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <cerver/collections/dlist.h>

#include <cerver/http/http.h>
#include <cerver/http/request.h>

#include <cerver/http/json/json.h>

#ifdef SILVERSE_DEBUG
#include <cerver/utils/log.h>
#endif

#include "auth/auth.h"
#include "auth/requests.h"
#include "auth/routes.h"
#include "auth/service.h"
#include "auth/token.h"

static unsigned int silverse_custom_authentication_handle_response (
	SilverseAuth *silverse_auth, const char *response
);

const char *silverse_auth_type_to_string (const SilverseAuthType type) {

	switch (type) {
		#define XX(num, name, string) case SILVERSE_AUTH_TYPE_##name: return #string;
		SILVERSE_AUTH_TYPE_MAP(XX)
		#undef XX
	}

	return silverse_auth_type_to_string (SILVERSE_AUTH_TYPE_NONE);

}

const char *silverse_auth_scope_to_string (const SilverseAuthScope scope) {

	switch (scope) {
		#define XX(num, name, string) case SILVERSE_AUTH_SCOPE_##name: return #string;
		SILVERSE_AUTH_SCOPE_MAP(XX)
		#undef XX
	}

	return silverse_auth_scope_to_string (SILVERSE_AUTH_SCOPE_NONE);

}

static SilverseAuth *silverse_auth_new (void) {

	SilverseAuth *auth = (SilverseAuth *) malloc (sizeof (SilverseAuth));
	if (auth) {
		(void) memset (auth, 0, sizeof (SilverseAuth));

		auth->type = SILVERSE_AUTH_TYPE_NONE;
		auth->scope = SILVERSE_AUTH_SCOPE_NONE;
	}

	return auth;

}

void silverse_auth_delete (void *auth_ptr) {

	if (auth_ptr) {
		free (auth_ptr);
	}

}

const SilverseAuthType silverse_auth_get_type (
	const SilverseAuth *silverse_auth
) {

	return silverse_auth->type;

}

const SilverseAuthScope silverse_auth_get_scope (
	const SilverseAuth *silverse_auth
) {

	return silverse_auth->scope;

}

const bool silverse_auth_get_admin (
	const SilverseAuth *silverse_auth
) {

	return silverse_auth->super_admin;

}

const char *silverse_auth_get_token_id (
	const SilverseAuth *silverse_auth
) {

	return silverse_auth->token.id;

}

const SilverseTokenType silverse_auth_get_token_type (
	const SilverseAuth *silverse_auth
) {

	return silverse_auth->token.type;

}

const char *silverse_auth_get_token_organization (
	const SilverseAuth *silverse_auth
) {

	return silverse_auth->token.organization;

}

const char *silverse_auth_get_token_permissions (
	const SilverseAuth *silverse_auth
) {

	return silverse_auth->token.permissions;

}

const char *silverse_auth_get_token_role (
	const SilverseAuth *silverse_auth
) {

	return silverse_auth->token.role;

}

const char *silverse_auth_get_token_user (
	const SilverseAuth *silverse_auth
) {

	return silverse_auth->token.user;

}

const char *silverse_auth_get_token_username (
	const SilverseAuth *silverse_auth
) {

	return silverse_auth->token.username;

}

const int64_t silverse_auth_get_mask (
	const SilverseAuth *silverse_auth
) {

	return silverse_auth->mask;

}

SilverseAuth *silverse_auth_create (const SilverseAuthType type) {

	SilverseAuth *silverse_auth = silverse_auth_new ();
	if (silverse_auth) {
		silverse_auth->type = type;

		switch (silverse_auth->type) {
			case SILVERSE_AUTH_TYPE_NONE: break;

			case SILVERSE_AUTH_TYPE_TOKEN: break;
			case SILVERSE_AUTH_TYPE_ACTION: break;
			case SILVERSE_AUTH_TYPE_ROLE: break;
			case SILVERSE_AUTH_TYPE_SERVICE: break;

			case SILVERSE_AUTH_TYPE_PERMISSIONS: break;

			case SILVERSE_AUTH_TYPE_MULTIPLE: break;
			case SILVERSE_AUTH_TYPE_COMPLETE: break;

			default: break;
		}
	}

	return silverse_auth;

}

void silverse_auth_print_token (const SilverseAuth *silverse_auth) {

	silverse_token_print (&silverse_auth->token);

}

static inline void silverse_custom_authentication_parse_token (
	AuthToken *token, json_t *json_object
) {

	const char *key = NULL;
	json_t *value = NULL;
	json_object_foreach (json_object, key, value) {
		if (!strcmp (key, "id")) {
			(void) snprintf (
				token->id, AUTH_ID_SIZE, "%s", json_string_value (value)
			);
		}

		else if (!strcmp (key, "t_type")) {
			token->type = (SilverseTokenType) json_integer_value (value);
		}

		else if (!strcmp (key, "organization")) {
			(void) snprintf (
				token->organization, AUTH_ID_SIZE, "%s", json_string_value (value)
			);
		}

		else if (!strcmp (key, "permissions")) {
			(void) snprintf (
				token->permissions, AUTH_ID_SIZE, "%s", json_string_value (value)
			);
		}

		else if (!strcmp (key, "role")) {
			(void) snprintf (
				token->role, AUTH_ID_SIZE, "%s", json_string_value (value)
			);
		}

		else if (!strcmp (key, "user")) {
			(void) snprintf (
				token->user, AUTH_ID_SIZE, "%s", json_string_value (value)
			);
		}

		else if (!strcmp (key, "username")) {
			(void) snprintf (
				token->username, AUTH_TOKEN_USERNAME_SIZE, "%s", json_string_value (value)
			);
		}
	}

}

static void silverse_custom_authentication_parse_json (
	SilverseAuth *silverse_auth, json_t *json_body
) {

	const char *key = NULL;
	json_t *value = NULL;
	if (json_typeof (json_body) == JSON_OBJECT) {
		json_object_foreach (json_body, key, value) {
			if (!strcmp (key, "token")) {
				if (json_typeof (value) == JSON_OBJECT) {
					silverse_custom_authentication_parse_token (
						&silverse_auth->token, value
					);
				}
			}
		}
	}

}

static unsigned int silverse_custom_authentication_handle_response (
	SilverseAuth *silverse_auth, const char *response
) {

	unsigned int retval = 1;

	json_error_t json_error =  { 0 };
	json_t *json_body = json_loads (response, 0, &json_error);
	if (json_body) {
		silverse_custom_authentication_parse_json (silverse_auth, json_body);

		json_decref (json_body);

		retval = 0;
	}

	#ifdef SILVERSE_DEBUG
	else {
		cerver_log_error (
			"silverse_custom_authentication_handle_response () - json error on line %d: %s\n",
			json_error.line, json_error.text
		);
	}
	#endif

	return retval;

}

static unsigned int silverse_custom_internal_authentication_handler (
	const HttpRequest *request, const char *auth_service_address,
	const SilverseAuthType auth_type, AuthRequest *auth_request
) {

	unsigned int retval = 1;

	// perform request to the auth service and handle token response
	if (!auth_request_authentication (auth_service_address, auth_request)) {
		SilverseAuth *silverse_auth = silverse_auth_create (auth_type);

		// get token values from response's body
		if (!silverse_custom_authentication_handle_response (
			silverse_auth, auth_request->response
		)) {
			#ifdef SILVERSE_DEBUG
			cerver_log_success ("Success auth!");
			#endif

			http_request_set_custom_data (
				(HttpRequest *) request, silverse_auth
			);

			http_request_set_delete_custom_data (
				(HttpRequest *) request, silverse_auth_delete
			);

			retval = 0;
		}
	}

	return retval;

}

unsigned int silverse_custom_authentication_handler (
	const HttpReceive *http_receive, const HttpRequest *request
) {

	unsigned int retval = 1;

	// get the token from the request's headers
	const String *token = http_request_get_header (
		request, HTTP_HEADER_AUTHORIZATION
	);

	if (token) {
		const AuthService *auth_service = (
			const AuthService *
		) http_receive->http_cerver->custom_data;

		const AuthRoute *auth_route = (
			const AuthRoute *
		) http_receive->route->custom_data;

		AuthRequest auth_request = { 0 };

		switch (auth_route->auth_type) {
			case SILVERSE_AUTH_TYPE_NONE: break;

			case SILVERSE_AUTH_TYPE_TOKEN:
				auth_request_create (
					&auth_request, token->str, auth_service->service_name
				);

				retval = silverse_custom_internal_authentication_handler (
					request, auth_service->auth_service_address,
					SILVERSE_AUTH_TYPE_TOKEN, &auth_request
				);
				break;

			case SILVERSE_AUTH_TYPE_ACTION:
				auth_request_create_action (
					&auth_request, token->str,
					auth_service->service_name, auth_route->action
				);

				retval = silverse_custom_internal_authentication_handler (
					request, auth_service->auth_service_address,
					SILVERSE_AUTH_TYPE_ACTION, &auth_request
				);
				break;

			case SILVERSE_AUTH_TYPE_ROLE:
				auth_request_create_role (
					&auth_request, token->str, auth_service->service_name,
					auth_route->action, auth_route->role
				);

				retval = silverse_custom_internal_authentication_handler (
					request, auth_service->auth_service_address,
					SILVERSE_AUTH_TYPE_ROLE, &auth_request
				);
				break;

			case SILVERSE_AUTH_TYPE_SERVICE: break;

			case SILVERSE_AUTH_TYPE_PERMISSIONS: break;

			case SILVERSE_AUTH_TYPE_MULTIPLE: break;
			case SILVERSE_AUTH_TYPE_COMPLETE: break;

			default: break;
		}
	}

	#ifdef SILVERSE_DEBUG
	else {
		cerver_log_error (
			"silverse_custom_auth () "
			"Failed to get token from request's \"Authorization\" header!"
		);
	}
	#endif

	return retval;

}
