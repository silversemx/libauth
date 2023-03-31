#include <cerver/utils/log.h>

#include "auth/version.h"

// print full libauth version information
void silverse_libauth_version_print_full (void) {

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"\nSilverse libauth Version: %s", SILVERSE_AUTH_VERSION_NAME
	);

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"Release Date & time: %s - %s", SILVERSE_AUTH_VERSION_DATE, SILVERSE_AUTH_VERSION_TIME
	);

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"Author: %s\n", SILVERSE_AUTH_VERSION_AUTHOR
	);

}

// print the version id
void silverse_libauth_version_print_version_id (void) {

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"\nSilverse libauth Version ID: %s\n", SILVERSE_AUTH_VERSION
	);

}

// print the version name
void silverse_libauth_version_print_version_name (void) {

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"\nSilverse libauth Version: %s\n", SILVERSE_AUTH_VERSION_NAME
	);

}
