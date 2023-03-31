#ifndef _SILVERSE_AUTH_VERSION_H_
#define _SILVERSE_AUTH_VERSION_H_

#include "auth/config.h"

#define SILVERSE_AUTH_VERSION			"0.1"
#define SILVERSE_AUTH_VERSION_NAME		"Version 0.1"
#define SILVERSE_AUTH_VERSION_DATE		"30/03/2023"
#define SILVERSE_AUTH_VERSION_TIME		"22:30 CST"
#define SILVERSE_AUTH_VERSION_AUTHOR	"Erick Salas"

#ifdef __cplusplus
extern "C" {
#endif

// print full silverse libauth version information
AUTH_PUBLIC void silverse_libauth_version_print_full (void);

// print the version id
AUTH_PUBLIC void silverse_libauth_version_print_version_id (void);

// print the version name
AUTH_PUBLIC void silverse_libauth_version_print_version_name (void);

#ifdef __cplusplus
}
#endif

#endif
