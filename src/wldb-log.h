#pragma once

#if defined(WLDB_LOG_STDIO)
#include "wldb-log-stdio.h"
#elif defined(WLDB_LOG_CUSTOM)
#include <wldb-log-custom.h>
#else
#define WLDB_LOG(format, ...)
#endif