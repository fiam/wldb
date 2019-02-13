#pragma once

#include <stddef.h>

#if defined(HAS_WLDB_CUSTOM_TYPES_H)
#include "wldb-custom-types.h"
#else
typedef ptrdiff_t wldb_addr_t;
#endif
