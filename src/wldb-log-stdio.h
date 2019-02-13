#pragma once

#include <stdio.h>

#define WLDB_LOG(format, ...) fprintf(stderr, format "\n", __VA_ARGS__)