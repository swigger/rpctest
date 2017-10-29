#pragma once

#include "shared.h"
#include "kms_io.h"

#define ENABLE_DEGUG_DUMP 1

#if ENABLE_DEGUG_DUMP+0
void dbg_dump_req(const REQUEST_V6& r);
void dbg_dump_responce(const RESPONSE_V6& r);

#endif
