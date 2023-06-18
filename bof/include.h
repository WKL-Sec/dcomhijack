#pragma once

#include <windows.h>
#include <combaseapi.h>
#include "beacon.h"

#define D_API( x )    __typeof__( x ) * x
#define U_PTR( x )    ( ( ULONG_PTR ) x )
#define C_PTR( x )    ( ( PVOID ) x )
