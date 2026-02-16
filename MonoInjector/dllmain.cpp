// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <cstdint>
#include "Utils/Utils.h/lazy_import.h"
#include "Utils/Utils.h/Utils.h"
#include "Utils/Utils.h/dll_buffer.h"
#include "HookLib.h"
#include <Psapi.h>

#include <MinHook.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

wchar_t g_ImageName[ MAX_PATH ];


struct _RTL_BALANCED_NODE
{
	union
	{
		struct _RTL_BALANCED_NODE* Children[ 2 ];                             //0x0
		struct
		{
			struct _RTL_BALANCED_NODE* Left;                                //0x0
			struct _RTL_BALANCED_NODE* Right;                               //0x8
		};
	};
	union
	{
		struct
		{
			UCHAR Red : 1;                                                    //0x10
			UCHAR Balance : 2;                                                //0x10
		};
		ULONGLONG ParentValue;                                              //0x10
	};
};

struct __LDR_DATA_TABLE_ENTRY
{
	struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
	struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
	struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
	VOID* DllBase;                                                          //0x30
	VOID* EntryPoint;                                                       //0x38
	ULONG SizeOfImage;                                                      //0x40
	UNICODE_STRING FullDllName;                                     //0x48
	UNICODE_STRING BaseDllName;                                     //0x58
	union
	{
		UCHAR FlagGroup[ 4 ];                                                 //0x68
		ULONG Flags;                                                        //0x68
		struct
		{
			ULONG PackagedBinary : 1;                                         //0x68
			ULONG MarkedForRemoval : 1;                                       //0x68
			ULONG ImageDll : 1;                                               //0x68
			ULONG LoadNotificationsSent : 1;                                  //0x68
			ULONG TelemetryEntryProcessed : 1;                                //0x68
			ULONG ProcessStaticImport : 1;                                    //0x68
			ULONG InLegacyLists : 1;                                          //0x68
			ULONG InIndexes : 1;                                              //0x68
			ULONG ShimDll : 1;                                                //0x68
			ULONG InExceptionTable : 1;                                       //0x68
			ULONG ReservedFlags1 : 2;                                         //0x68
			ULONG LoadInProgress : 1;                                         //0x68
			ULONG LoadConfigProcessed : 1;                                    //0x68
			ULONG EntryProcessed : 1;                                         //0x68
			ULONG ProtectDelayLoad : 1;                                       //0x68
			ULONG ReservedFlags3 : 2;                                         //0x68
			ULONG DontCallForThreads : 1;                                     //0x68
			ULONG ProcessAttachCalled : 1;                                    //0x68
			ULONG ProcessAttachFailed : 1;                                    //0x68
			ULONG CorDeferredValidate : 1;                                    //0x68
			ULONG CorImage : 1;                                               //0x68
			ULONG DontRelocate : 1;                                           //0x68
			ULONG CorILOnly : 1;                                              //0x68
			ULONG ChpeImage : 1;                                              //0x68
			ULONG ReservedFlags5 : 2;                                         //0x68
			ULONG Redirected : 1;                                             //0x68
			ULONG ReservedFlags6 : 2;                                         //0x68
			ULONG CompatDatabaseProcessed : 1;                                //0x68
		};
	};
	USHORT ObsoleteLoadCount;                                               //0x6c
	USHORT TlsIndex;                                                        //0x6e
	struct _LIST_ENTRY HashLinks;                                           //0x70
	ULONG TimeDateStamp;                                                    //0x80
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
	VOID* Lock;                                                             //0x90
	struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
	struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
	struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
	VOID* ParentDllBase;                                                    //0xb8
	VOID* SwitchBackContext;                                                //0xc0
	struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
	struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
	ULONGLONG OriginalBase;                                                 //0xf8
	union _LARGE_INTEGER LoadTime;                                          //0x100
	ULONG BaseNameHashValue;                                                //0x108
	enum class _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
	ULONG ImplicitPathOptions;                                              //0x110
	ULONG ReferenceCount;                                                   //0x114
	ULONG DependentLoadFlags;                                               //0x118
	UCHAR SigningLevel;                                                     //0x11c
};


uint64_t m_mono_module = 0;

void __cdecl free_base( uint64_t Block )
{
	int* v1; // rbx
	DWORD LastError; // eax

	if ( Block )
	{
		auto hHeap = *reinterpret_cast< uint64_t** >( m_mono_module + 0x4A1D40 );
		if ( !HeapFree( hHeap, 0, ( VOID* )Block ) )
		{
			LastError = GetLastError( );
		}
	}
}

void __fastcall mono_free_0( uint64_t Block )
{
	if ( Block )
		free_base( Block );
}

void mono_error_cleanup( __int16* a1 )
{
	__int16 v1; // di
	int v2; // esi

	v1 = *a1;
	v2 = a1[ 1 ] & 1;
	if ( ( a1[ 1 ] & 4 ) != 0 )
		return;
	*( uint64_t* )a1 = 0xFFFF;
	if ( v1 )
	{
		//if ( v1 == 10 )
		//	mono_gchandle_free( *( ( unsigned int* )a1 + 12 ) );
		mono_free_0( *( ( uint64_t* )a1 + 7 ) );
		mono_free_0( *( ( uint64_t* )a1 + 8 ) );
		*( ( uint64_t* )a1 + 7 ) = 0i64;
		*( ( uint64_t* )a1 + 8 ) = 0i64;
		if ( v2 )
		{
			mono_free_0( *( ( uint64_t* )a1 + 1 ) );
			mono_free_0( *( ( uint64_t* )a1 + 2 ) );
			mono_free_0( *( ( uint64_t* )a1 + 3 ) );
			mono_free_0( *( ( uint64_t* )a1 + 4 ) );
			mono_free_0( *( ( uint64_t* )a1 + 5 ) );
			mono_free_0( *( ( uint64_t* )a1 + 9 ) );
			mono_free_0( *( ( uint64_t* )a1 + 10 ) );
			*( ( uint64_t* )a1 + 10 ) = 0i64;
			*( ( uint64_t* )a1 + 9 ) = 0i64;
			*( ( uint64_t* )a1 + 5 ) = 0i64;
			*( ( uint64_t* )a1 + 4 ) = 0i64;
			*( ( uint64_t* )a1 + 3 ) = 0i64;
			*( ( uint64_t* )a1 + 2 ) = 0i64;
			*( ( uint64_t* )a1 + 1 ) = 0i64;
			*( ( uint64_t* )a1 + 6 ) = 0i64;
		}
	}
}

template <typename T, typename T1>
T mono_compile_method_recreated( T1 addr )
{
	int v3[ 30 ]; // [rsp+20h] [rbp-78h] BYREF
	auto& xmmword_49C830 = *reinterpret_cast< uint64_t* >( m_mono_module + 0x49C830 );
	v3[ 0 ] = 0;
	if ( !*( &xmmword_49C830 + 1 ) )
		return 0;
	auto v1 = reinterpret_cast< T( * )( T1, int* ) >( *( &xmmword_49C830 + 1 ) )( addr, v3 );
	mono_error_cleanup( ( short* )v3 );
	return v1;
}



EXTERN_C __declspec( dllexport ) LRESULT HardlineNvidiaOverlay( UINT code, WPARAM wp, LPARAM lp )
{
	return LI_FIND( CallNextHookEx ) ( NULL, code, wp, lp );
}

void* g_NtCreateFile = nullptr;

NTSTATUS NtCreateFileHk( PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
						 POBJECT_ATTRIBUTES ObjectAttributes, PVOID IoStatusBlock,
						 PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
						 ULONG ShareAccess, ULONG CreateDisposition,
						 ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength )

{
	const auto object_name = reinterpret_cast< const wchar_t* >( ObjectAttributes->ObjectName->Buffer );
	if ( object_name && ( wcsstr( object_name, g_ImageName ) || wcsstr( object_name, L"BugSplat64.dll" ) || wcsstr( object_name, L"ntdll.dll" ) ) )
		return STATUS_ACCESS_VIOLATION;

	return reinterpret_cast< decltype( &NtCreateFileHk ) >( g_NtCreateFile )(
		FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
		AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
		CreateOptions, EaBuffer, EaLength );
}

void* __fastcall sub_180004A10( void* Src, size_t Size )
{
	size_t v4; // rdi
	void* v5; // rax
	void* v6; // rbx

	if ( !Src )
		return 0i64;
	v4 = ( unsigned int )Size;
	if ( !( DWORD )Size )
		return 0i64;
	v5 = malloc( ( unsigned int )Size );
	v6 = v5;
	if ( !v5 )
	{
		while ( 1 )
			;
	}
	memmove( v5, Src, v4 );
	return v6;
}

void* sub_180001870( )
{
	return reinterpret_cast< void* >( LI_MODULE_SAFE_( ( "mono-2.0-bdwgc.dll" ) ) + 0x04A2438 );
}

__int64 __fastcall sub_18006D430( void* Src, size_t Size, int a3, DWORD* a4, char a5, char a6, void* Srca )
{
	size_t v7; // r14
	char v9; // si
	void* v11; // rbp
	void* v12; // rax
	uint64_t v14; // rbx
	__int64 v15; // rax
	__int64 v16; // rax
	__int64 v18; // rax
	__int64 v19; // rax

	static auto sub_18006A400 = reinterpret_cast< uint64_t( * )( uint64_t, DWORD*, int ) >( LI_MODULE_SAFE_( ( "mono-2.0-bdwgc.dll" ) ) + 0x6A400 );
	static auto sub_18006E0E0 = reinterpret_cast< uint64_t( * )( uint64_t ) >( LI_MODULE_SAFE_( ( "mono-2.0-bdwgc.dll" ) ) + 0x6E0E0 );
	static auto sub_180004B80 = reinterpret_cast< uint64_t( * )( uint32_t ) >( LI_MODULE_SAFE_( ( "mono-2.0-bdwgc.dll" ) ) + 0x4B80 );
	static auto sub_180004AE0 = reinterpret_cast< uint64_t( * )( uint32_t ) >( LI_MODULE_SAFE_( ( "mono-2.0-bdwgc.dll" ) ) + 0x4AE0 );

	v7 = ( unsigned int )Size;
	v9 = a3;
	if ( Src && ( DWORD )Size )
	{
		v11 = Src;
		if ( a3 )
		{
			v12 = ( void* )malloc( ( unsigned int )Size );
			v11 = v12;
			if ( !v12 )
			{
				if ( a4 )
					*a4 = 1;
				return 0i64;
			}
			memmove( v12, Src, v7 );
		}
		v14 = ( uint64_t )sub_180004AE0( 0x730ui64 );
		*( BYTE* )( v14 + 28 ) &= ~2u;
		*( BYTE* )( v14 + 28 ) |= 2 * ( v9 & 1 );
		*( void** )( v14 + 16 ) = v11;
		*( size_t* )( v14 + 24 ) = v7;
		if ( Srca )
		{
			v16 = -1i64;
			while ( *( ( BYTE* )Srca + ++v16 ) != 0 )
				;
			v15 = ( uint64_t )sub_180004A10( Srca, ( unsigned int )( v16 + 1 ) );
		}
		else
		{
			v15 = ( uint64_t )reinterpret_cast< uint64_t( * )( char* ) >( LI_MODULE_SAFE_( ( "mono-2.0-bdwgc.dll" ) ) + 0x6300 ) ( ( char* )"data-%p" );
		}
		*( uint64_t* )( v14 + 32 ) = v15;
		v18 = ( uint64_t )sub_180004AE0( 0x198ui64 );
		*( BYTE* )( v14 + 28 ) &= ~0x40u;
		*( BYTE* )( v14 + 29 ) &= ~1u;
		*( uint64_t* )( v14 + 80 ) = v18;
		*( DWORD* )v14 = 1;
		*( BYTE* )( v14 + 28 ) |= ( a5 & 1 ) << 6;
		*( BYTE* )( v14 + 29 ) |= a6 & 1;
		v19 = sub_18006A400( v14, a4, 1i64 );
		return v19;
		return 0i64;
	}
	if ( a4 )
		*a4 = 3;
	return 0i64;
}

__int64 __fastcall mono_image_open_from_data( void* a1, size_t a2 )
{
	return sub_18006D430( a1, a2, 0, 0, 0i64, 0, 0 );
}

void __fastcall sub_1800C7DD0( __int64 a1 )
{
	uint64_t* v1; // rbx
	void( __fastcall * v3 )( uint64_t, __int64 ); // rax
	auto qword_1804A1FE8 = *reinterpret_cast< uint64_t* >( LI_MODULE_SAFE_( ( "mono-2.0-bdwgc.dll" ) ) + 0x4A1FE8 );
	v1 = ( uint64_t* )qword_1804A1FE8;
	if ( qword_1804A1FE8 )
	{
		do
		{
			v3 = ( void( __fastcall* )( uint64_t, __int64 ) )v1[ 32 ];
			if ( v3 )
				v3( v1[ 1 ], a1 );
			v1 = ( uint64_t* )*v1;
		} while ( v1 );
	}
}

__int64 __fastcall mono_metadata_string_heap( __int64 a1, unsigned int a2 )
{
	return *( uint64_t* )( a1 + 0x68 ) + a2;
}

__int64 __fastcall mono_metadata_blob_heap( __int64 a1, unsigned int a2 )
{
	return *( uint64_t* )( a1 + 136 ) + a2;
}

__int64 __fastcall mono_metadata_decode_blob_size( char* a1, uint64_t* a2 )
{
	char v2; // r8
	unsigned int v3; // er8
	__int64 v4; // rax
	int v5; // eax
	int v6; // er8

	v2 = *a1;
	if ( *a1 < 0 )
	{
		v5 = ( unsigned __int8 )a1[ 1 ];
		if ( ( *a1 & 0x40 ) != 0 )
		{
			v6 = ( ( unsigned __int8 )a1[ 2 ] << 8 ) + ( v5 << 16 ) + ( ( v2 & 0x1F ) << 24 );
			v4 = 4i64;
			v3 = ( unsigned __int8 )a1[ 3 ] + v6;
		}
		else
		{
			v3 = v5 + ( ( v2 & 0x3F ) << 8 );
			v4 = 2i64;
		}
	}
	else
	{
		v3 = v2 & 0x7F;
		v4 = 1i64;
	}
	if ( a2 )
		*a2 = ( uint64_t ) &a1[ v4 ];
	return v3;
}

__int64 __fastcall mono_digest_get_public_token( BYTE* a1 )
{
	__int64 result; // rax
	int v3[ 5 ]; // [rsp+30h] [rbp-88h] BYREF
	__int64 v4; // [rsp+44h] [rbp-74h]
	char v5[ 12 ]; // [rsp+90h] [rbp-28h] BYREF
	unsigned __int8 v6 = 0; // [rsp+9Ch] [rbp-1Ch]
	char v7 = 0; // [rsp+9Dh] [rbp-1Bh]
	char v8 = 0; // [rsp+9Eh] [rbp-1Ah]
	char v9 = 0; // [rsp+9Fh] [rbp-19h]
	char v10 = 0; // [rsp+A0h] [rbp-18h]
	char v11 = 0; // [rsp+A1h] [rbp-17h]
	char v12 = 0; // [rsp+A2h] [rbp-16h]
	char v13 = 0; // [rsp+A3h] [rbp-15h]

	v3[ 0 ] = 1732584193;
	v4 = 0i64;
	v3[ 1 ] = -271733879;
	v3[ 2 ] = -1732584194;
	v3[ 3 ] = 271733878;
	v3[ 4 ] = -1009589776;
	Utils::CallExportByName<void>( "mono_sha1_update", v3 );
	Utils::CallExportByName<void>( "mono_sha1_final", v3, v5 );
	*a1 = v13;
	a1[ 1 ] = v12;
	a1[ 2 ] = v11;
	a1[ 3 ] = v10;
	a1[ 4 ] = v9;
	a1[ 5 ] = v8;
	a1[ 6 ] = v7;
	result = v6;
	a1[ 7 ] = v6;
	return result;
}

__int64 __fastcall sub_18002FA40( __int64 a1, __int64 a2, int a3 )
{
	__int64 v5; // rcx
	__int64 v8; // rdx
	__int64 v9; // rax
	__int64 v10; // rdi
	BYTE* v11; // rcx
	__int64 v12; // rax
	bool v13; // zf
	__int64 v14; // rax
	BYTE* v15; // rax
	__int64 v16; // rax
	__int64 v17; // rsi
	unsigned int v18; // eax
	__int64 v19; // rdx
	__int64 v20; // rdi
	__int64 v21; // rax
	int v22; // eax
	size_t v23; // rsi
	void* v24; // rdi
	__int64 v25; // rax
	int v26; // edx
	__int64 v27; // [rsp+20h] [rbp-68h] BYREF
	int v28; // [rsp+28h] [rbp-60h] BYREF
	__int16 v29 = 0; // [rsp+2Ch] [rbp-5Ch]
	__int16 v30 = 0; // [rsp+30h] [rbp-58h]
	__int16 v31 = 0; // [rsp+34h] [rbp-54h]
	__int16 v32 = 0; // [rsp+38h] [rbp-50h]
	int v33 = 0; // [rsp+3Ch] [rbp-4Ch]
	unsigned int v34 = 0; // [rsp+40h] [rbp-48h]
	unsigned int v35 = 0; // [rsp+44h] [rbp-44h]
	unsigned int v36 = 0; // [rsp+48h] [rbp-40h]

	v5 = a1 + 736;
	if ( ( *( DWORD* )( v5 + 8 ) & 0xFFFFFF ) == 0 )
		return 0i64;
	Utils::CallExportByName<void>( "mono_metadata_decode_row", v5, 0i64, &v28, 9i64 );
	v8 = v35;
	*( DWORD* )( a2 + 56 ) = 0;
	*( uint64_t* )( a2 + 16 ) = 0i64;
	v9 = mono_metadata_string_heap( a1, v8 );
	v10 = -1i64;
	*( uint64_t* )a2 = v9;
	v11 = ( BYTE* )v9;
	if ( a3 )
	{
		if ( v9 )
		{
			v12 = -1i64;
			do
				v13 = v11[ ++v12 ] == 0;
			while ( !v13 );
			v14 = ( uint64_t )sub_180004A10( v11, ( unsigned int )( v12 + 1 ) );
		}
		else
		{
			v14 = 0i64;
		}
		*( uint64_t* )a2 = v14;
	}
	v15 = ( BYTE* )mono_metadata_string_heap( a1, v36 );
	*( uint64_t* )( a2 + 8 ) = ( uint64_t ) v15;
	if ( a3 )
	{
		if ( v15 )
		{
			do
				v13 = v15[ ++v10 ] == 0;
			while ( !v13 );
			v16 = ( uint64_t ) sub_180004A10( v15, ( unsigned int )( v10 + 1 ) );
		}
		else
		{
			v16 = 0i64;
		}
		*( uint64_t* )( a2 + 8 ) = v16;
	}

	static auto m_mono = LI_MODULE_SAFE_( ( "mono-2.0-bdwgc.dll" ) );
	static auto sub_18002E810 = reinterpret_cast< uint64_t( * )( uint64_t, int ) >( m_mono + 0x2E810 );
	static auto sub_1800069A0 = reinterpret_cast< uint64_t( * )( uint64_t, uint64_t, int ) >( m_mono + 0x69A0 );

	*( DWORD* )( a2 + 60 ) = v33;
	*( WORD* )( a2 + 64 ) = v29;
	*( WORD* )( a2 + 66 ) = v30;
	*( WORD* )( a2 + 68 ) = v31;
	*( WORD* )( a2 + 70 ) = v32;
	*( DWORD* )( a2 + 52 ) = v28;
	if ( v34 )
	{
		v17 = ( uint64_t ) malloc( 8i64 );
		v27 = mono_metadata_blob_heap( a1, v34 );
		v18 = mono_metadata_decode_blob_size( ( char* )v27, ( uint64_t* ) &v27 );
		v19 = v27;
		*( uint64_t* )( a2 + 24 ) = v27;
		mono_digest_get_public_token( ( BYTE* ) v17 );
		v20 = sub_18002E810( v17, 8i64 );
		sub_1800069A0( a2 + 32, v20, 17i64 );
		mono_free_0( v20 );
		mono_free_0( v17 );
		if ( v34 )
		{
			v21 = mono_metadata_blob_heap( a1, v34 );
			*( uint64_t* )( a2 + 24 ) = v21;
			if ( a3 )
			{
				v22 = mono_metadata_decode_blob_size( ( char* ) v21, ( uint64_t* )&v27 );
				v27 += v22;
				v23 = v27 - *( uint64_t* )( a2 + 24 );
				v24 = ( void* )malloc( v23 );
				memmove( v24, *( const void** )( a2 + 24 ), v23 );
				*( uint64_t* )( a2 + 24 ) = ( uint64_t ) v24;
			}
			goto LABEL_22;
		}
	}
	else
	{
		*( uint64_t* )( a2 + 24 ) = 0i64;
		*( uint64_t* )( a2 + 32 ) = 0i64;
		*( uint64_t* )( a2 + 40 ) = 0i64;
		*( BYTE* )( a2 + 48 ) = 0;
	}
	*( uint64_t* )( a2 + 24 ) = 0i64;
LABEL_22:
	v25 = *( uint64_t* )( a1 + 80 );
	v26 = *( DWORD* )( v25 + 288 );
	switch ( *( WORD* )( v25 + 4 ) )
	{
		case 0x14C:
			if ( ( v26 & 0x20002 ) != 0 )
				*( WORD* )( a2 + 72 ) = 2;
			else
				*( WORD* )( a2 + 72 ) = ( v26 & 0x70 ) != 112;
			break;
		case 0x1C4:
			*(WORD* )( a2 + 72 ) = 5;
			break;
		case 0x200:
			*( WORD* )( a2 + 72 ) = 3;
			break;
		default:
			if ( *( unsigned __int16* )( v25 + 4 ) == 34404 )
				*( WORD* )( a2 + 72 ) = 4;
			break;
	}
	return 1i64;
}

__int64 __fastcall sub_180030A70(
	const char** a1,
	BYTE* a2,
	unsigned int a3,
	unsigned int( __fastcall* a4 )( __int64, __int64 ),
	__int64 a5,
	DWORD* a6 )
{
	static auto m_mono = LI_MODULE_SAFE_( ( "mono-2.0-bdwgc.dll" ) );
	__int64 result; // rax
	__int64 v10; // rbx
	__int64 v11; // rax
	char* v13; // rdi
	int v14; // ebx
	char* v15; // rax
	__int64 v16; // rcx
	__int64 v17; // rbp
	__int64 v18; // rax
	__int64 v19; // rdi
	__int64 v20; // r14
	const char* v21; // rbx
	__int64 v22; // rcx
	__int64 i; // rbx
	int v24[ 28 ]; // [rsp+40h] [rbp-98h] BYREF
	int v25; // [rsp+E0h] [rbp+8h] BYREF

	if ( ( ( DWORD )a1[ 93 ] & 0xFFFFFF ) == 0 )
	{
		*a6 = 3;
		return 0i64;
	}
	v10 = -1i64;
	if ( a2 )
	{
		v11 = -1i64;
		while ( a2[ ++v11 ] != 0 )
			;
		v13 = ( char* )sub_180004A10( a2, ( unsigned int )( v11 + 1 ) );
	}
	else
	{
		v13 = 0i64;
	}
	do
		++v10;
	while ( v13[ v10 ] );
	v14 = v10 - 1;
	if ( v14 >= 0 )
	{
		v15 = &v13[ v14 ];
		v16 = v14 + 1i64;
		do
		{
			if ( *v15 == 47 )
				*v15 = 92;
			--v15;
			--v16;
		} while ( v16 );
	}
	static auto sub_18002DD20 = reinterpret_cast< uint64_t( * )( char* ) > ( m_mono + 0x2DD20 );
	static auto sub_1800300B0 = reinterpret_cast< uint64_t( * )( uint64_t, int, uint32_t, int ) > ( m_mono + 0x300B0 );
	static auto sub_180110060 = reinterpret_cast< uint64_t( * )( uint64_t, uint64_t, int* ) > ( m_mono + 0x300B0 );

	v17 = sub_18002DD20( v13 );
	mono_free_0( ( uint64_t ) v13 );
	v18 = ( uint64_t )malloc( 0x80ui64 );
	v19 = v18;
	*( uint64_t* )( v18 + 8 ) = v17;
	*( DWORD* )( v18 + 116 ) = a3;
	*( uint64_t* )( v18 + 96 ) = ( uint64_t ) a1;
	if ( *reinterpret_cast< int* >( m_mono + 0x4A20EC ) )
		sub_1800C7DD0( v18 );
	sub_18002FA40( ( uint64_t ) a1, v19 + 16, 0i64 );
	if ( *( uint64_t* )( m_mono + 0x4A21A0 ) && !strcmp( *( const char** )( v19 + 16 ), "mscorlib" ) )
	{
		mono_free_0( v19 );
		mono_free_0( v17 );
		//mono_image_addref( *( uint64_t* )&qword_1804A21A0 );
		//*a6 = 0;
		//return *( uint64_t* )( *( uint64_t* )&qword_1804A21A0 + 1200i64 );
	}
	//mono_image_addref( a1 );
	if ( *( uint64_t* )( v19 + 16 ) )
	{
		v20 = sub_1800300B0( v19 + 16, 0i64, a3, 0i64 );
		if ( v20 )
		{
			mono_free_0( v19 );
			mono_free_0( v17 );
			result = v20;
			*a6 = 0;
			return result;
		}
	}
	if ( !a3 )
		v24[ 0 ] = 0;
	v25 = 0;
	sub_180110060( v19, m_mono + 0x2EBC0, &v25 );
	if ( v25 )
	{
LABEL_33:
		mono_free_0( v19 );
		mono_free_0( v17 );
		*a6 = 3;
		return 0i64;
	}
	mono_error_cleanup( ( short* )v24 );
}

__int64 __fastcall mono_assembly_load_from( const char** a1, BYTE* a2, DWORD* a3 )
{
	return sub_180030A70( a1, a2, 0, 0i64, 0i64, a3 );
}

JitHook PreLoaderUiUpdateHk;
void* PreloaderUIUpdate( void* component )
{
	auto raw_image = mono_image_open_from_data( ( void* )dll_array, sizeof( dll_array ) );
	auto assembly = Utils::CallExportByName<uint64_t>( "mono_assembly_load_from", raw_image, dll_array, 0 );
	auto image = Utils::CallExportByName<uint64_t>( "mono_assembly_get_image", assembly );

	auto method = Utils::CallExportByName<uint64_t>( "mono_class_get_method_from_name", Utils::CallExportByName<uint64_t>( "mono_class_from_name", image, "MonoCheat", "Entry" ), "Init", 0 );
	uint64_t method_ptr = mono_compile_method_recreated<uint64_t>( method );

	reinterpret_cast< void( * )( ) >( method_ptr )( );
	PreLoaderUiUpdateHk.Unload( );
	return nullptr;
}

void start( void* mod_instance )
{
	K32GetModuleBaseNameW( GetCurrentProcess( ), ( HMODULE )mod_instance, g_ImageName,
						   sizeof( g_ImageName ) / sizeof( wchar_t ) );


	auto module_instance = mod_instance;
	const auto peb = reinterpret_cast< _PEB* >( __readgsqword( 0x60 ) );
	const auto list_entry = reinterpret_cast< LIST_ENTRY* >( peb->Ldr->InMemoryOrderModuleList.Flink );
	auto first_module = reinterpret_cast< __LDR_DATA_TABLE_ENTRY* >( CONTAINING_RECORD( list_entry,
																	 __LDR_DATA_TABLE_ENTRY,
																	 InMemoryOrderLinks ) );
	decltype( first_module ) our_module = 0;
	decltype( first_module ) ntdll = 0;
	auto current_module = reinterpret_cast< __LDR_DATA_TABLE_ENTRY* >( first_module );
	do
	{
		if ( current_module->DllBase == module_instance )
		{
			our_module = reinterpret_cast< decltype( our_module ) >( current_module );
		}
		if ( wcsstr( current_module->FullDllName.Buffer, L"tdll" ) )
		{
			ntdll = reinterpret_cast< decltype( ntdll ) >( current_module );
		}
		if ( ntdll && our_module )
		{
			break;
		}
		current_module = reinterpret_cast< __LDR_DATA_TABLE_ENTRY* >( current_module->InLoadOrderLinks.Flink );
	} while ( current_module != first_module );

	if ( LoadLibraryW( our_module->FullDllName.Buffer ) != module_instance )
	{
		std::quick_exit( -1 );
	}

	our_module->SigningLevel = ntdll->SigningLevel;
	our_module->LoadReason = ntdll->LoadReason;
	our_module->BaseNameHashValue = ntdll->BaseNameHashValue;
	our_module->LoadTime = ntdll->LoadTime;
	our_module->TimeDateStamp = ntdll->TimeDateStamp;

	RtlInitUnicodeString( &our_module->BaseDllName, L"C:\\Windows\\System32\\ntdll.dll" );
	RtlInitUnicodeString( &our_module->FullDllName, L"C:\\Windows\\System32\\ntdll.dll" );

	if ( MH_Initialize( ) != MH_OK )
		return;

	if ( MH_CreateHookApi( L"ntdll.dll", "NtCreateFile", &NtCreateFileHk, &g_NtCreateFile ) != MH_OK )
		return;

	if ( MH_EnableHook( MH_ALL_HOOKS ) != MH_OK )
		return;

	m_mono_module = LI_MODULE_SAFE_( ( "mono-2.0-bdwgc.dll" ) );

	PreLoaderUiUpdateHk.StartHook( &PreloaderUIUpdate, ( "EFT.UI" ), ( "PreloaderUI" ), ( "Update" ) );

}

extern "C" __declspec( dllexport ) BOOL APIENTRY DllMain( HMODULE hModule,
														  DWORD  ul_reason_for_call,
														  LPVOID lpReserved
)
{
	switch ( ul_reason_for_call )
	{
		case DLL_PROCESS_ATTACH:
		{
			LI_FIND( CreateThread ) ( reinterpret_cast< LPSECURITY_ATTRIBUTES >( NULL ), 0, reinterpret_cast< LPTHREAD_START_ROUTINE >( start ), reinterpret_cast< LPVOID >( hModule ), 0, nullptr );
		}
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}

