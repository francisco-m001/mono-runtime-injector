#pragma once
#include <Windows.h>
#include "lazy_import.h"

namespace Utils
{
	template<typename T, typename ...Ts>
	inline T CallExportByName( const char* name, Ts ...args )
	{
		static auto m_mono_module = LI_MODULE_SAFE_( ( "mono-2.0-bdwgc.dll" ) );
		using fn_func_t = T( __fastcall* )( Ts... );

		const auto FunctionAddress = LI_GET_EXPORT_NOHASH( ( const char* )m_mono_module, name );
		return reinterpret_cast< T( * )( Ts... ) >( FunctionAddress )( args... );
	}
}