#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include "Utils/Utils.h/lazy_import.h"
#include <vector>
#include "Utils/Utils.h/Utils.h"
#include "pattern.h"

void enumerator( void* callback, std::vector<void*>* vec )
{
	vec->push_back( callback );
}

uintptr_t find_method( const char* method_name, bool uses_namespace )
{
	static auto mono_method_desc_new = reinterpret_cast< uint64_t( * )( const char*, bool ) >( LI_GET_EXPORT_NOHASH( ( const char* )LI_MODULE_SAFE_( ( "mono-2.0-bdwgc.dll" ) ), ( "mono_method_desc_new" ) ) );

	const auto method_desc = mono_method_desc_new( method_name, uses_namespace );
	if ( !method_desc )
		return false;

	std::vector<void*> loaded_assemblies;
	Utils::CallExportByName<void>( "mono_assembly_foreach", ( void* )enumerator, ( void* )&loaded_assemblies );

	uint64_t methodPtr = 0;
	for ( auto assembly : loaded_assemblies )
	{
		auto img = Utils::CallExportByName<uint64_t>( "mono_assembly_get_image", assembly );
		if ( !img )
			continue;

		const auto name = *reinterpret_cast< char** >( reinterpret_cast< uint64_t >( assembly ) + 0x10 );
		const auto method = Utils::CallExportByName<uint64_t>( ( "mono_method_desc_search_in_image" ), method_desc, img );
		if ( method )
		{
			methodPtr = method;
			break;
		}
	}

	return methodPtr;
}


class JitInfo
{
public:
	uintptr_t& get_code( )
	{
		return *reinterpret_cast< uintptr_t* >( this + 0x10 );
	}
};

JitInfo* find_jit_method( uint64_t method )
{
	static auto m_mono_module = LI_MODULE_SAFE_( ( "mono-2.0-bdwgc.dll" ) );
	static auto m_offset_find_jit_method = pattern::find_offset32( ( "mono-2.0-bdwgc.dll" ), ( "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B E9 48 8B FA 48 81 C1 ? ? ? ?" ) );

	// In this case it's mini_lookup_method but w/o the third arg?
	return reinterpret_cast< JitInfo * ( * )( void*, uint64_t ) > ( m_mono_module + m_offset_find_jit_method ) ( Utils::CallExportByName<void*>( "mono_get_root_domain" ), method );
}

uint64_t dump_method_by_name( const char* _namespace, const char* class_name, const char* field_name )
{
	const auto namespaceStr = std::string( _namespace ) + ( "." );

	auto formattedMethod = namespaceStr + std::string( class_name ) + ( ":" ) + std::string( field_name );

	auto __method = find_method( formattedMethod.c_str( ), false );
	if ( !__method )
		return 0;

	auto _method = find_jit_method( __method );
	if ( !_method )
		return 0;

	return _method->get_code( );
}


class JitHook
{
public:
	const char* _namespace{ };
	const char* _klass{ };
	const char* _method{ };
	void* ourFunc{ };

	uint64_t original = 0;
	uint64_t* hook_target = nullptr;

	template <typename t>
	auto get_original( ) -> t
	{
		return reinterpret_cast< t >( original );
	}

	uint64_t padding = 100;
	bool StartHook( void* our_func, const char* _namespace, const char* _klass, const char* method )
	{
		this->_namespace = _namespace;
		this->_klass = _klass;
		this->_method = method;

		if ( original )
			return true;

		const auto targetFunction = dump_method_by_name( _namespace, _klass, method );
		if ( !targetFunction )
			return false;

		// call r11
		const auto call_xref = pattern::find( targetFunction, targetFunction + padding, ( "41 FF D3" ) );
		if ( !call_xref )
			return false;

		auto random_num_fn_ptr = reinterpret_cast< uintptr_t* >( call_xref - 8 );
		if ( !random_num_fn_ptr )
			return false;

		auto original = random_num_fn_ptr;

		this->original = *original;

		*original = reinterpret_cast< uint64_t >( our_func );

		this->hook_target = original;
	}

	void Unload( )
	{
		*this->hook_target = this->original;
	}
};