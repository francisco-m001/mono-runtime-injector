// credits for learn_more for his epic copy pasted findpattern
#include <Windows.h>
#include <Psapi.h>

#include "pattern.h"
#include "Utils/Utils.h/lazy_import.h"

#define in_range(x,a,b) (x>=a&&x<=b) 
#define get_bits(x) (in_range((x&(~0x20)),'A','F')?((x&(~0x20))-'A'+0xa):(in_range(x,'0','9')?x-'0':0))
#define get_byte(x) (get_bits(x[0])<<4|get_bits(x[1]))

uintptr_t pattern::find( uintptr_t range_start, uintptr_t range_end, const char* pattern )
{
	const char* pattern_bytes = pattern;

	uintptr_t first_match = 0;

	for ( uintptr_t cur_byte = range_start; cur_byte < range_end; cur_byte++ )
	{
		if ( !*pattern_bytes )
			return first_match;

		if ( *( uint8_t* )pattern_bytes == '\?' || *( uint8_t* )cur_byte == static_cast< uint8_t >( get_byte( pattern_bytes ) ) )
		{
			if ( !first_match )
				first_match = cur_byte;

			if ( !pattern_bytes[ 2 ] )
				return first_match;

			if ( *( uint16_t* )pattern_bytes == '\?\?' || *( uint8_t* )pattern_bytes != '\?' )
				pattern_bytes += 3;
			else
				pattern_bytes += 2;
		}
		else
		{
			pattern_bytes = pattern;
			first_match = 0;
		}
	}

	return 0;
}

uintptr_t pattern::find( const char* mod, const char* pattern )
{
	const char* pattern_bytes = pattern;

	uintptr_t range_start = ( uint64_t )LI_MODULE_SAFE_( mod );

	uintptr_t range_end = range_start + LI_MODULESIZE_SAFE_( mod );

	return find( range_start, range_end, pattern );
}


MODULEINFO GetModuleInfo( char* szModule )
{
	MODULEINFO modinfo = { 0 };
	HMODULE hModule = LI_FIND( GetModuleHandleA )( ( LPCSTR )szModule );
	if ( hModule == 0 )
		return modinfo;
	LI_FIND( K32GetModuleInformation )( LI_FIND( GetCurrentProcess )( ), hModule, &modinfo, ( DWORD )sizeof( MODULEINFO ) );
	return modinfo;
}

uintptr_t pattern::find_module_handle( const char* mod, const char* pattern )
{
	const char* pattern_bytes = pattern;

	uintptr_t range_start = ( uint64_t ) LI_FIND( GetModuleHandleA )( ( LPCSTR )mod );

	uintptr_t range_end = range_start + GetModuleInfo( ( char* )mod ).SizeOfImage;

	return find( range_start, range_end, pattern );
}


uintptr_t pattern::find_rel( const char* mod, const char* pattern, ptrdiff_t position, ptrdiff_t jmp_size, ptrdiff_t instruction_size )
{
	auto result = find_module_handle( mod, pattern );

	if ( !result ) return 0;

	result += position;

	auto rel_addr = *reinterpret_cast< int32_t* >( result + jmp_size );
	auto abs_addr = result + instruction_size + rel_addr;

	return abs_addr;
}

uint32_t pattern::find_offset32( const char* mod, const char* pattern, ptrdiff_t position )
{
	auto result = find( mod, pattern );

	if ( !result ) return 0;

	result += position;

	auto mod_base = LI_MODULE_SAFE_( mod );

	return result - mod_base;
}

uint32_t pattern::find_offset32_rel( const char* mod, const char* pattern, ptrdiff_t position, ptrdiff_t jmp_size, ptrdiff_t instruction_size )
{
	auto result = find_rel( mod, pattern, position, jmp_size, instruction_size );

	if ( !result ) return 0;

	auto mod_base = LI_MODULE_SAFE_( mod );

	return result - mod_base;
}