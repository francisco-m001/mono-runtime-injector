#pragma once

namespace Utils
{
    template<typename Ret, typename... Args>
    static inline auto SafeCall( Ret( *fn )( Args... ), Args... args ) -> Ret
    {
        return fn( args... );
    }
}