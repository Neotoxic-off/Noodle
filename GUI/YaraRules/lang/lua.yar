// severity: safe
rule Lang_Lua {
    meta:
        description = "Lua / LuaJIT binary — embedded Lua interpreter or JIT runtime"
    strings:
        $sig     = { 1B 4C 75 61 }
        $luajit  = "LuaJIT" ascii
        $luavm   = "lua_newstate" ascii
        $luadll  = "lua51.dll" nocase ascii
        $luadll2 = "lua52.dll" nocase ascii
        $luadll3 = "lua53.dll" nocase ascii
        $luadll4 = "lua54.dll" nocase ascii
        $luaopen = "luaopen_" ascii
        $luaerr  = "attempt to index" ascii
    condition:
        $sig or $luajit or 2 of ($luavm, $luadll, $luadll2, $luadll3, $luadll4, $luaopen, $luaerr)
}
