// severity: safe
rule Lang_Lua_Bytecode {
    meta:
        description = "Lua bytecode header signature"
    strings:
        $sig = { 1B 4C 75 61 }
    condition:
        $sig
}

// severity: safe
rule Lang_Lua_Runtime {
    meta:
        description = "Lua / LuaJIT runtime embedded — stable C API present"
    strings:
        // Stable Lua C API functions (unchanged across Lua 5.1–5.5, LuaJIT 2.x)
        $newstate  = "lua_newstate" ascii
        $lnewstate = "luaL_newstate" ascii
        $luajit    = "LuaJIT" ascii
        $luaopen   = "luaopen_" ascii
        $pcall     = "lua_pcall" ascii
        $tostring  = "lua_tostring" ascii
        $errmsg    = "attempt to index" ascii
    condition:
        $luajit or 2 of ($newstate, $lnewstate, $luaopen, $pcall, $tostring, $errmsg)
}
