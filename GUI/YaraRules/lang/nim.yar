// severity: safe
rule Lang_Nim {
    meta:
        description = "Nim compiled binary — Nim runtime or GC symbols"
    strings:
        $nimrt  = "NimMain" ascii
        $nimgc  = "nimGCinit" ascii
        $nimobj = "nimNewObj" ascii
        $nimstr = "fatal.nim" ascii
        $nimerr = "SIGSEGV: Illegal storage access." ascii
        $nimeq  = "nimEqStr" ascii
    condition:
        2 of them
}
