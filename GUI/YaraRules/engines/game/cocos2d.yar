// severity: safe
rule Engine_Cocos2d {
    meta:
        description = "Cocos2d / Cocos Creator game engine binary"
    strings:
        $cocos1 = "cocos2d" ascii nocase
        $cocos2 = "Cocos Creator" ascii nocase
        $cocos3 = "CCDirector" ascii
        $cocos4 = "CCScene" ascii
        $cocos5 = "CCNode" ascii
        $cocos6 = "CCSprite" ascii
        $cocos7 = "cocos/cocos2d" ascii nocase
        $cocos8 = "libcocos2d" ascii nocase
    condition:
        2 of them
}
