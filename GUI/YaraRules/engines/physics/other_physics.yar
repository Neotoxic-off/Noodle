// severity: safe
rule Physics_Bullet {
    meta:
        description = "Bullet physics engine (open source)"
    strings:
        $bt1 = "btDiscreteDynamicsWorld" ascii
        $bt2 = "btRigidBody" ascii
        $bt3 = "btCollisionShape" ascii
        $bt4 = "btBroadphaseInterface" ascii
        $bt5 = "BulletDynamics" ascii nocase
        $bt6 = "Bullet Physics" ascii nocase
    condition:
        2 of them
}

// severity: safe
rule Physics_Box2D {
    meta:
        description = "Box2D 2D physics engine"
    strings:
        $b2_1 = "b2World" ascii
        $b2_2 = "b2BodyDef" ascii
        $b2_3 = "b2FixtureDef" ascii
        $b2_4 = "b2ContactListener" ascii
        $b2_5 = "Box2D" ascii nocase fullword
    condition:
        2 of them
}

// severity: safe
rule Physics_Jolt {
    meta:
        description = "Jolt Physics engine"
    strings:
        $jolt1 = "JoltPhysics" ascii nocase
        $jolt2 = "JPH::" ascii
        $jolt3 = "PhysicsSystem" ascii
        $jolt4 = "RegisterDefaultAllocator" ascii
        $jolt5 = "Jolt/Physics" ascii nocase
    condition:
        2 of them
}
