// severity: safe
rule Render_OpenGL {
    meta:
        description = "OpenGL / OpenGL ES rendering library usage"
    strings:
        $ogl1 = "opengl32.dll" ascii nocase
        $ogl2 = "glBegin" ascii
        $ogl3 = "glDrawElements" ascii
        $ogl4 = "glGenTextures" ascii
        $ogl5 = "glAttachShader" ascii
        $ogl6 = "wglCreateContext" ascii
        $ogl7 = "glXCreateContext" ascii
        $glew = "GLEW_VERSION" ascii
        $glfw = "glfwCreateWindow" ascii
        $glad = "gladLoadGL" ascii
    condition:
        2 of them
}

// severity: safe
rule Render_OpenCL {
    meta:
        description = "OpenCL GPU compute usage"
    strings:
        $cl1 = "OpenCL.dll" ascii nocase
        $cl2 = "clCreateContext" ascii
        $cl3 = "clCreateCommandQueue" ascii
        $cl4 = "clBuildProgram" ascii
        $cl5 = "cl_device_id" ascii
        $cl6 = "OpenCL" ascii fullword
    condition:
        2 of them
}
