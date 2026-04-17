// severity: safe
rule Render_Vulkan {
    meta:
        description = "Vulkan GPU API usage"
    strings:
        $vk1  = "vulkan-1.dll" ascii nocase
        $vk2  = "vkCreateInstance" ascii
        $vk3  = "vkCreateDevice" ascii
        $vk4  = "vkQueueSubmit" ascii
        $vk5  = "vkCreateSwapchainKHR" ascii
        $vk6  = "VkInstance" ascii
        $vk7  = "VK_STRUCTURE_TYPE" ascii
        $spv  = "SPIR-V" ascii
        $glsl = "glslang" ascii nocase
    condition:
        2 of them
}
