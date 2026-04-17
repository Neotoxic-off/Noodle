// severity: safe
rule Render_DirectX {
    meta:
        description = "Microsoft DirectX (D3D9/D3D11/D3D12) usage detected"
    strings:
        $d3d9  = "d3d9.dll" ascii nocase
        $d3d11 = "d3d11.dll" ascii nocase
        $d3d12 = "d3d12.dll" ascii nocase
        $dxgi  = "dxgi.dll" ascii nocase
        $d3dc  = "D3DCompiler" ascii nocase
        $dx1   = "D3D11CreateDevice" ascii
        $dx2   = "D3D12CreateDevice" ascii
        $dx3   = "Direct3DCreate9" ascii
        $hlsl  = "HLSL" ascii fullword
        $shader = "vs_4_0" ascii
    condition:
        2 of them
}

// severity: safe
rule Render_DirectX12 {
    meta:
        description = "DirectX 12 (DX12) usage — modern low-level GPU API"
    strings:
        $d3d12_1 = "D3D12CreateDevice" ascii
        $d3d12_2 = "ID3D12Device" ascii
        $d3d12_3 = "ID3D12CommandQueue" ascii
        $d3d12_4 = "D3D12GetDebugInterface" ascii
        $d3d12_5 = "IDXGIFactory4" ascii
        $d3d12_6 = "d3d12.dll" ascii nocase
    condition:
        2 of them
}
