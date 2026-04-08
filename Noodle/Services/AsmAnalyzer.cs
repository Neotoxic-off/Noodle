using Iced.Intel;
using Noodle.Core.Models;

namespace Noodle.Core.Services;

/// <summary>
/// Disassembles the entry-point region of a PE binary and flags suspicious
/// instruction patterns: packer stubs, shellcode tricks, anti-debug sequences.
/// </summary>
public sealed class AsmAnalyzer
{
    private const int MaxBytes = 512;

    public IEnumerable<Detection> Analyze(string filePath, PEInfo peInfo)
    {
        var epBytes = ReadEntryPointBytes(filePath, peInfo);
        if (epBytes.Length < 4) yield break;

        var instructions = Disassemble(epBytes, peInfo.IsX64, peInfo.EntryPoint);
        if (instructions.Count == 0) yield break;

        // ── Packer stub: PUSHAD / POPAD (32-bit only) ────────────────────────
        if (!peInfo.IsX64)
        {
            bool hasPushad = instructions.Any(i => i.Mnemonic == Mnemonic.Pushad);
            bool hasPopad  = instructions.Any(i => i.Mnemonic == Mnemonic.Popad);

            if (hasPushad && hasPopad)
                yield return new Detection(
                    "Packer Stub (PUSHAD/POPAD)",
                    "Entry point contains a PUSHAD/POPAD register-save sequence — classic runtime-packer stub (UPX, ASPack, MEW, etc.).",
                    Severity.Dangerous, DetectionCategory.Packing);
            else if (hasPushad)
                yield return new Detection(
                    "PUSHAD at Entry Point",
                    "Entry point starts with PUSHAD — typical of packer stubs that save all registers before unpacking code.",
                    Severity.Suspicious, DetectionCategory.Packing);
        }

        // ── NOP sled ─────────────────────────────────────────────────────────
        int maxNops = 0, curNops = 0;
        foreach (var instr in instructions)
        {
            if (instr.Mnemonic == Mnemonic.Nop) { curNops++; maxNops = Math.Max(maxNops, curNops); }
            else curNops = 0;
        }
        if (maxNops >= 8)
            yield return new Detection(
                $"NOP Sled ({maxNops} bytes)",
                $"Entry point contains {maxNops} consecutive NOP instructions — common padding technique in shellcode and exploits.",
                Severity.Dangerous, DetectionCategory.AsmPattern);

        // ── RDTSC anti-timing ─────────────────────────────────────────────────
        if (instructions.Any(i => i.Mnemonic == Mnemonic.Rdtsc))
            yield return new Detection(
                "RDTSC Anti-Debug (Timing)",
                "RDTSC instruction at entry point — used for timing-based debugger detection; execution is measurably slower under a debugger.",
                Severity.Suspicious, DetectionCategory.AntiDebug);

        // ── CPUID anti-VM ─────────────────────────────────────────────────────
        if (instructions.Any(i => i.Mnemonic == Mnemonic.Cpuid))
            yield return new Detection(
                "CPUID Anti-VM Check",
                "CPUID instruction at entry point — used to query hypervisor vendor strings and detect virtual machine environments.",
                Severity.Suspicious, DetectionCategory.Evasion);

        // ── INT3 / INT 0x2D anti-debug traps ─────────────────────────────────
        int int3Count = instructions.Count(i => i.Mnemonic == Mnemonic.Int3);
        bool hasInt2d = instructions.Any(i =>
            i.Mnemonic == Mnemonic.Int &&
            i.Op0Kind  == OpKind.Immediate8 &&
            i.GetImmediate(0) == 0x2D);

        if (int3Count >= 3)
            yield return new Detection(
                $"INT3 Trap Cluster ({int3Count}×)",
                $"Found {int3Count} INT3 (0xCC) instructions near the entry point — used to detect software breakpoints set by a debugger.",
                Severity.Suspicious, DetectionCategory.AntiDebug);

        if (hasInt2d)
            yield return new Detection(
                "INT 0x2D Anti-Debug",
                "INT 0x2D detected — Windows-specific anti-debugging interrupt that behaves differently when a debugger is attached.",
                Severity.Suspicious, DetectionCategory.AntiDebug);

        // ── GetEIP / PIC trick: CALL $+5 followed by POP ─────────────────────
        for (int i = 0; i < instructions.Count - 1; i++)
        {
            var call = instructions[i];
            var pop  = instructions[i + 1];
            if (call.Mnemonic == Mnemonic.Call &&
                (ulong)call.NearBranch64 == call.NextIP &&
                pop.Mnemonic == Mnemonic.Pop)
            {
                yield return new Detection(
                    "GetEIP / PIC Shellcode Trick",
                    "CALL $+5 followed by POP — position-independent code trick used in shellcode and packers to obtain the current instruction pointer at runtime.",
                    Severity.Dangerous, DetectionCategory.AsmPattern);
                break;
            }
        }

        // ── XOR decryption loop ───────────────────────────────────────────────
        bool hasXorLoop = false;
        for (int i = 0; i < instructions.Count && !hasXorLoop; i++)
        {
            if (instructions[i].Mnemonic != Mnemonic.Xor) continue;

            int start = Math.Max(0, i - 6);
            int end   = Math.Min(instructions.Count, i + 12);
            for (int j = start; j < end && !hasXorLoop; j++)
            {
                var jcc = instructions[j];
                if (jcc.Mnemonic is Mnemonic.Jne or Mnemonic.Jl or
                    Mnemonic.Jle or Mnemonic.Loop or Mnemonic.Loope or Mnemonic.Loopne)
                {
                    if (jcc.NearBranch64 < jcc.IP)
                        hasXorLoop = true;
                }
            }
        }
        if (hasXorLoop)
            yield return new Detection(
                "XOR Decryption Loop",
                "XOR instruction combined with a backward conditional branch at entry point — typical of self-decrypting runtime-unpacking stubs.",
                Severity.Dangerous, DetectionCategory.Packing);

        // ── Tail jump to OEP (large unconditional JMP) ───────────────────────
        foreach (var jmp in instructions.Where(i => i.Mnemonic == Mnemonic.Jmp))
        {
            ulong target = jmp.NearBranch64;
            if (target == 0) continue;
            long disp = Math.Abs((long)target - (long)jmp.IP);
            if (disp > 0x2000)
            {
                yield return new Detection(
                    "Tail Jump (OEP Redirect)",
                    $"Large unconditional JMP to 0x{target:X} at entry point — packed binaries jump to the original entry point after runtime decryption.",
                    Severity.Dangerous, DetectionCategory.Packing);
                break;
            }
        }

        // ── Suspicious instruction density: heavy XOR/MOV on memory ──────────
        int xorCount  = instructions.Count(i => i.Mnemonic == Mnemonic.Xor);
        int stosCount = instructions.Count(i =>
            i.Mnemonic is Mnemonic.Stosb or Mnemonic.Stosw or Mnemonic.Stosd or Mnemonic.Stosq);
        int movsCount = instructions.Count(i =>
            i.Mnemonic is Mnemonic.Movsb or Mnemonic.Movsw or Mnemonic.Movsd or Mnemonic.Movsq);

        if (stosCount + movsCount >= 4)
            yield return new Detection(
                "Bulk Memory Ops at Entry",
                $"Found {stosCount} STOS + {movsCount} MOVS instructions near the entry point — bulk memory operations are common in decompression/decryption loops.",
                Severity.Suspicious, DetectionCategory.Packing);

        if (xorCount >= 6 && !hasXorLoop)
            yield return new Detection(
                "High XOR Density",
                $"{xorCount} XOR instructions in the entry-point region — may indicate obfuscation or inline decryption.",
                Severity.Suspicious, DetectionCategory.Packing);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static List<Instruction> Disassemble(byte[] bytes, bool is64, uint rva)
    {
        var reader  = new ByteArrayCodeReader(bytes);
        var decoder = Decoder.Create(is64 ? 64 : 32, reader, DecoderOptions.None);
        decoder.IP = rva;

        var list = new List<Instruction>(64);
        while (reader.CanReadByte)
        {
            decoder.Decode(out var instr);
            if (instr.IsInvalid) break;
            list.Add(instr);
        }
        return list;
    }

    private static byte[] ReadEntryPointBytes(string filePath, PEInfo peInfo)
    {
        try
        {
            uint ep = peInfo.EntryPoint;
            if (ep == 0) return [];

            var section = peInfo.Sections.FirstOrDefault(s =>
                ep >= s.VirtualAddress && ep < s.VirtualAddress + Math.Max(s.VirtualSize, 1u));
            if (section == default) return [];

            uint offsetInSection = ep - section.VirtualAddress;
            if (offsetInSection >= section.RawSize) return [];

            uint fileOffset = section.PointerToRawData + offsetInSection;
            uint available  = section.RawSize - offsetInSection;
            int  toRead     = (int)Math.Min(MaxBytes, available);
            if (toRead <= 0) return [];

            using var fs = File.OpenRead(filePath);
            fs.Seek(fileOffset, SeekOrigin.Begin);
            var buf  = new byte[toRead];
            int read = fs.Read(buf);
            return buf[..read];
        }
        catch { return []; }
    }
}
