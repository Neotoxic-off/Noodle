using Iced.Intel;
using Noodle.Core.Models;

namespace Noodle.Core.Services;

public sealed class AsmAnalyzer
{
    private const int MaxBytes = 512;

    public IEnumerable<Detection> Analyze(string filePath, PEInfo peInfo)
    {
        byte[]             epBytes      = ReadEntryPointBytes(filePath, peInfo);
        List<Instruction>  instructions = [];
        bool               hasPushad    = false;
        bool               hasPopad     = false;
        int                maxNops      = 0;
        int                curNops      = 0;
        int                int3Count    = 0;
        bool               hasInt2d     = false;
        bool               hasPicTrick  = false;
        int                picIdx       = 0;
        bool               hasXorLoop   = false;
        bool               hasTailJmp   = false;
        ulong              tailTarget   = 0;
        int                xorCount     = 0;
        int                stosCount    = 0;
        int                movsCount    = 0;

        if (epBytes.Length < 4) yield break;

        instructions = Disassemble(epBytes, peInfo.IsX64, peInfo.EntryPoint);

        if (instructions.Count == 0) yield break;

        if (!peInfo.IsX64)
        {
            hasPushad = instructions.Any(i => i.Mnemonic == Mnemonic.Pushad);
            hasPopad  = instructions.Any(i => i.Mnemonic == Mnemonic.Popad);

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

        foreach (Instruction instr in instructions)
        {
            if (instr.Mnemonic == Mnemonic.Nop) { curNops = curNops + 1; maxNops = Math.Max(maxNops, curNops); }
            else curNops = 0;
        }

        if (maxNops >= 8)
            yield return new Detection(
                $"NOP Sled ({maxNops} bytes)",
                $"Entry point contains {maxNops} consecutive NOP instructions — common padding technique in shellcode and exploits.",
                Severity.Dangerous, DetectionCategory.AsmPattern);

        if (instructions.Any(i => i.Mnemonic == Mnemonic.Rdtsc))
            yield return new Detection(
                "RDTSC Anti-Debug (Timing)",
                "RDTSC instruction at entry point — used for timing-based debugger detection; execution is measurably slower under a debugger.",
                Severity.Suspicious, DetectionCategory.AntiDebug);

        if (instructions.Any(i => i.Mnemonic == Mnemonic.Cpuid))
            yield return new Detection(
                "CPUID Anti-VM Check",
                "CPUID instruction at entry point — used to query hypervisor vendor strings and detect virtual machine environments.",
                Severity.Suspicious, DetectionCategory.Evasion);

        int3Count = instructions.Count(i => i.Mnemonic == Mnemonic.Int3);
        hasInt2d  = instructions.Any(i =>
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

        while (picIdx < instructions.Count - 1 && !hasPicTrick)
        {
            Instruction call = instructions[picIdx];
            Instruction pop  = instructions[picIdx + 1];

            hasPicTrick = call.Mnemonic == Mnemonic.Call
                && (ulong)call.NearBranch64 == call.NextIP
                && pop.Mnemonic == Mnemonic.Pop;

            picIdx = picIdx + 1;
        }

        if (hasPicTrick)
            yield return new Detection(
                "GetEIP / PIC Shellcode Trick",
                "CALL $+5 followed by POP — position-independent code trick used in shellcode and packers to obtain the current instruction pointer at runtime.",
                Severity.Dangerous, DetectionCategory.AsmPattern);

        for (int i = 0; i < instructions.Count && !hasXorLoop; i = i + 1)
        {
            if (instructions[i].Mnemonic != Mnemonic.Xor) continue;

            int start = Math.Max(0, i - 6);
            int end   = Math.Min(instructions.Count, i + 12);

            for (int j = start; j < end && !hasXorLoop; j = j + 1)
            {
                Instruction jcc = instructions[j];

                if (jcc.Mnemonic is Mnemonic.Jne or Mnemonic.Jl or
                    Mnemonic.Jle or Mnemonic.Loop or Mnemonic.Loope or Mnemonic.Loopne)
                {
                    if (jcc.NearBranch64 < jcc.IP)
                    {
                        hasXorLoop = true;
                    }
                }
            }
        }

        if (hasXorLoop)
            yield return new Detection(
                "XOR Decryption Loop",
                "XOR instruction combined with a backward conditional branch at entry point — typical of self-decrypting runtime-unpacking stubs.",
                Severity.Dangerous, DetectionCategory.Packing);

        for (int i = 0; i < instructions.Count && !hasTailJmp; i = i + 1)
        {
            Instruction jmp = instructions[i];

            if (jmp.Mnemonic != Mnemonic.Jmp || jmp.NearBranch64 == 0) continue;

            long disp = Math.Abs((long)jmp.NearBranch64 - (long)jmp.IP);

            if (disp > 0x2000)
            {
                hasTailJmp = true;
                tailTarget = jmp.NearBranch64;
            }
        }

        if (hasTailJmp)
            yield return new Detection(
                "Tail Jump (OEP Redirect)",
                $"Large unconditional JMP to 0x{tailTarget:X} at entry point — packed binaries jump to the original entry point after runtime decryption.",
                Severity.Dangerous, DetectionCategory.Packing);

        xorCount  = instructions.Count(i => i.Mnemonic == Mnemonic.Xor);
        stosCount = instructions.Count(i =>
            i.Mnemonic is Mnemonic.Stosb or Mnemonic.Stosw or Mnemonic.Stosd or Mnemonic.Stosq);
        movsCount = instructions.Count(i =>
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

    private static List<Instruction> Disassemble(byte[] bytes, bool is64, uint rva)
    {
        ByteArrayCodeReader reader  = new ByteArrayCodeReader(bytes);
        Decoder             decoder = Decoder.Create(is64 ? 64 : 32, reader, DecoderOptions.None);
        List<Instruction>   list    = new List<Instruction>(64);
        Instruction         instr   = default;

        decoder.IP = rva;

        while (reader.CanReadByte)
        {
            decoder.Decode(out instr);
            if (instr.IsInvalid) return list;
            list.Add(instr);
        }

        return list;
    }

    private static byte[] ReadEntryPointBytes(string filePath, PEInfo peInfo)
    {
        uint      ep              = peInfo.EntryPoint;
        SectionInfo? section       = null;
        uint      offsetInSection = 0;
        uint      fileOffset      = 0;
        uint      available       = 0;
        int       toRead          = 0;
        byte[]    buf             = [];
        int       read            = 0;

        if (ep == 0) return [];

        section = peInfo.Sections.FirstOrDefault(s =>
            ep >= s.VirtualAddress && ep < s.VirtualAddress + Math.Max(s.VirtualSize, 1u));

        if (section is null) return [];

        offsetInSection = ep - section.VirtualAddress;
        if (offsetInSection >= section.RawSize) return [];

        fileOffset = section.PointerToRawData + offsetInSection;
        available  = section.RawSize - offsetInSection;
        toRead     = (int)Math.Min(MaxBytes, available);

        if (toRead <= 0) return [];

        using FileStream fs = File.OpenRead(filePath);

        fs.Seek(fileOffset, SeekOrigin.Begin);
        buf  = new byte[toRead];
        read = fs.Read(buf);

        return buf[..read];
    }
}
