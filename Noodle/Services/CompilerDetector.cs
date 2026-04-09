using Noodle.Core.Models;

namespace Noodle.Core.Services;

public static class CompilerDetector
{
    public static CompilerInfo Detect(PEInfo pe)
    {
        string lang  = "Unknown";
        string comp  = "";
        string rt    = "";
        string vsVer = "";

        if (pe.IsDotNet)
        {
            lang = ".NET";
            rt   = pe.ClrVersion.Length > 0 ? $"CLR {pe.ClrVersion}" : "CLR";
        }
        else if (pe.IsDriver)
        {
            lang = "C / C++";
            comp = "Kernel Mode";
        }

        vsVer = MapLinkerToVs(pe.LinkerVersion);

        if (vsVer.Length > 0)
        {
            if (lang == "Unknown") lang = "C / C++";
            if (comp.Length == 0)  comp = vsVer;
        }

        return new CompilerInfo(lang, comp, rt, pe.LinkerVersion, []);
    }

    private static string MapLinkerToVs(string ver)
    {
        int minor = 0;

        if (ver.StartsWith("14."))
        {
            int.TryParse(ver.Split('.').ElementAtOrDefault(1) ?? "", out minor);

            return minor >= 40 ? "VS 2022 (17.x)" :
                   minor >= 30 ? "VS 2022 (17.x)" :
                   minor >= 20 ? "VS 2019 (16.x)" :
                   minor >= 10 ? "VS 2017 (15.x)" : "VS 2015 (14.x)";
        }

        return ver switch
        {
            string v when v.StartsWith("12.") => "VS 2013",
            string v when v.StartsWith("11.") => "VS 2012",
            string v when v.StartsWith("10.") => "VS 2010",
            string v when v.StartsWith("9.")  => "VS 2008",
            string v when v.StartsWith("8.")  => "VS 2005",
            string v when v.StartsWith("7.")  => "VS 2003",
            string v when v.StartsWith("6.")  => "VC6",
            string v when v.StartsWith("2.")  => "Borland / Delphi",
            _ => ""
        };
    }
}
