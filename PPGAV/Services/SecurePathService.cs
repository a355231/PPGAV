using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace PPGAV.Services;

/// Centralized path policy used before every security-sensitive filesystem operation.
/// It rejects reparse points and compares both lexical and final paths. Final-path
/// checks are repeated immediately before a move/open because path validation is not
/// a permanent lock against later replacement.
public static class SecurePathService
{
    public static string RequireExistingDirectory(string path, string name = "directory")
    {
        var full = RequireAbsolute(path, name);
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException(full);
        RejectReparse(full, name);
        RequireFinalPath(full, full, name);
        return full;
    }

    public static string RequireExistingFile(string path, string name = "file")
    {
        var full = RequireAbsolute(path, name);
        if (!File.Exists(full)) throw new FileNotFoundException($"The {name} does not exist.", full);
        RejectReparse(full, name);
        RequireFinalPath(Path.GetDirectoryName(full)!, full, name);
        return full;
    }

    public static string RequireContained(string root, string candidate, bool mustExist = true, string name = "path")
    {
        var safeRoot = RequireExistingDirectory(root, "root directory");
        var fullCandidate = RequireAbsolute(candidate, name);
        var prefix = safeRoot.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!fullCandidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException($"The {name} escapes the configured root.");
        if (mustExist && !File.Exists(fullCandidate) && !Directory.Exists(fullCandidate)) throw new FileNotFoundException($"The {name} does not exist.", fullCandidate);
        RejectReparse(fullCandidate, name);
        if (mustExist) RequireFinalPath(safeRoot, fullCandidate, name);
        else RequireFinalPath(safeRoot, Path.GetDirectoryName(fullCandidate)!, name);
        return fullCandidate;
    }

    public static void RejectReparse(string path, string name = "path")
    {
        var full = RequireAbsolute(path, name);
        var current = File.Exists(full) ? full : Path.TrimEndingDirectorySeparator(full);
        while (!string.IsNullOrEmpty(current))
        {
            try
            {
                if (File.GetAttributes(current).HasFlag(FileAttributes.ReparsePoint)) throw new IOException($"The {name} contains a reparse point: {current}");
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
            var parent = Path.GetDirectoryName(current);
            if (string.IsNullOrEmpty(parent) || string.Equals(parent, current, StringComparison.OrdinalIgnoreCase)) break;
            current = parent;
        }
    }

    public static string RequireAbsolute(string path, string name)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException($"A {name} is required.", name);
        var full = Path.GetFullPath(path);
        if (Path.IsPathRooted(full) == false) throw new UnauthorizedAccessException($"The {name} is not absolute.");
        return full;
    }

    private static void RequireFinalPath(string root, string candidate, string name)
    {
        if (!OperatingSystem.IsWindows()) return;
        var rootFinal = GetFinalPath(root);
        var candidateFinal = GetFinalPath(candidate);
        var prefix = rootFinal.TrimEnd('\\') + "\\";
        if (!candidateFinal.Equals(rootFinal, StringComparison.OrdinalIgnoreCase) && !candidateFinal.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException($"The final {name} escapes the configured root.");
    }

    private static string GetFinalPath(string path)
    {
        using var handle = CreateFile(path, 0, FileShare.ReadWrite | FileShare.Delete, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not resolve final path: {path}");
        var buffer = new char[32768];
        var length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Length, 0);
        if (length == 0 || length >= buffer.Length) throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not resolve final path: {path}");
        var result = new string(buffer, 0, (int)length);
        return result.StartsWith(@"\\?\", StringComparison.Ordinal) ? result[4..] : result;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFile(string fileName, uint access, FileShare share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, [Out] char[] path, uint length, uint flags);
}
