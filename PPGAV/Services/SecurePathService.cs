using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace PPGAV.Services;

/// <summary>Centralized filesystem policy. Security-sensitive reads should use OpenContainedRead.</summary>
public static class SecurePathService
{
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileAddSubdirectory = 0x00000004;
    private const uint FileAddFile = 0x00000002;
    private const uint GenericRead = 0x80000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint FileShareRead = 0x00000001;

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
        RejectReparse(fullCandidate, name);
        if (mustExist && !File.Exists(fullCandidate) && !Directory.Exists(fullCandidate)) throw new FileNotFoundException($"The {name} does not exist.", fullCandidate);
        RejectReparse(fullCandidate, name);
        if (mustExist) RequireFinalPath(safeRoot, fullCandidate, name);
        else RequireFinalPath(safeRoot, Path.GetDirectoryName(fullCandidate)!, name);
        return fullCandidate;
    }

    /// <summary>
    /// Opens a file without write/delete sharing, checks the opened handle for
    /// reparse points and final-path escapes, and pins the root directory until
    /// the returned stream is disposed. This closes the common validate-then-open
    /// replacement window for read, hash, and staging operations. Pass a wider
    /// <paramref name="share"/> only for observation of files another process is
    /// actively writing (runtime monitoring), never for pre-launch verification.
    /// </summary>
    public static Stream OpenContainedRead(string root, string candidate, string name = "file", FileShare share = FileShare.Read)
    {
        var safeRoot = RequireExistingDirectory(root, "root directory");
        var fullCandidate = RequireAbsolute(candidate, name);
        var prefix = safeRoot.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!fullCandidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException($"The {name} escapes the configured root.");

        if (!OperatingSystem.IsWindows())
        {
            RejectReparse(fullCandidate, name);
            RequireFinalPath(safeRoot, fullCandidate, name);
            return new FileStream(fullCandidate, FileMode.Open, FileAccess.Read, share, 65536, FileOptions.SequentialScan);
        }

        var rootHandle = CreateFile(safeRoot, FileReadAttributes, share | FileShare.Read, IntPtr.Zero, OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (rootHandle.IsInvalid)
        {
            rootHandle.Dispose();
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not pin the {name} root.");
        }

        SafeFileHandle? fileHandle = null;
        try
        {
            if (GetAttributes(rootHandle, "root directory").HasFlag(FileAttributes.ReparsePoint)) throw new IOException("The root directory is a reparse point.");
            fileHandle = CreateFile(fullCandidate, GenericRead, share, IntPtr.Zero, OpenExisting,
                FileFlagOpenReparsePoint | FileFlagSequentialScan, IntPtr.Zero);
            if (fileHandle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not safely open {name}: {fullCandidate}");
            if (GetAttributes(fileHandle, name).HasFlag(FileAttributes.ReparsePoint)) throw new IOException($"The {name} is a reparse point.");

            var rootFinal = GetFinalPath(rootHandle);
            var fileFinal = GetFinalPath(fileHandle);
            var finalPrefix = rootFinal.TrimEnd('\\') + "\\";
            if (!fileFinal.StartsWith(finalPrefix, StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException($"The final {name} escapes the configured root.");

            var stream = new FileStream(fileHandle, FileAccess.Read, 65536, isAsync: false);
            fileHandle = null;
            return new RootPinnedReadStream(stream, rootHandle);
        }
        catch
        {
            fileHandle?.Dispose();
            rootHandle.Dispose();
            throw;
        }
    }

    /// <summary>Renames a child directory using its verified open handle, without replacing a target.</summary>
    public static void MoveDirectoryContained(string root, string source, string destination)
    {
        if (!OperatingSystem.IsWindows())
        {
            var safeRoot = RequireExistingDirectory(root, "move root");
            RequireContained(safeRoot, source, true, "move source");
            RequireContained(safeRoot, destination, false, "move destination");
            if (Directory.Exists(destination) || File.Exists(destination)) throw new IOException("Refusing to replace an existing move destination.");
            Directory.Move(source, destination);
            return;
        }

        var safeRootPath = RequireExistingDirectory(root, "move root");
        var sourcePath = RequireContained(safeRootPath, source, true, "move source");
        var destinationPath = RequireContained(safeRootPath, destination, false, "move destination");
        if (Directory.Exists(destinationPath) || File.Exists(destinationPath)) throw new IOException("Refusing to replace an existing move destination.");
        var sourceHandle = CreateFile(sourcePath, DeleteAccess | FileReadAttributes, FileShare.ReadWrite | FileShare.Delete, IntPtr.Zero, OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (sourceHandle.IsInvalid)
        {
            sourceHandle.Dispose();
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not safely open move source: {sourcePath}");
        }
        var destinationParent = Path.GetDirectoryName(destinationPath)!;
        var destinationParentHandle = CreateFile(destinationParent, FileReadAttributes | FileAddSubdirectory, FileShare.ReadWrite | FileShare.Delete, IntPtr.Zero, OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (destinationParentHandle.IsInvalid)
        {
            destinationParentHandle.Dispose(); sourceHandle.Dispose();
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not safely pin the move destination directory.");
        }
        using (sourceHandle)
        using (destinationParentHandle)
        {
            if (GetAttributes(sourceHandle, "move source").HasFlag(FileAttributes.ReparsePoint)) throw new IOException("Move source is a reparse point.");
            if (GetAttributes(destinationParentHandle, "move destination directory").HasFlag(FileAttributes.ReparsePoint)) throw new IOException("Move destination parent is a reparse point.");
            var rootFinal = GetFinalPath(safeRootPath);
            var sourceFinal = GetFinalPath(sourceHandle);
            var prefix = rootFinal.TrimEnd('\\') + "\\";
            if (!sourceFinal.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException("Move source escapes the validated root.");
            var parentFinal = GetFinalPath(destinationParentHandle);
            if (!parentFinal.Equals(rootFinal, StringComparison.OrdinalIgnoreCase) && !parentFinal.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Move destination escapes the validated root.");

            var nameBytes = Encoding.Unicode.GetBytes(destinationPath);
            var rootHandleOffset = IntPtr.Size;
            var nameLengthOffset = IntPtr.Size * 2;
            var nameOffset = nameLengthOffset + sizeof(uint);
            var bufferLength = Math.Max(24, nameOffset + nameBytes.Length + sizeof(char));
            var buffer = Marshal.AllocHGlobal(bufferLength);
            try
            {
                Marshal.Copy(new byte[bufferLength], 0, buffer, bufferLength);
                Marshal.WriteByte(buffer, 0, 0); // ReplaceIfExists = false
                Marshal.WriteIntPtr(buffer, rootHandleOffset, IntPtr.Zero);
                Marshal.WriteInt32(buffer, nameLengthOffset, nameBytes.Length);
                Marshal.Copy(nameBytes, 0, IntPtr.Add(buffer, nameOffset), nameBytes.Length);
                if (!SetFileInformationByHandle(sourceHandle, 3, buffer, (uint)bufferLength))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Handle-verified directory rename failed.");
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        if (!Directory.Exists(destinationPath)) throw new IOException("The handle-based move completed without the expected destination.");
        if (Directory.Exists(sourcePath) || File.Exists(sourcePath)) throw new IOException("A new path appeared at the move source during the transaction.");
        RejectReparse(destinationPath, "moved directory");
    }

    /// <summary>Deletes a file only when the opened, path-validated file still has the expected hash.</summary>
    public static bool DeleteContainedFileIfHash(string root, string candidate, string expectedSha256)
    {
        var safeRoot = RequireExistingDirectory(root, "delete root");
        var fullCandidate = RequireAbsolute(candidate, "delete candidate");
        var prefix = safeRoot.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!fullCandidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException("The delete candidate escapes its configured root.");
        RejectReparse(fullCandidate, "delete candidate");
        if (!OperatingSystem.IsWindows())
        {
            using var stream = OpenContainedRead(safeRoot, fullCandidate, "delete candidate");
            if (!Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream)).Equals(expectedSha256, StringComparison.OrdinalIgnoreCase)) return false;
            File.Delete(fullCandidate);
            return true;
        }

        using var rootHandle = CreateFile(safeRoot, FileReadAttributes, FileShare.ReadWrite | FileShare.Delete, IntPtr.Zero, OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (rootHandle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not pin the delete root.");
        var fileHandle = CreateFile(fullCandidate, GenericRead | DeleteAccess, FileShare.Read, IntPtr.Zero, OpenExisting,
            FileFlagOpenReparsePoint | FileFlagSequentialScan, IntPtr.Zero);
        if (fileHandle.IsInvalid)
        {
            fileHandle.Dispose();
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not safely open delete candidate: {fullCandidate}");
        }
        using (fileHandle)
        {
            if (GetAttributes(rootHandle, "delete root").HasFlag(FileAttributes.ReparsePoint) || GetAttributes(fileHandle, "delete candidate").HasFlag(FileAttributes.ReparsePoint))
                throw new IOException("Refusing to delete a reparse-point path.");
            var rootFinal = GetFinalPath(rootHandle);
            var candidateFinal = GetFinalPath(fileHandle);
            if (!candidateFinal.StartsWith(rootFinal.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("The final delete candidate escapes its configured root.");
            using var stream = new FileStream(fileHandle, FileAccess.Read, 65536, isAsync: false);
            var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream));
            if (!hash.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase)) return false;
            var info = Marshal.AllocHGlobal(sizeof(int));
            try
            {
                Marshal.WriteInt32(info, 1);
                if (!SetFileInformationByHandle(fileHandle, 4, info, sizeof(int)))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not delete the verified file handle.");
            }
            finally { Marshal.FreeHGlobal(info); }
            return true;
        }
    }

    /// <summary>Atomically publishes a verified file using its opened handle and a pinned destination directory.</summary>
    public static void MoveFileContained(string root, string source, string destination, bool replaceExisting = false)
    {
        var safeRoot = RequireExistingDirectory(root, "file move root");
        var sourcePath = RequireContained(safeRoot, source, true, "file move source");
        var destinationPath = RequireContained(safeRoot, destination, false, "file move destination");
        var destinationParent = RequireExistingDirectory(Path.GetDirectoryName(destinationPath)!, "file move destination directory");
        RejectReparse(sourcePath, "file move source");
        RejectReparse(destinationParent, "file move destination directory");
        if (Directory.Exists(destinationPath)) throw new IOException("Refusing to replace a directory with a file move.");
        if (File.Exists(destinationPath))
        {
            if (!replaceExisting) throw new IOException("Refusing to replace an existing file.");
            RequireContained(safeRoot, destinationPath, true, "file move replacement target");
        }
        if (!OperatingSystem.IsWindows())
        {
            File.Move(sourcePath, destinationPath, replaceExisting);
            return;
        }

        using var sourceHandle = CreateFile(sourcePath, DeleteAccess | FileReadAttributes, FileShare.Read, IntPtr.Zero, OpenExisting,
            FileFlagOpenReparsePoint | FileFlagSequentialScan, IntPtr.Zero);
        if (sourceHandle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not pin the file move source.");
        using var parentHandle = CreateFile(destinationParent, FileReadAttributes | FileAddFile, FileShare.ReadWrite, IntPtr.Zero, OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (parentHandle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not pin the file move destination directory.");
        if ((GetAttributes(sourceHandle, "file move source") & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0 ||
            GetAttributes(parentHandle, "file move destination directory").HasFlag(FileAttributes.ReparsePoint))
            throw new IOException("Refusing a file move involving reparse-point or directory content.");
        var rootFinal = GetFinalPath(safeRoot);
        var sourceFinal = GetFinalPath(sourceHandle);
        var parentFinal = GetFinalPath(parentHandle);
        var rootPrefix = rootFinal.TrimEnd('\\') + "\\";
        if (!sourceFinal.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase) ||
            !parentFinal.Equals(rootFinal, StringComparison.OrdinalIgnoreCase) && !parentFinal.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Final file-move paths are outside the configured root.");
        if ((File.Exists(destinationPath) || Directory.Exists(destinationPath)) && !replaceExisting) throw new IOException("A file appeared at the move destination.");

        var nameBytes = Encoding.Unicode.GetBytes(destinationPath);
        var nameLengthOffset = IntPtr.Size * 2;
        var nameOffset = nameLengthOffset + sizeof(uint);
        var bufferLength = Math.Max(24, nameOffset + nameBytes.Length + sizeof(char));
        var buffer = Marshal.AllocHGlobal(bufferLength);
        try
        {
            Marshal.Copy(new byte[bufferLength], 0, buffer, bufferLength);
            Marshal.WriteByte(buffer, 0, replaceExisting ? (byte)1 : (byte)0);
            Marshal.WriteIntPtr(buffer, IntPtr.Size, IntPtr.Zero);
            Marshal.WriteInt32(buffer, nameLengthOffset, nameBytes.Length);
            Marshal.Copy(nameBytes, 0, IntPtr.Add(buffer, nameOffset), nameBytes.Length);
            if (!SetFileInformationByHandle(sourceHandle, 3, buffer, (uint)bufferLength))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Handle-verified file publication failed.");
        }
        finally { Marshal.FreeHGlobal(buffer); }

        if (!File.Exists(destinationPath) || File.Exists(sourcePath)) throw new IOException("The file move completed without the expected final state.");
        RequireContained(safeRoot, destinationPath, true, "published file");
    }

    public static void RejectReparse(string path, string name = "path")
    {
        var full = RequireAbsolute(path, name);
        var current = File.Exists(full) ? full : Path.TrimEndingDirectorySeparator(full);
        while (!string.IsNullOrEmpty(current))
        {
            try { if (File.GetAttributes(current).HasFlag(FileAttributes.ReparsePoint)) throw new IOException($"The {name} contains a reparse point: {current}"); }
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
        if (!Path.IsPathRooted(full)) throw new UnauthorizedAccessException($"The {name} is not absolute.");
        return full;
    }

    private static void RequireFinalPath(string root, string candidate, string name)
    {
        if (!OperatingSystem.IsWindows()) return;
        var rootFinal = GetFinalPath(root);
        var candidateFinal = GetFinalPath(candidate);
        var prefix = rootFinal.TrimEnd('\\') + "\\";
        if (!candidateFinal.Equals(rootFinal, StringComparison.OrdinalIgnoreCase) && !candidateFinal.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException($"The final {name} escapes the configured root.");
    }

    private static string GetFinalPath(string path)
    {
        using var handle = CreateFile(path, 0, FileShare.ReadWrite | FileShare.Delete, IntPtr.Zero, OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not resolve final path: {path}");
        return GetFinalPath(handle);
    }

    private static string GetFinalPath(SafeFileHandle handle)
    {
        var buffer = new char[32768];
        var length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Length, 0);
        if (length == 0 || length >= buffer.Length) throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not resolve final path.");
        var result = new string(buffer, 0, (int)length);
        return result.StartsWith(@"\\?\", StringComparison.Ordinal) ? result[4..] : result;
    }

    private static FileAttributes GetAttributes(SafeFileHandle handle, string name)
    {
        if (!GetFileInformationByHandleEx(handle, 9, out var info, (uint)Marshal.SizeOf<FileAttributeTagInfo>()))
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not inspect the opened {name}.");
        return (FileAttributes)info.FileAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo { public uint FileAttributes; public uint ReparseTag; }

    private sealed class RootPinnedReadStream : Stream
    {
        private readonly FileStream _inner;
        private SafeFileHandle? _rootHandle;
        public RootPinnedReadStream(FileStream inner, SafeFileHandle rootHandle) { _inner = inner; _rootHandle = rootHandle; }
        public override bool CanRead => _inner.CanRead;
        public override bool CanSeek => _inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;
        public override long Position { get => _inner.Position; set => _inner.Position = value; }
        public override void Flush() => _inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override int Read(Span<byte> buffer) => _inner.Read(buffer);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => _inner.ReadAsync(buffer, cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) { _inner.Dispose(); Interlocked.Exchange(ref _rootHandle, null)?.Dispose(); } base.Dispose(disposing); }
        public override async ValueTask DisposeAsync() { await _inner.DisposeAsync(); Interlocked.Exchange(ref _rootHandle, null)?.Dispose(); GC.SuppressFinalize(this); }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFile(string fileName, uint access, FileShare share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, [Out] char[] path, uint length, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass, out FileAttributeTagInfo info, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int infoClass, IntPtr fileInformation, uint bufferSize);
}
