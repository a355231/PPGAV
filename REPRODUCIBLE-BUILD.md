# Reproducible builds

Build with the pinned .NET SDK in `global.json` (or the current CI SDK), Release configuration, and the exact source revision. Publish with:

```powershell
dotnet publish .\PPGAV\PPGAV.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
```

Record the commit, SDK version, RID, and SHA-256 of every MSI and executable. Release signing must be performed in a protected CI environment with a code-signing certificate; unsigned local artifacts are development artifacts only.
