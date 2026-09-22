namespace PPGAV.Services;

public interface IOutboundNetworkBlocker
{
    bool TryBlockOutbound(string executablePath, out string ruleName);
    bool TryRemove(string executablePath);
    bool TryRemoveRule(string ruleName);
}
