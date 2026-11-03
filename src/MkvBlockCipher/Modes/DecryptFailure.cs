namespace MkvBlockCipher.Modes;

// One message for every decrypt failure, so a caller cannot tell a bad padding from a bad tag.
internal static class DecryptFailure
{
    internal const string Message = "The data could not be decrypted.";
}
