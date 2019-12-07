Function Get-SmartCardCred{
<#
.SYNOPSIS
Get certificate credentials from the Windows logon UI.

.DESCRIPTION
Returns a PSCredential object of the user's selected account.

.EXAMPLE
Get-SmartCardCred
UserName                                           Password
--------                                           --------
@@BVkEYkWiqJgd2d9xz3-5BiHs1cAN System.Security.SecureString

.EXAMPLE
$Cred = Get-SmartCardCred

.OUTPUTS
[System.Management.Automation.PSCredential]

.NOTES
Author: Joshua Chase
Last Modified: 09 September 2019
Version: 1.1.0
C# signatures obtained from PInvoke.
#>
[cmdletbinding()]
Param()
    $Code = @"
using System;
using System.Text;
using System.Security;
using System.Management.Automation;
using System.Runtime.InteropServices;
public class Credentials
{
    private const int CREDUIWIN_GENERIC = 1;
    private const int CREDUIWIN_CHECKBOX = 2;
    private const int CREDUIWIN_AUTHPACKAGE_ONLY = 16;
    private const int CREDUIWIN_IN_CRED_ONLY = 32;
    private const int CREDUIWIN_ENUMERATE_ADMINS = 256;
    private const int CREDUIWIN_ENUMERATE_CURRENT_USER = 512;
    private const int CREDUIWIN_SECURE_PROMPT = 4096;
    private const int CREDUIWIN_PACK_32_WOW = 268435456;
    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    private static extern uint CredUIPromptForWindowsCredentials(ref CREDUI_INFO notUsedHere,
        int authError,
        ref uint authPackage,
        IntPtr InAuthBuffer,
        uint InAuthBufferSize,
        out IntPtr refOutAuthBuffer,
        out uint refOutAuthBufferSize,
        ref bool fSave,
        int flags);
    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    private static extern bool CredUnPackAuthenticationBuffer(int dwFlags,
        IntPtr pAuthBuffer,
        uint cbAuthBuffer,
        StringBuilder pszUserName,
        ref int pcchMaxUserName,
        StringBuilder pszDomainName,
        ref int pcchMaxDomainame,
        StringBuilder pszKey,
        ref int pcchMaxKey);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDUI_INFO
    {
        public int cbSize;
        public IntPtr hwndParent;
        public string pszMessageText;
        public string pszCaptionText;
        public IntPtr hbmBanner;
    }
    public static PSCredential getPSCred()
    {
        bool save = false;
        int authError = 0;
        uint result;
        uint authPackage = 0;
        IntPtr outCredBuffer;
        uint outCredSize;
        PSCredential psCreds = null;
        var credui = new CREDUI_INFO
                                {
                                    pszCaptionText = "Enter your credentials",
                                    pszMessageText = "These credentials will be used for Get-SmartCardCred"
                                };
        credui.cbSize = Marshal.SizeOf(credui);
        while (true) //Show the dialog again and again, until Cancel is clicked or the entered credentials are correct.
        {
            //Show the dialog
            result = CredUIPromptForWindowsCredentials(ref credui,
            authError,
            ref authPackage,
            IntPtr.Zero,
            0,
            out outCredBuffer,
            out outCredSize,
            ref save,
            CREDUIWIN_ENUMERATE_CURRENT_USER);
            if (result != 0) break;
            var usernameBuf = new StringBuilder(100);
            var keyBuf = new StringBuilder(100);
            var domainBuf = new StringBuilder(100);
            var maxUserName = 100;
            var maxDomain = 100;
            var maxKey = 100;
            if (CredUnPackAuthenticationBuffer(1, outCredBuffer, outCredSize, usernameBuf, ref maxUserName, domainBuf, ref maxDomain, keyBuf, ref maxKey))
            {
                Marshal.ZeroFreeCoTaskMemUnicode(outCredBuffer);
                var key = new SecureString();
                foreach (char c in keyBuf.ToString())
                {
                    key.AppendChar(c);
                }
                keyBuf.Clear();
                key.MakeReadOnly();
                psCreds = new PSCredential(usernameBuf.ToString(), key);
                GC.Collect();
                break;
            }
              
            else authError = 1326; //1326 = 'Logon failure: unknown user name or bad password.' 
        }
        return psCreds;
    }
}
"@

    Add-Type -TypeDefinition $Code -Language CSharp

    Write-Output ([Credentials]::getPSCred())
}