using Newtonsoft.Json;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace CredDump
{
    class Program
    {
        static void Main(string[] args)
        {
            CredentialUtil.CredEnumerate(null, 0, out int count, out IntPtr pCredentials);
            for (int n = 0; n < count; n++)
            {
                var ptrCred = Marshal.ReadIntPtr(pCredentials, n * Marshal.SizeOf(typeof(IntPtr)));
                var credential = (CREDENTIAL)Marshal.PtrToStructure(ptrCred, typeof(CREDENTIAL));
                var credential2 = new CREDENTIAL2
                {
                    AttributeCount = credential.AttributeCount,
                    Attributes = credential.Attributes,
                    Comment = credential.Comment,
                    CredentialBlobSize = credential.CredentialBlobSize,
                    Flags = credential.Flags,
                    LastWritten = credential.LastWritten,
                    Persist = credential.Persist,
                    TargetAlias = credential.TargetAlias,
                    TargetName = credential.TargetName,
                    Type = credential.Type,
                    UserName = credential.UserName
                };

                if (credential.CredentialBlobSize > 0)
                {
                    //Try Ansi first
                    credential2.CredentialBlob = Marshal.PtrToStringAnsi(credential.CredentialBlob, credential.CredentialBlobSize);

                    //Test for unicode
                    if (credential2.CredentialBlob.Replace("\0", "").Length != credential.CredentialBlobSize)
                        //If it is unicode then redo
                        credential2.CredentialBlob = Marshal.PtrToStringUni(credential.CredentialBlob, credential.CredentialBlobSize / 2);

                    Console.WriteLine(JsonConvert.SerializeObject(credential2, Formatting.Indented));
                    //CredentialUtil.CredFree(ptrCred);
                }
            }
#if DEBUG
            Console.WriteLine("Press any key to continue...");
            Console.ReadKey();
#endif
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

    internal struct CREDENTIAL2
    {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public string CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    public static class CredentialUtil
    {
        [DllImport("Advapi32.dll", EntryPoint = "CredEnumerate", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CredEnumerate(string filter, int flag, out int count, out IntPtr pCredentials);
        [DllImport("Advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
        internal static extern void CredFree([In] IntPtr cred);
    }

}
