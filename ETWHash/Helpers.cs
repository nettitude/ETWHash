using System;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;

namespace EtwHash
{
    internal static class Helpers
    {
        //code from https://github.com/X-C3LL/SharpNTLMRawUnHide/blob/7f32c034dde2d70d9426a403357c81df632367b5/SharpNTLMRawUnhide/Program.cs#L19
        public static int Search(byte[] src, byte[] pattern, int begin, int stop)
        {
            try
            {
                for (var i = begin; i < stop; i++)
                {
                    if (src[i] != pattern[0]) // compare only first byte
                    {
                        continue;
                    }

                    // found a match on first byte, now try to match rest of the pattern
                    for (var j = pattern.Length - 1; j >= 1; j--)
                    {
                        if (src[i + j] != pattern[j])
                        {
                            break;
                        }

                        if (j == 1)
                        {
                            return i;
                        }
                    }
                }
                return -1;
            }
            catch
            {
                return -1;
            }
        }

        public static string ByteArrayToString(byte[] ba)
        {
            return BitConverter.ToString(ba).Replace("-", "");
        }
        //code from https://github.com/mdsecactivebreach/Farmer/blob/1f37598125a92c9edf41295c6c1b7c258143968d/Farmer/Farmer.cs#L148
        public static string DecodeNTLM(byte[] NTLM, byte[] server_challenge)
        {
            var LMHash_len = BitConverter.ToInt16(NTLM, 12);
            var LMHash_offset = BitConverter.ToInt16(NTLM, 16);
            var LMHash = NTLM.Skip(LMHash_offset).Take(LMHash_len).ToArray();
            var NTHash_len = BitConverter.ToInt16(NTLM, 20);
            var NTHash_offset = BitConverter.ToInt16(NTLM, 24);
            var NTHash = NTLM.Skip(NTHash_offset).Take(NTHash_len).ToArray();
            var User_len = BitConverter.ToInt16(NTLM, 36);
            var User_offset = BitConverter.ToInt16(NTLM, 40);
            var User = NTLM.Skip(User_offset).Take(User_len).ToArray();
            var UserString = Encoding.Unicode.GetString(User);

            if (NTHash_len == 24)
            {  // NTLMv1
                var HostName_len = BitConverter.ToInt16(NTLM, 46);
                var HostName_offset = BitConverter.ToInt16(NTLM, 48);
                var HostName = NTLM.Skip(HostName_offset).Take(HostName_len).ToArray();
                var HostNameString = Encoding.Unicode.GetString(HostName);
                var retval = UserString + "::" + HostNameString + ":" + LMHash + ":" + NTHash + ":" + ByteArrayToString(server_challenge);
                return retval;
            }

            if (NTHash_len > 24)
            { // NTLMv2
                NTHash_len = 64;
                var Domain_len = BitConverter.ToInt16(NTLM, 28);
                var Domain_offset = BitConverter.ToInt16(NTLM, 32);
                var Domain = NTLM.Skip(Domain_offset).Take(Domain_len).ToArray();
                var DomainString = Encoding.Unicode.GetString(Domain);
                var HostName_len = BitConverter.ToInt16(NTLM, 44);
                var HostName_offset = BitConverter.ToInt16(NTLM, 48);
                var HostName = NTLM.Skip(HostName_offset).Take(HostName_len).ToArray();
                var HostNameString = Encoding.Unicode.GetString(HostName);

                var NTHash_part1 = BitConverter.ToString(NTHash.Take(16).ToArray()).Replace("-", "");
                var NTHash_part2 = BitConverter.ToString(NTHash.Skip(16).Take(NTLM.Length).ToArray()).Replace("-", "");
                var retval = UserString + "::" + DomainString + ":" + ByteArrayToString(server_challenge) + ":" + NTHash_part1 + ":" + NTHash_part2;
                return retval;
            }

            Console.WriteLine("Could not parse NTLM hash");
            return "";
        }// End DecodeNTLM

        public static byte[] ObjectToByteArray(object obj)
        {
            BinaryFormatter bf = new BinaryFormatter();
            using (MemoryStream ms = new MemoryStream())
            {
                bf.Serialize(ms, obj);
                return ms.ToArray();
            }
        }

    }
}
