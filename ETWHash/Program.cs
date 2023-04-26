using System;
using System.Threading;

namespace EtwHash
{
    public static class Program
	{
        private static void ShowHelp()
		{
			Console.WriteLine("Usage: EtwHash.exe [time_in_seconds]");
		}

		static void Main(string[] args)
		{
            if (args.Length <1)
            {
                ShowHelp();
            }
            else
            {
                try
                {
                    var monitor = new Monitor
                    {
                        Timer = int.Parse(args[0])
                    };

                    Console.WriteLine($"[*] Started monitoring ETW provider for {monitor.Timer} seconds.");
                    monitor.Initialize();

                    if (monitor.Timer == 0)
                    {
                        while (monitor.Timer != -1)
                        {
                            Thread.Sleep(1000);
                        }
                    }
                    else
                    {
                        while (monitor.Timer > 0)
                        {
                            Thread.Sleep(1000);
                            monitor.Timer--;
                        }
                    }
                    monitor.Stop();
                    Thread.Sleep(10000);

                    Console.WriteLine("[*] Monitoring complete!");
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] Exception occurred: {0}", e);
                }
            }
        }
	}
}
