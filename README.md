# HybridHelper
Set thread affinity on specific cores (P-Core and E-Core) with Intel Hybrid Architecture using C#.

# How to use

1. Add the file **HybridHelper.cs** to your project
2. From the thread you want to set the affinity, call
````
    Wide.HybridHelper.SetCurrentThreadAffinity(HybridHelper.EfficiencyClass.Efficient);
````
or
````
    Wide.HybridHelper.SetCurrentThreadAffinity(HybridHelper.EfficiencyClass.Performance);
````

# Example

````
using System;
using System.Text;
using System.Threading;

namespace Wide
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Thread pThread = new Thread(new ThreadStart(PStart));
            pThread.Name = "Performance";
            pThread.Start();

            Thread eThread = new Thread(new ThreadStart(EStart));
            eThread.Name = "Efficient";
            eThread.Start();
        }

        [ThreadStatic] private static uint oldThreadMask;
        public static void PStart()
        {
            oldThreadMask = HybridHelper.SetCurrentThreadAffinity(HybridHelper.EfficiencyClass.Performance);
            DoWork();
        }

        public static void EStart()
        {
            oldThreadMask = HybridHelper.SetCurrentThreadAffinity(HybridHelper.EfficiencyClass.Efficient);
            DoWork();
        }

        private static void DoWork()
        {
            while (true)
            {
                // do work
            }
        }
    }
}
````

# Debug Information

You will get debug information on the first use of the HybridHelper

Example:

````
**************************** HybridHelper ****************************
CPU: 16P+8E
P-Cache: L1i:32KB / L1d:48KB / L2:1.25MB / L3:30MB 
E-Cache: L1i:64KB / L1d:32KB / L2:2MB 
**************************** HybridHelper ****************************
````

# Tested on the following CPUs:
* Intel i9 12900KF
