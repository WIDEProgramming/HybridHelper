using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HybridHelper.App.Framework
{
    internal class Program
    {
        public static void Main(string[] args)
        {
            Wide.HybridHelper.SetCurrentThreadAffinity(Wide.HybridHelper.EfficiencyClass.Performance);
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
            oldThreadMask = Wide.HybridHelper.SetCurrentThreadAffinity(Wide.HybridHelper.EfficiencyClass.Performance);
            DoWork();
        }

        public static void EStart()
        {
            oldThreadMask = Wide.HybridHelper.SetCurrentThreadAffinity(Wide.HybridHelper.EfficiencyClass.Efficient);
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
