using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace Wide
{
    public class HybridHelper
    {
        private static readonly bool _isHybrid = false;

        public enum EfficiencyClass
        {
            Efficient = 0,
            Performance = 1
        }

        static HybridHelper()
        {
            _isHybrid = CpuID.HYBRID();
            Console.WriteLine("**************************** HybridHelper ****************************");

            if (_isHybrid)
            {
                foreach (ProcessorPackage package in CpuInformation.ProcessorPackages)
                {
                    Console.Write(package);
                }
            }
            else
            {
                Console.WriteLine("Non-Hybrid CPU detected!");
            }

            Console.WriteLine("**************************** HybridHelper ****************************");
        }

        public static uint SetCurrentThreadAffinity(EfficiencyClass efficiencyClass)
        {
            if (!_isHybrid)
            {
                return 0x0;
            }

            uint threadPreviousAffinityMask = 0;

            foreach (var package in CpuInformation.ProcessorPackages)
            {
                IntPtr threadHandle = winbase.GetCurrentThread();
                ulong coreMask = package.GetCoresMaskByEfficiency(efficiencyClass);

                Debug.Assert(coreMask != 0, $"A core with the efficiency class {efficiencyClass} could not be found");

                threadPreviousAffinityMask |= winbase.SetThreadAffinityMask(threadHandle, (uint)coreMask);

                if (threadPreviousAffinityMask == 0)
                {
                    // function failed
                    Debug.WriteLine($"Error calling SetThreadAffinityMask, GetLastError()={Marshal.GetLastWin32Error()}");
                }
            }

            return threadPreviousAffinityMask;
        }

        private static int NumberOfSetBits(ulong bitmask)
        {
            short LSHIFT = sizeof(int) * 8 - 1;
            int bitSetCount = 0;
            ulong bitTest = 1UL << LSHIFT;
            short i;

            for (i = 0; i <= LSHIFT; ++i)
            {
                bitSetCount += ((bitmask & bitTest) > 0 ? 1 : 0);
                bitTest /= 2;
            }

            return bitSetCount;
        }

        private class CacheSize
        {
            private int[] _cacheSizeBytes = new int[4];

            internal CacheSize()
            {
                // initialize L1i/L1d/L2/L3
                _cacheSizeBytes[0] = 0;
                _cacheSizeBytes[1] = 0;
                _cacheSizeBytes[2] = 0;
                _cacheSizeBytes[3] = 0;
            }

            internal void SetCacheSize(int level, int bytes)
            {
                Debug.Assert(level >= 0 && level < 4);
                _cacheSizeBytes[level] = bytes;
            }

            public override string ToString()
            {
                StringBuilder sb = new StringBuilder();

                for (int i = 0; i < 4; ++i)
                {
                    string cacheName = "";
                    switch (i)
                    {
                        case 0:
                            cacheName = "L1i";
                            break;
                        case 1:
                            cacheName = "L1d";
                            break;
                        case 2:
                            cacheName = "L2";
                            break;
                        case 3:
                            cacheName = "L3";
                            break;
                    }

                    int sizeBytes = _cacheSizeBytes[i];
                    if (sizeBytes > 0)
                    {
                        double sizeKb = sizeBytes / 1024.0;
                        double sizeMb = sizeKb / 1024.0;

                        if (sizeMb > 1)
                        {
                            sb.Append($"{cacheName}:{sizeMb}MB / ");
                        }
                        else
                        {
                            sb.Append($"{cacheName}:{sizeKb}KB / ");
                        }
                    }
                }

                if (sb.Length > 2)
                {
                    sb.Remove(sb.Length - 2, 2);
                }

                return sb.ToString();
            }
        }

        private class ProcessorPackage
        {
            // index/key is the class efficiency (0 or 1)
            private IDictionary<EfficiencyClass, ulong> _coreMasks = new Dictionary<EfficiencyClass, ulong>();
            private IDictionary<EfficiencyClass, int> _coreCount = new Dictionary<EfficiencyClass, int>();
            private IDictionary<EfficiencyClass, int> _threadCount = new Dictionary<EfficiencyClass, int>();
            private IDictionary<EfficiencyClass, CacheSize> _caches = new Dictionary<EfficiencyClass, CacheSize>();

            internal ProcessorPackage()
            {
                _coreMasks[EfficiencyClass.Efficient] = 0L;
                _coreMasks[EfficiencyClass.Performance] = 0L;

                _coreCount[EfficiencyClass.Efficient] = 0;
                _coreCount[EfficiencyClass.Performance] = 0;

                _threadCount[EfficiencyClass.Efficient] = 0;
                _threadCount[EfficiencyClass.Performance] = 0;

                _caches[EfficiencyClass.Efficient] = null;
                _caches[EfficiencyClass.Performance] = null;
            }

            internal int PackageEfficiencyClass { get; set; }
            internal ulong PackageMask { get; set; }
            internal List<ProcessorCore> ProcessorCores { get; set; } = new List<ProcessorCore>();

            private static bool _initialized = false;
            internal void Initialize()
            {
                if (_initialized)
                {
                    return;
                }

                foreach (ProcessorCore core in ProcessorCores)
                {
                    _coreMasks[core.EfficiencyClass] |= core.Mask;
                    _coreCount[core.EfficiencyClass]++;
                    _threadCount[core.EfficiencyClass] += core.IsSMT ? NumberOfSetBits(core.Mask) : 1;

                    if (_caches[core.EfficiencyClass] == null)
                    {
                        _caches[core.EfficiencyClass] = new CacheSize();
                        foreach (var cache in core.ProcessorCaches)
                        {
                            int level = 0;

                            switch (cache.Type)
                            {
                                case ProcessorCache.CacheType.Instruction:
                                    level = 0;
                                    break;
                                case ProcessorCache.CacheType.Data:
                                    level = 1;
                                    break;
                                case ProcessorCache.CacheType.Unified:
                                    {
                                        if (cache.Level == 2)
                                        {
                                            level = 2;
                                        }
                                        else if (cache.Level == 3)
                                        {
                                            level = 3;
                                        }
                                    }
                                    break;
                                default:
                                    break;
                            }

                            _caches[core.EfficiencyClass].SetCacheSize(level, cache.CacheSize);
                        }
                    }
                }

                _initialized = true;
            }

            public override string ToString()
            {
                StringBuilder sb = new StringBuilder();
                sb.Append($"CPU: {_coreCount[EfficiencyClass.Performance]}P ({_threadCount[EfficiencyClass.Performance]} threads, mask 0x{_coreMasks[EfficiencyClass.Performance]:X})");

                if (_coreCount[EfficiencyClass.Efficient] > 0)
                {
                    sb.AppendLine($" + {_coreCount[EfficiencyClass.Efficient]}E ({_threadCount[EfficiencyClass.Efficient]} threads, mask 0x{_coreMasks[EfficiencyClass.Efficient]:X})");
                }

                sb.AppendLine($"P-Cache: {_caches[EfficiencyClass.Performance]}");

                if (_coreCount[EfficiencyClass.Efficient] > 0)
                {
                    sb.AppendLine($"E-Cache: {_caches[EfficiencyClass.Efficient]}");
                }

                return sb.ToString();
            }

            internal ulong GetCoresMaskByEfficiency(EfficiencyClass efficiencyClass)
            {
                ulong mask = 0UL;
                if (_coreMasks.TryGetValue(efficiencyClass, out mask))
                {
                    return mask;
                }

                return 0UL;
            }

            internal void UpdateCoresMaskByEfficiency(EfficiencyClass efficiencyClass, ulong mask)
            {
                if (_coreMasks.ContainsKey(efficiencyClass))
                {
                    _coreMasks[efficiencyClass] |= mask;
                }
            }
        }

        private class ProcessorCore
        {
            internal int Flags { get; set; }
            internal bool IsSMT { get { return Flags == Constants.LTP_PC_SMT; } }
            internal EfficiencyClass EfficiencyClass { get; set; }
            internal ulong Mask { get; set; }
            internal IList<ProcessorCache> ProcessorCaches { get; set; } = new List<ProcessorCache>();
        }

        private class ProcessorCache
        {
            internal enum CacheType
            {
                Unified,
                Instruction,
                Data,
                Trace
            }

            internal ulong Mask { get; set; }
            internal int Level { get; set; }
            internal CacheType Type { get; set; }
            internal int CacheSize { get; set; }
            internal int LineSize { get; set; }
            internal bool FullyAssociative { get; set; }
        }

        private class ProcessorGroup
        {
            internal int MaximumProcessorCount { get; set; }
            internal int ActiveProcessorCount { get; set; }
            internal long ActiveProcessorMask { get; set; }
        }

        private class NumaNode
        {
            internal int NodeNumber { get; set; }
            internal long Mask { get; set; }
        }

        private class CpuInformation
        {
            internal static IList<ProcessorPackage> ProcessorPackages { get; set; } = new List<ProcessorPackage>();

            static CpuInformation()
            {
                try
                {
                    Initialize(GetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP.RelationAll));
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message); ;
                }
            }

            private static void Initialize(IList<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX> logicalProcessorInformationEx)
            {
                ProcessorPackage package = null;
                ProcessorCore core = null;

                foreach (var logicalProcInfo in logicalProcessorInformationEx)
                {
                    switch (logicalProcInfo.Relationship)
                    {
                        case LOGICAL_PROCESSOR_RELATIONSHIP.RelationProcessorPackage:
                            {
                                package = new ProcessorPackage();

                                // package efficiency class is not the same as core efficiency class
                                package.PackageEfficiencyClass = logicalProcInfo.ProcessorInformation.Processor.EfficiencyClass;
                                package.PackageMask = logicalProcInfo.ProcessorInformation.Processor.GroupMask.GroupAffinity.Mask;

                                ProcessorPackages.Add(package);
                                break;
                            }
                        case LOGICAL_PROCESSOR_RELATIONSHIP.RelationProcessorCore:
                            {
                                Debug.Assert(package != null);
                                core = new ProcessorCore();
                                core.Flags = logicalProcInfo.ProcessorInformation.Processor.Flags;
                                core.EfficiencyClass = (EfficiencyClass)Enum.ToObject(typeof(EfficiencyClass), logicalProcInfo.ProcessorInformation.Processor.EfficiencyClass);
                                core.Mask = logicalProcInfo.ProcessorInformation.Processor.GroupMask.GroupAffinity.Mask;

                                package.UpdateCoresMaskByEfficiency((EfficiencyClass)Enum.ToObject(typeof(EfficiencyClass), core.EfficiencyClass), core.Mask);
                                package.ProcessorCores.Add(core);
                                break;
                            }
                        case LOGICAL_PROCESSOR_RELATIONSHIP.RelationCache:
                            {
                                Debug.Assert(package != null);
                                Debug.Assert(core != null);

                                ProcessorCache cache = new ProcessorCache();
                                cache.Level = logicalProcInfo.ProcessorInformation.Cache.Level;
                                cache.Type = (ProcessorCache.CacheType)Enum.ToObject(typeof(ProcessorCache.CacheType), (int)logicalProcInfo.ProcessorInformation.Cache.Type);
                                cache.FullyAssociative = logicalProcInfo.ProcessorInformation.Cache.Associativity == Constants.CACHE_FULLY_ASSOCIATIVE;
                                cache.CacheSize = logicalProcInfo.ProcessorInformation.Cache.CacheSize;
                                cache.LineSize = logicalProcInfo.ProcessorInformation.Cache.LineSize;
                                cache.Mask = logicalProcInfo.ProcessorInformation.Cache.GroupMask.GroupAffinity.Mask;

                                core.ProcessorCaches.Add(cache);
                                break;
                            }
                    }
                }

                foreach (ProcessorPackage procPackage in ProcessorPackages)
                {
                    procPackage.Initialize();
                }
            }

            private static SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX[] GetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP relationship)
            {
                // query for the length of the buffer needed
                uint bufferSize = 0;
                bool success = sysinfoapi.GetLogicalProcessorInformationEx(relationship, IntPtr.Zero, ref bufferSize);
                Debug.Assert(!success);
                Debug.Assert(Marshal.GetLastWin32Error() == Constants.ERROR_INSUFFICIENT_BUFFER);
                // allocate a buffer 
                IntPtr rootPtr = IntPtr.Zero;
                try
                {
                    rootPtr = Marshal.AllocHGlobal((int)bufferSize);
                }
                catch (OutOfMemoryException)
                {
                    return new SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX[0];
                }

                // query a second time with the new buffer size
                success = sysinfoapi.GetLogicalProcessorInformationEx(relationship, rootPtr, ref bufferSize);

                if (!success)
                {
                    Debug.WriteLine($"Error calling GetLogicalProcessorInformationEx with ReturnedLength={bufferSize}");
                    Marshal.FreeHGlobal(rootPtr);
                    return new SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX[0];
                }

                SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX[] sysLogicalProcInfos = null;
                try
                {
                    sysLogicalProcInfos = MarshalHelper.PtrToStructures<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(rootPtr, bufferSize);
                }
                finally
                {
                    // free the buffer memory
                    Marshal.FreeHGlobal(rootPtr);
                }

                return sysLogicalProcInfos;
            }
        }

        private class MarshalHelper
        {
            internal static T[] PtrToStructures<T>(IntPtr ptr, uint bufferSize) where T : struct
            {
                IList<T> list = new List<T>();

                FieldInfo sizeField = typeof(T).GetField("Size", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
                Debug.Assert(sizeField != null);
                Debug.Assert(sizeField.FieldType == typeof(uint));

                uint readCount = 0;
                uint structureSize = 0;
                IntPtr bufferPtr = IntPtr.Zero;

                for (bufferPtr = ptr; readCount < bufferSize; readCount += (uint)structureSize, bufferPtr += (int)structureSize)
                {
                    T sysLogicalProcInfoEx = Marshal.PtrToStructure<T>(bufferPtr);
                    structureSize = (uint)sizeField.GetValue(sysLogicalProcInfoEx);
                    list.Add(sysLogicalProcInfoEx);
                }

                return list.ToArray();
            }
        }

        private class sysinfoapi
        {
            [DllImport("kernel32", SetLastError = true)]
            internal static extern bool GetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP relationship, IntPtr buffer, ref uint returnedLength);
        }

        private class winbase
        {
            [DllImport("kernel32", SetLastError = true)]
            internal static extern IntPtr OpenThread(UInt32 dwDesiredAccess, bool bInheritHandle, UInt32 dwThreadId);

            [DllImport("kernel32", SetLastError = true)]
            internal static extern UInt32 SetThreadAffinityMask(IntPtr hThread, UInt32 dwThreadAffinityMask);

            [DllImport("kernel32", SetLastError = true)]
            internal static extern UInt32 GetCurrentThreadId();

            [DllImport("kernel32", SetLastError = true)]
            internal static extern IntPtr GetCurrentThread();
        }

        private class Constants
        {
            internal const int LTP_PC_SMT = 0x1;
            internal const int CACHE_FULLY_ASSOCIATIVE = 0xFF;
            internal const int ERROR_INSUFFICIENT_BUFFER = 122;
        }

        //typedef enum _LOGICAL_PROCESSOR_RELATIONSHIP
        //{
        //    RelationProcessorCore,
        //    RelationNumaNode,
        //    RelationCache,
        //    RelationProcessorPackage,
        //    RelationGroup,
        //    RelationProcessorDie,
        //    RelationNumaNodeEx,
        //    RelationProcessorModule,
        //    RelationAll = 0xffff
        //}
        //LOGICAL_PROCESSOR_RELATIONSHIP;
        private enum LOGICAL_PROCESSOR_RELATIONSHIP
        {
            RelationProcessorCore,
            RelationNumaNode,
            RelationCache,
            RelationProcessorPackage,
            RelationGroup,
            RelationProcessorDie,
            RelationNumaNodeEx,
            RelationProcessorModule,
            RelationAll = 0xffff
        }

        //typedef enum _PROCESSOR_CACHE_TYPE
        //{
        //    CacheUnified,
        //    CacheInstruction,
        //    CacheData,
        //    CacheTrace
        //}
        //PROCESSOR_CACHE_TYPE;
        private enum PROCESSOR_CACHE_TYPE
        {
            CacheUnified,
            CacheInstruction,
            CacheData,
            CacheTrace
        }

        //typedef struct _GROUP_AFFINITY
        //{
        //    KAFFINITY Mask;
        //    WORD Group;
        //    WORD Reserved[3];
        //}
        //GROUP_AFFINITY, * PGROUP_AFFINITY;
        [StructLayout(LayoutKind.Sequential, Size = 16)]
        private struct GROUP_AFFINITY
        {
            internal ulong Mask;
            internal ushort Group;
            internal ushort Reserved1;
            internal ushort Reserved2;
            internal ushort Reserved3;
        }

        //typedef struct _CACHE_DESCRIPTOR
        //{
        //    BYTE Level;
        //    BYTE Associativity;
        //    WORD LineSize;
        //    DWORD Size;
        //    PROCESSOR_CACHE_TYPE Type;
        //}
        //CACHE_DESCRIPTOR, * PCACHE_DESCRIPTOR;
        [StructLayout(LayoutKind.Sequential)]
        private struct CACHE_DESCRIPTOR
        {
            internal byte Level;
            internal byte Associativity;
            internal ushort LineSize;
            internal uint Size;
            internal PROCESSOR_CACHE_TYPE Type;
        }

        //typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION {
        //    ULONG_PTR   ProcessorMask;
        //    LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
        //    union {
        //        struct {
        //            BYTE  Flags;
        //        } ProcessorCore;
        //        struct {
        //            DWORD NodeNumber;
        //        } NumaNode;
        //        CACHE_DESCRIPTOR Cache;
        //        ULONGLONG  Reserved[2];
        //    } DUMMYUNIONNAME;
        //} SYSTEM_LOGICAL_PROCESSOR_INFORMATION, *PSYSTEM_LOGICAL_PROCESSOR_INFORMATION;
        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_LOGICAL_PROCESSOR_INFORMATION
        {
            internal UIntPtr ProcessorMask;
            internal LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
            internal SYSTEM_LOGICAL_PROCESSOR_INFORMATION_UNION ProcessorInformation;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct SYSTEM_LOGICAL_PROCESSOR_INFORMATION_UNION
        {
            [FieldOffset(0)]
            internal PROCESSORCORE ProcessorCore;
            [FieldOffset(0)]
            internal NUMANODE NumaNode;
            [FieldOffset(0)]
            internal CACHE_DESCRIPTOR Cache;
            [FieldOffset(0)]
            private UInt64 Reserved1;
            [FieldOffset(8)]
            private UInt64 Reserved2;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESSORCORE
        {
            internal byte Flags;
        };

        [StructLayout(LayoutKind.Sequential)]
        private struct NUMANODE
        {
            internal uint NodeNumber;
        }

        //typedef struct _PROCESSOR_RELATIONSHIP
        //{
        //    BYTE Flags;
        //    BYTE EfficiencyClass;
        //    BYTE Reserved[20];
        //    WORD GroupCount;
        //    _Field_size_(GroupCount) GROUP_AFFINITY GroupMask[ANYSIZE_ARRAY];
        //}
        //PROCESSOR_RELATIONSHIP, * PPROCESSOR_RELATIONSHIP;
        [StructLayout(LayoutKind.Sequential, Size = 40)]
        private struct PROCESSOR_RELATIONSHIP
        {
            internal byte Flags;
            internal byte EfficiencyClass;
            internal byte Reserved1;
            internal byte Reserved2;
            internal byte Reserved3;
            internal byte Reserved4;
            internal byte Reserved5;
            internal byte Reserved6;
            internal byte Reserved7;
            internal byte Reserved8;
            internal byte Reserved9;
            internal byte Reserved10;
            internal byte Reserved11;
            internal byte Reserved12;
            internal byte Reserved13;
            internal byte Reserved14;
            internal byte Reserved15;
            internal byte Reserved16;
            internal byte Reserved17;
            internal byte Reserved18;
            internal byte Reserved19;
            internal byte Reserved20;
            internal ushort GroupCount;
            internal GROUP_AFFINITY_UNION GroupMask;
        }

        //typedef struct _NUMA_NODE_RELATIONSHIP
        //{
        //    DWORD NodeNumber;
        //    BYTE Reserved[18];
        //    WORD GroupCount;
        //    union {
        //    GROUP_AFFINITY GroupMask;
        //    _Field_size_(GroupCount)
        //        GROUP_AFFINITY GroupMasks[ANYSIZE_ARRAY];
        //}
        //DUMMYUNIONNAME;
        //}
        //NUMA_NODE_RELATIONSHIP, *PNUMA_NODE_RELATIONSHIP;
        [StructLayout(LayoutKind.Sequential, Size = 40)]
        private struct NUMA_NODE_RELATIONSHIP
        {
            internal int NodeNumber;
            internal byte Reserved1;
            internal byte Reserved2;
            internal byte Reserved3;
            internal byte Reserved4;
            internal byte Reserved5;
            internal byte Reserved6;
            internal byte Reserved7;
            internal byte Reserved8;
            internal byte Reserved9;
            internal byte Reserved10;
            internal byte Reserved11;
            internal byte Reserved12;
            internal byte Reserved13;
            internal byte Reserved14;
            internal byte Reserved15;
            internal byte Reserved16;
            internal byte Reserved17;
            internal byte Reserved18;
            internal short GroupCount;
            internal GROUP_AFFINITY_UNION NumaNodeGroupMask;
        }

        //typedef struct _CACHE_RELATIONSHIP
        //{
        //    BYTE Level;
        //    BYTE Associativity;
        //    WORD LineSize;
        //    DWORD CacheSize;
        //    PROCESSOR_CACHE_TYPE Type;
        //    BYTE Reserved[18];
        //    WORD GroupCount;
        //    union {
        //    GROUP_AFFINITY GroupMask;
        //    _Field_size_(GroupCount)
        //    GROUP_AFFINITY GroupMasks[ANYSIZE_ARRAY];
        //}
        //DUMMYUNIONNAME;
        //}
        //CACHE_RELATIONSHIP, *PCACHE_RELATIONSHIP;
        [StructLayout(LayoutKind.Sequential, Size = 48)]
        private struct CACHE_RELATIONSHIP
        {
            internal byte Level;
            internal byte Associativity;
            internal short LineSize;
            internal int CacheSize;
            internal PROCESSOR_CACHE_TYPE Type;
            internal byte Reserved1;
            internal byte Reserved2;
            internal byte Reserved3;
            internal byte Reserved4;
            internal byte Reserved5;
            internal byte Reserved6;
            internal byte Reserved7;
            internal byte Reserved8;
            internal byte Reserved9;
            internal byte Reserved10;
            internal byte Reserved11;
            internal byte Reserved12;
            internal byte Reserved13;
            internal byte Reserved14;
            internal byte Reserved15;
            internal byte Reserved16;
            internal byte Reserved17;
            internal byte Reserved18;
            internal short GroupCount;
            internal GROUP_AFFINITY_UNION GroupMask;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct GROUP_AFFINITY_UNION
        {
            [FieldOffset(0)]
            internal GROUP_AFFINITY GroupAffinity;

            [FieldOffset(0)]
            internal IntPtr GroupAffinityArray;
        }

        //typedef struct _PROCESSOR_GROUP_INFO
        //{
        //    BYTE MaximumProcessorCount;
        //    BYTE ActiveProcessorCount;
        //    BYTE Reserved[38];
        //    KAFFINITY ActiveProcessorMask;
        //}
        //PROCESSOR_GROUP_INFO, * PPROCESSOR_GROUP_INFO;
        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESSOR_GROUP_INFO
        {
            internal byte MaximumProcessorCount;
            internal byte ActiveProcessorCount;
            internal byte Reserved1;
            internal byte Reserved2;
            internal byte Reserved3;
            internal byte Reserved4;
            internal byte Reserved5;
            internal byte Reserved6;
            internal byte Reserved7;
            internal byte Reserved8;
            internal byte Reserved9;
            internal byte Reserved10;
            internal byte Reserved11;
            internal byte Reserved12;
            internal byte Reserved13;
            internal byte Reserved14;
            internal byte Reserved15;
            internal byte Reserved16;
            internal byte Reserved17;
            internal byte Reserved18;
            internal byte Reserved19;
            internal byte Reserved20;
            internal byte Reserved21;
            internal byte Reserved22;
            internal byte Reserved23;
            internal byte Reserved24;
            internal byte Reserved25;
            internal byte Reserved26;
            internal byte Reserved27;
            internal byte Reserved28;
            internal byte Reserved29;
            internal byte Reserved30;
            internal byte Reserved31;
            internal byte Reserved32;
            internal byte Reserved33;
            internal byte Reserved34;
            internal byte Reserved35;
            internal byte Reserved36;
            internal byte Reserved37;
            internal byte Reserved38;
            internal long ActiveProcessorMask;
        }

        //typedef struct _GROUP_RELATIONSHIP
        //{
        //    WORD MaximumGroupCount;
        //    WORD ActiveGroupCount;
        //    BYTE Reserved[20];
        //    _Field_size_(ActiveGroupCount) PROCESSOR_GROUP_INFO GroupInfo[ANYSIZE_ARRAY];
        //}
        //GROUP_RELATIONSHIP, * PGROUP_RELATIONSHIP;
        [StructLayout(LayoutKind.Sequential, Size = 72)]
        private struct GROUP_RELATIONSHIP
        {
            internal short MaximumGroupCount;
            internal short ActiveGroupCount;
            internal byte Reserved1;
            internal byte Reserved2;
            internal byte Reserved3;
            internal byte Reserved4;
            internal byte Reserved5;
            internal byte Reserved6;
            internal byte Reserved7;
            internal byte Reserved8;
            internal byte Reserved9;
            internal byte Reserved10;
            internal byte Reserved11;
            internal byte Reserved12;
            internal byte Reserved13;
            internal byte Reserved14;
            internal byte Reserved15;
            internal byte Reserved16;
            internal byte Reserved17;
            internal byte Reserved18;
            internal byte Reserved19;
            internal byte Reserved20;
            internal PROCESSOR_GROUP_INFO GroupInfo;
        }

        //_Struct_size_bytes_(Size) struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX
        //{
        //    LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
        //    DWORD Size;
        //    union {
        //      PROCESSOR_RELATIONSHIP Processor;
        //      NUMA_NODE_RELATIONSHIP NumaNode;
        //      CACHE_RELATIONSHIP Cache;
        //      GROUP_RELATIONSHIP Group;
        //    }
        //DUMMYUNIONNAME;
        //};
        //typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, *PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX;
        [StructLayout(LayoutKind.Sequential, Size = 80)]
        private struct SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX
        {
            internal LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
            internal uint Size;
            internal SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX_UNION ProcessorInformation;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX_UNION
        {
            [FieldOffset(0)]
            internal PROCESSOR_RELATIONSHIP Processor;
            [FieldOffset(0)]
            internal NUMA_NODE_RELATIONSHIP NumaNode;
            [FieldOffset(0)]
            internal CACHE_RELATIONSHIP Cache;
            [FieldOffset(0)]
            internal GROUP_RELATIONSHIP Group;
        }

        private static class CpuID
        {
            private static BitArray _f_0_EAX = new BitArray(32);
            private static BitArray _f_0_EBX = new BitArray(32);
            private static BitArray _f_0_ECX = new BitArray(32);
            private static BitArray _f_0_EDX = new BitArray(32);
            private static BitArray _f_1_EAX = new BitArray(32);
            private static BitArray _f_1_EBX = new BitArray(32);
            private static BitArray _f_1_ECX = new BitArray(32);
            private static BitArray _f_1_EDX = new BitArray(32);
            private static BitArray _f_7_EAX = new BitArray(32);
            private static BitArray _f_7_EBX = new BitArray(32);
            private static BitArray _f_7_ECX = new BitArray(32);
            private static BitArray _f_7_EDX = new BitArray(32);
            private static BitArray _f_81_EAX = new BitArray(32);
            private static BitArray _f_81_EBX = new BitArray(32);
            private static BitArray _f_81_ECX = new BitArray(32);
            private static BitArray _f_81_EDX = new BitArray(32);
            private static bool _isIntel = false;
            private static bool _isAMD = false;

            static CpuID()
            {
                // 0x0 as function_id
                uint[] cpuid0 = CpuID.Invoke(0x0);
                uint numberOfFunctions = cpuid0[0];

                if (numberOfFunctions == 0)
                {
                    Debug.WriteLine("Could not call CPUID");
                    return;
                }

                byte[] eax = BitConverter.GetBytes(cpuid0[1]);
                byte[] ebx = BitConverter.GetBytes(cpuid0[1]);
                byte[] ecx = BitConverter.GetBytes(cpuid0[2]);
                byte[] edx = BitConverter.GetBytes(cpuid0[3]);

                _f_0_EAX = new BitArray(eax);
                _f_0_EBX = new BitArray(ebx);
                _f_0_ECX = new BitArray(ecx);
                _f_0_EDX = new BitArray(edx);

                // Capture vendor string
                string vendor = new string(Encoding.ASCII.GetChars(ebx.Concat(edx).Concat(ecx).ToArray()));
                if (vendor == "GenuineIntel")
                {
                    _isIntel = true;
                }
                else if (vendor == "AuthenticAMD")
                {
                    _isAMD = true;
                }

                if (numberOfFunctions >= 1)
                {
                    uint[] cpuid1 = CpuID.Invoke(0x1);
                    _f_1_EAX = new BitArray(BitConverter.GetBytes(cpuid1[0]));
                    _f_1_EBX = new BitArray(BitConverter.GetBytes(cpuid1[1]));
                    _f_1_ECX = new BitArray(BitConverter.GetBytes(cpuid1[2]));
                    _f_1_EDX = new BitArray(BitConverter.GetBytes(cpuid1[3]));
                }
                
                if (numberOfFunctions >= 7)
                {
                    uint[] cpuid7 = CpuID.Invoke(0x7);
                    _f_7_EAX = new BitArray(BitConverter.GetBytes(cpuid7[0]));
                    _f_7_EBX = new BitArray(BitConverter.GetBytes(cpuid7[1]));
                    _f_7_ECX = new BitArray(BitConverter.GetBytes(cpuid7[2]));
                    _f_7_EDX = new BitArray(BitConverter.GetBytes(cpuid7[3]));
                }

                uint[] cpuid8 = CpuID.Invoke(0x80000000);
                numberOfFunctions = cpuid8[0];
                if (numberOfFunctions >= 0x80000001)
                {
                    uint[] cpuid8i = CpuID.Invoke(0x80000001);
                    _f_81_EAX = new BitArray(BitConverter.GetBytes(cpuid8i[0]));
                    _f_81_EBX = new BitArray(BitConverter.GetBytes(cpuid8i[1]));
                    _f_81_ECX = new BitArray(BitConverter.GetBytes(cpuid8i[2]));
                    _f_81_EDX = new BitArray(BitConverter.GetBytes(cpuid8i[3]));
                }
            }

            public static uint[] Invoke(uint level)
            {
                IntPtr codePointer = IntPtr.Zero;
                try
                {
                    byte[] codeBytes;
                    if (IntPtr.Size == 4)
                    {
                        codeBytes = x86CodeBytes;
                    }
                    else
                    {
                        codeBytes = x64CodeBytes;
                    }

                    codePointer = VirtualAlloc(
                        IntPtr.Zero,
                        new UIntPtr((uint)codeBytes.Length),
                        AllocationType.COMMIT | AllocationType.RESERVE,
                        MemoryProtection.EXECUTE_READWRITE
                    );

                    Marshal.Copy(codeBytes, 0, codePointer, codeBytes.Length);

                    CpuIDDelegate cpuIdDelg = (CpuIDDelegate)Marshal.GetDelegateForFunctionPointer(codePointer, typeof(CpuIDDelegate));

                    // invoke
                    GCHandle handle = default(GCHandle);
                    uint[] buffer = new uint[4];

                    try
                    {
                        handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                        cpuIdDelg(level, buffer);
                    }
                    finally
                    {
                        if (handle != default(GCHandle))
                        {
                            handle.Free();
                        }
                    }

                    return buffer;
                }
                finally
                {
                    if (codePointer != IntPtr.Zero)
                    {
                        VirtualFree(codePointer, 0, 0x8000);
                        codePointer = IntPtr.Zero;
                    }
                }
            }

            [UnmanagedFunctionPointerAttribute(CallingConvention.Cdecl)]
            private delegate void CpuIDDelegate(uint level, uint[] buffer);

            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

            [DllImport("kernel32")]
            private static extern bool VirtualFree(IntPtr lpAddress, UInt32 dwSize, UInt32 dwFreeType);

            [Flags]
            private enum AllocationType : uint
            {
                COMMIT = 0x1000,
                RESERVE = 0x2000,
                RESET = 0x80000,
                LARGE_PAGES = 0x20000000,
                PHYSICAL = 0x400000,
                TOP_DOWN = 0x100000,
                WRITE_WATCH = 0x200000
            }

            [Flags]
            private enum MemoryProtection : uint
            {
                EXECUTE = 0x10,
                EXECUTE_READ = 0x20,
                EXECUTE_READWRITE = 0x40,
                EXECUTE_WRITECOPY = 0x80,
                NOACCESS = 0x01,
                READONLY = 0x02,
                READWRITE = 0x04,
                WRITECOPY = 0x08,
                GUARD_Modifierflag = 0x100,
                NOCACHE_Modifierflag = 0x200,
                WRITECOMBINE_Modifierflag = 0x400
            }

            private readonly static byte[] x86CodeBytes = {
                0x55,                           // push  ebp  
                0x8B, 0xEC,                     // mov   ebp,esp
                0x53,                           // push  ebx  
                0x57,                           // push  edi

                0x8B, 0x45, 0x08,               // mov   eax, dword ptr [ebp+8] (move level into eax)
                0xB9, 0x00, 0x00, 0x00, 0x00,   // mov ecx, 0
                0x0F, 0xA2,                     // cpuid

                0x8B, 0x7D, 0x0C,               // mov   edi, dword ptr [ebp+12] (move address of buffer into edi)
                0x89, 0x07,                     // mov   dword ptr [edi+0], eax  (write eax, ... to buffer)
                0x89, 0x5F, 0x04,               // mov   dword ptr [edi+4], ebx 
                0x89, 0x4F, 0x08,               // mov   dword ptr [edi+8], ecx 
                0x89, 0x57, 0x0C,               // mov   dword ptr [edi+12],edx 

                0x5F,                           // pop   edi  
                0x5B,                           // pop   ebx  
                0x8B, 0xE5,                     // mov   esp,ebp  
                0x5D,                           // pop   ebp 
                0xC3                            // ret
            };

            private readonly static byte[] x64CodeBytes = {
                0x53,                           // push rbx

                0x49, 0x89, 0xD0,               // mov r8,  rdx
                                                
                0x89, 0xC8,                     // mov eax, ecx
                0xB9, 0x00, 0x00, 0x00, 0x00,   // mov ecx, 0
                0x0F, 0xA2,                     // cpuid
                                                
                0x41, 0x89, 0x40, 0x00,         // mov    dword ptr [r8+0],  eax
                0x41, 0x89, 0x58, 0x04,         // mov    dword ptr [r8+4],  ebx
                0x41, 0x89, 0x48, 0x08,         // mov    dword ptr [r8+8],  ecx
                0x41, 0x89, 0x50, 0x0C,         // mov    dword ptr [r8+12], edx
                                                
                0x5B,                           // pop rbx
                0xC3                            // ret
            };

            public static bool SSE3() { return CpuID._f_1_ECX[0]; }
            public static bool PCLMULQDQ() { return CpuID._f_1_ECX[1]; }
            public static bool MONITOR() { return CpuID._f_1_ECX[3]; }
            public static bool SSSE3() { return CpuID._f_1_ECX[9]; }
            public static bool FMA() { return CpuID._f_1_ECX[12]; }
            public static bool CMPXCHG16B() { return CpuID._f_1_ECX[13]; }
            public static bool SSE41() { return CpuID._f_1_ECX[19]; }
            public static bool SSE42() { return CpuID._f_1_ECX[20]; }
            public static bool MOVBE() { return CpuID._f_1_ECX[22]; }
            public static bool POPCNT() { return CpuID._f_1_ECX[23]; }
            public static bool AES() { return CpuID._f_1_ECX[25]; }
            public static bool XSAVE() { return CpuID._f_1_ECX[26]; }
            public static bool OSXSAVE() { return CpuID._f_1_ECX[27]; }
            public static bool AVX() { return CpuID._f_1_ECX[28]; }
            public static bool F16C() { return CpuID._f_1_ECX[29]; }
            public static bool RDRAND() { return CpuID._f_1_ECX[30]; }

            public static bool MSR() { return CpuID._f_1_EDX[5]; }
            public static bool CX8() { return CpuID._f_1_EDX[8]; }
            public static bool SEP() { return CpuID._f_1_EDX[11]; }
            public static bool CMOV() { return CpuID._f_1_EDX[15]; }
            public static bool CLFSH() { return CpuID._f_1_EDX[19]; }
            public static bool MMX() { return CpuID._f_1_EDX[23]; }
            public static bool FXSR() { return CpuID._f_1_EDX[24]; }
            public static bool SSE() { return CpuID._f_1_EDX[25]; }
            public static bool SSE2() { return CpuID._f_1_EDX[26]; }

            public static bool FSGSBASE() { return CpuID._f_7_EBX[0]; }
            public static bool BMI1() { return CpuID._f_7_EBX[3]; }
            public static bool HLE() { return CpuID._isIntel && CpuID._f_7_EBX[4]; }
            public static bool AVX2() { return CpuID._f_7_EBX[5]; }
            public static bool BMI2() { return CpuID._f_7_EBX[8]; }
            public static bool ERMS() { return CpuID._f_7_EBX[9]; }
            public static bool INVPCID() { return CpuID._f_7_EBX[10]; }
            public static bool RTM() { return CpuID._isIntel && CpuID._f_7_EBX[11]; }
            public static bool AVX512F() { return CpuID._f_7_EBX[16]; }
            public static bool RDSEED() { return CpuID._f_7_EBX[18]; }
            public static bool ADX() { return CpuID._f_7_EBX[19]; }
            public static bool AVX512PF() { return CpuID._f_7_EBX[26]; }
            public static bool AVX512ER() { return CpuID._f_7_EBX[27]; }
            public static bool AVX512CD() { return CpuID._f_7_EBX[28]; }
            public static bool SHA() { return CpuID._f_7_EBX[29]; }
            public static bool HYBRID() { return CpuID._f_7_EDX[15]; }

            public static bool PREFETCHWT1() { return CpuID._f_7_ECX[0]; }

            public static bool LAHF() { return CpuID._f_81_ECX[0]; }
            public static bool LZCNT() { return CpuID._isIntel && CpuID._f_81_ECX[5]; }
            public static bool ABM() { return CpuID._isAMD && CpuID._f_81_ECX[5]; }
            public static bool SSE4a() { return CpuID._isAMD && CpuID._f_81_ECX[6]; }
            public static bool XOP() { return CpuID._isAMD && CpuID._f_81_ECX[11]; }
            public static bool TBM() { return CpuID._isAMD && CpuID._f_81_ECX[21]; }

            public static bool SYSCALL() { return CpuID._isIntel && CpuID._f_81_EDX[11]; }
            public static bool MMXEXT() { return CpuID._isAMD && CpuID._f_81_EDX[22]; }
            public static bool RDTSCP() { return CpuID._isIntel && CpuID._f_81_EDX[27]; }
            public static bool _3DNOWEXT() { return CpuID._isAMD && CpuID._f_81_EDX[30]; }
            public static bool _3DNOW() { return CpuID._isAMD && CpuID._f_81_EDX[31]; }
        }
    }
}
