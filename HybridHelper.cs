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
        public enum EfficiencyClass
        {
            Efficient = 0,
            Performance = 1
        }

        static HybridHelper()
        {
            Debug.WriteLine("**************************** HybridHelper ****************************");
            foreach (ProcessorPackage package in CpuInformation.ProcessorPackages)
            {
                Debug.Write(package);
            }
            Debug.WriteLine("**************************** HybridHelper ****************************");
        }

        public static uint SetCurrentThreadAffinity(EfficiencyClass efficiencyClass)
        {
            uint threadPreviousAffinityMask = 0;

            foreach (var package in CpuInformation.ProcessorPackages)
            {
                IntPtr threadHandle = winbase.GetCurrentThread();
                uint coreMask = (uint)package.CoreEfficiencyMasks[(int)efficiencyClass];
                threadPreviousAffinityMask |= winbase.SetThreadAffinityMask(threadHandle, coreMask);

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
            bitmask = bitmask - ((bitmask >> 1) & 0x5555555555555555UL);
            bitmask = (bitmask & 0x3333333333333333UL) + ((bitmask >> 2) & 0x3333333333333333UL);
            return (int)(unchecked(((bitmask + (bitmask >> 4)) & 0xF0F0F0F0F0F0F0FUL) * 0x101010101010101UL) >> 56);
        }

        private class CoreInformation
        {
            public int CoreCount { get; set; }
            public int EfficiencyClass { get; set; }
            public CacheSize CacheSize { get; set; } = new CacheSize();
        }

        private class CoreInformationWrapper
        {
            private Dictionary<int, CoreInformation> _coreInformation = new Dictionary<int, CoreInformation>();
            private BitArray _cacheSet = new BitArray(new bool[] { false, false });

            internal CoreInformationWrapper()
            {
                // initialize both efficiency
                _coreInformation[0] = new CoreInformation() { EfficiencyClass = 0 };
                _coreInformation[1] = new CoreInformation() { EfficiencyClass = 1 };
            }

            internal CoreInformation GetCoreInformation(int efficiencyClass)
            {
                Debug.Assert(efficiencyClass == 0 || efficiencyClass == 1);
                return _coreInformation[efficiencyClass];
            }

            internal void SetCache(int efficiencyClass)
            {
                _cacheSet[efficiencyClass] = true;
            }

            internal bool IsCacheSet(int efficiencyClass)
            {
                return _cacheSet[efficiencyClass];
            }

            public override string ToString()
            {
                StringBuilder sb = new StringBuilder();
                sb.Append($"CPU: {_coreInformation[1].CoreCount}P");

                if (_coreInformation[0].CoreCount > 0)
                {
                    sb.AppendLine($"+{_coreInformation[0].CoreCount}E");
                }

                sb.AppendLine($"P-Cache: {_coreInformation[1].CacheSize}");

                if (_coreInformation[0].CoreCount > 0)
                {
                    sb.AppendLine($"E-Cache: {_coreInformation[0].CacheSize}");
                }

                return sb.ToString();
            }
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

                sb.Remove(sb.Length - 2, 2);

                return sb.ToString();
            }
        }

        private class ProcessorPackage
        {
            private static IDictionary<int, long> _coreEfficiencyMasks = new Dictionary<int, long>();

            internal int EfficiencyClass { get; set; }
            internal long Mask { get; set; }

            internal IList<ProcessorCore> ProcessorCores { get; set; } = new List<ProcessorCore>();
            internal IDictionary<int, long> CoreEfficiencyMasks { get { return _coreEfficiencyMasks; } }

            internal static long GetProcessorCoreMaskByEfficiency(int efficiencyClass)
            {
                long mask = 0;
                if (_coreEfficiencyMasks.TryGetValue(efficiencyClass, out mask))
                {
                    return mask;
                }

                return 0;
            }

            internal int LogicalProcessorCount
            {
                get
                {
                    int logicalProcessorCount = 0;
                    foreach (int key in CoreEfficiencyMasks.Keys)
                    {
                        logicalProcessorCount += NumberOfSetBits((ulong)CoreEfficiencyMasks[key]);
                    }

                    return logicalProcessorCount;
                }
            }

            public override string ToString()
            {
                StringBuilder sb = new StringBuilder();
                CoreInformationWrapper coreInfoWrapper = new CoreInformationWrapper();

                foreach (ProcessorCore core in ProcessorCores)
                {
                    if (core.Flags == Constants.LTP_PC_SMT)
                    {
                        int numberOfLogicalCore = NumberOfSetBits((ulong)core.Mask);
                        coreInfoWrapper.GetCoreInformation(core.EfficiencyClass).CoreCount += numberOfLogicalCore;
                    }
                    else
                    {
                        coreInfoWrapper.GetCoreInformation(core.EfficiencyClass).CoreCount++;
                    }

                    if (!coreInfoWrapper.IsCacheSet(core.EfficiencyClass))
                    {
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

                            coreInfoWrapper.GetCoreInformation(core.EfficiencyClass).CacheSize.SetCacheSize(level, cache.CacheSize);
                        }

                        coreInfoWrapper.SetCache(core.EfficiencyClass);
                    }
                }

                sb.Append(coreInfoWrapper);

                return sb.ToString();
            }
        }

        private class ProcessorCore
        {
            internal int Flags { get; set; }
            internal bool IsSMT { get { return Flags == Constants.LTP_PC_SMT; } }
            internal int EfficiencyClass { get; set; }
            internal long Mask { get; set; }
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

            internal long Mask { get; set; }
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
                Initialize(GetLogicalProcessorInformationEx());
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
                                package.Mask = logicalProcInfo.ProcessorInformation.Processor.GroupMask.GroupAffinity.Mask;
                                package.EfficiencyClass = logicalProcInfo.ProcessorInformation.Processor.EfficiencyClass;
                                ProcessorPackages.Add(package);
                                break;
                            }
                        case LOGICAL_PROCESSOR_RELATIONSHIP.RelationProcessorCore:
                            {
                                Debug.Assert(package != null);
                                core = new ProcessorCore();
                                core.Flags = logicalProcInfo.ProcessorInformation.Processor.Flags;
                                core.EfficiencyClass = logicalProcInfo.ProcessorInformation.Processor.EfficiencyClass;
                                core.Mask = logicalProcInfo.ProcessorInformation.Processor.GroupMask.GroupAffinity.Mask;

                                if (!package.CoreEfficiencyMasks.ContainsKey(core.EfficiencyClass))
                                {
                                    package.CoreEfficiencyMasks[core.EfficiencyClass] = 0;
                                }
                                package.CoreEfficiencyMasks[core.EfficiencyClass] |= core.Mask;

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
                                cache.Mask = logicalProcInfo.ProcessorInformation.Cache.GroupMask.Mask;

                                core.ProcessorCaches.Add(cache);
                                break;
                            }
                    }
                }
            }

            private static SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX[] GetLogicalProcessorInformationEx()
            {
                // query for the length of the buffer needed
                uint bufferSize = 0;
                bool success = sysinfoapi.GetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP.RelationAll, IntPtr.Zero, ref bufferSize);
                Debug.Assert(!success);

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
                success = sysinfoapi.GetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP.RelationAll, rootPtr, ref bufferSize);

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
                catch
                {
                    sysLogicalProcInfos = null;
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
                Debug.Assert(sizeField.FieldType == typeof(int));

                uint readCount = 0;
                int structureSize = 0;
                IntPtr bufferPtr = IntPtr.Zero;

                for (bufferPtr = ptr; readCount < bufferSize; readCount += (uint)structureSize, bufferPtr += structureSize)
                {
                    T sysLogicalProcInfoEx = Marshal.PtrToStructure<T>(bufferPtr);
                    structureSize = (int)sizeField.GetValue(sysLogicalProcInfoEx);
                    list.Add(sysLogicalProcInfoEx);
                }

                return list.ToArray();
            }
        }

        private class sysinfoapi
        {
            [System.Runtime.InteropServices.DllImport("kernel32", SetLastError = true)]
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
        [StructLayout(LayoutKind.Sequential)]
        private struct GROUP_AFFINITY
        {
            internal long Mask;
            internal short Group;
            internal short Reserved1;
            internal short Reserved2;
            internal short Reserved3;
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
        [StructLayout(LayoutKind.Sequential)]
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
            internal short GroupCount;
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
        [StructLayout(LayoutKind.Sequential)]
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
            internal GROUP_MASK_UNION NumaNodeGroupMask;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct GROUP_MASK_UNION
        {
            [FieldOffset(0)]
            internal GROUP_AFFINITY GroupMask;

            [FieldOffset(0)]
            internal IntPtr GroupMaskArray;
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
        [StructLayout(LayoutKind.Sequential)]
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
            internal GROUP_AFFINITY GroupMask;
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
        [StructLayout(LayoutKind.Sequential)]
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
        //    PROCESSOR_RELATIONSHIP Processor;
        //    NUMA_NODE_RELATIONSHIP NumaNode;
        //    CACHE_RELATIONSHIP Cache;
        //    GROUP_RELATIONSHIP Group;
        //}
        //DUMMYUNIONNAME;
        //};
        //typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, *PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX;
        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX
        {
            internal LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
            internal int Size;
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
    }
}
