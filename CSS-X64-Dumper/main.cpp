#include <Windows.h>
#include <fstream>
#include <iomanip>
#include <vector>
#include "memory.h"
#include "ClientClassEx.h"
#include <map>
#include <Psapi.h>
#pragma comment(lib, "psapi.lib")

namespace senddump
{
	constexpr std::uintptr_t kServerClassNetworkName = 0x0;
	constexpr std::uintptr_t kServerClassTable = 0x8;
	constexpr std::uintptr_t kServerClassNext = 0x10;
	constexpr std::uintptr_t kServerClassClassId = 0x18;
	constexpr std::uintptr_t kServerClassInstanceBaselineIndex = 0x1C;

	constexpr std::uintptr_t kSendTableProps = 0x0;
	constexpr std::uintptr_t kSendTablePropCount = 0x8;
	constexpr std::uintptr_t kSendTableName = 0x10;

	// SendProp offsets (CS:S x64). Verified via ProbeArrayProp:
	//   +0x20 = m_pArrayProp (element template, sits 0x80 before the DPT_ARRAY)
	//   +0x30 = m_nElements  (e.g. m_hViewModel=2, m_flPoseParameter=24)
	//   +0x34 = m_ElementStride (4/8/12 matching handle/float/vector)
	constexpr std::uintptr_t kSendPropType = 0x10;
	constexpr std::uintptr_t kSendPropBits = 0x14;
	constexpr std::uintptr_t kSendPropLowValue = 0x18;
	constexpr std::uintptr_t kSendPropHighValue = 0x1C;
	constexpr std::uintptr_t kSendPropArrayProp = 0x20;
	constexpr std::uintptr_t kSendPropNumElements = 0x30;
	constexpr std::uintptr_t kSendPropElementStride = 0x34;
	constexpr std::uintptr_t kSendPropExcludeDTName = 0x38;
	constexpr std::uintptr_t kSendPropName = 0x48;
	constexpr std::uintptr_t kSendPropFlags = 0x54;
	constexpr std::uintptr_t kSendPropProxyFn = 0x58;
	constexpr std::uintptr_t kSendPropDataTableProxyFn = 0x60;
	constexpr std::uintptr_t kSendPropPriority = 0x5C;
	constexpr std::uintptr_t kSendPropDataTable = 0x68;
	constexpr std::uintptr_t kSendPropOffset = 0x70;
	constexpr std::size_t kSendPropStride = 0x80;
	constexpr int kSpropExclude = (1 << 6);
	constexpr int kSpropInsideArray = (1 << 8);
	constexpr int kSpropCollapsible = (1 << 11);
	constexpr int kSpropChangesOften = (1 << 10);
	constexpr int kSpropNumFlagBitsNetworked = 16;

	bool IsValidReadString(const std::string& value)
	{
		return !value.empty() && value != "**invalid**";
	}

	std::string SendPropTypeToString(int type)
	{
		switch (type)
		{
		case 0: return "int";
		case 1: return "float";
		case 2: return "Vector";
		case 3: return "Vector2D";
		case 4: return "string";
		case 5: return "array";
		case 6: return "datatable";
		case 7: return "int64";
		default: return "unknown";
		}
	}

	std::string ResolveProxySymbol(std::uintptr_t fnPtr)
	{
		if (!fnPtr)
			return "?";
		HMODULE hMods[1024];
		HANDLE hProcess = GetCurrentProcess();
		DWORD cbNeeded;
		if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
		{
			for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
			{
				MODULEINFO modInfo;
				if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo)))
				{
					if (fnPtr >= (std::uintptr_t)modInfo.lpBaseOfDll &&
						fnPtr < (std::uintptr_t)modInfo.lpBaseOfDll + modInfo.SizeOfImage)
					{
						char modName[MAX_PATH];
						char offsetStr[32];
						GetModuleFileNameExA(hProcess, hMods[i], modName, MAX_PATH);
						sprintf_s(offsetStr, "+0x%llx", fnPtr - (std::uintptr_t)modInfo.lpBaseOfDll);
						return std::string(modName) + offsetStr;
					}
				}
			}
		}
		char addrStr[32];
		sprintf_s(addrStr, "0x%llx", fnPtr);
		return std::string(addrStr);
	}

	bool IsLikelyServerClass(std::uintptr_t serverClassAddress)
	{
		if (!serverClassAddress)
			return false;

		const auto namePtr = g_Memory.Read<std::uintptr_t>(serverClassAddress + kServerClassNetworkName);
		const auto tablePtr = g_Memory.Read<std::uintptr_t>(serverClassAddress + kServerClassTable);
		if (!namePtr || !tablePtr)
			return false;

		const auto className = g_Memory.ReadString(namePtr);
		const auto tableNamePtr = g_Memory.Read<std::uintptr_t>(tablePtr + kSendTableName);
		const auto tableName = g_Memory.ReadString(tableNamePtr);
		const int propCount = g_Memory.Read<int>(tablePtr + kSendTablePropCount);
		const auto propsPtr = g_Memory.Read<std::uintptr_t>(tablePtr + kSendTableProps);

		return IsValidReadString(className)
			&& IsValidReadString(tableName)
			&& propCount >= 0 && propCount < 8192
			&& propsPtr != 0;
	}

	std::uintptr_t FindServerClassHead()
	{
		const auto serverModule = g_Memory.GetModuleAddress("server.dll");
		if (!serverModule.m_uAddress || serverModule.m_uSize < 8)
			return 0;

		std::vector<std::uint8_t> moduleBytes(serverModule.m_uSize);
		if (!g_Memory.ReadRaw(serverModule.m_uAddress, moduleBytes.data(), moduleBytes.size()))
			return 0;

		for (std::size_t i = 0; i + 8 <= moduleBytes.size(); ++i)
		{
			// x64 getter shape: mov rax, [rip+rel32]; ret
			if (moduleBytes[i] != 0x48 || moduleBytes[i + 1] != 0x8B || moduleBytes[i + 2] != 0x05 || moduleBytes[i + 7] != 0xC3)
				continue;

			const std::int32_t rel = *reinterpret_cast<std::int32_t*>(&moduleBytes[i + 3]);
			const std::uintptr_t instr = serverModule.m_uAddress + i;
			const std::uintptr_t storage = instr + 7 + static_cast<std::intptr_t>(rel);
			const std::uintptr_t head = g_Memory.Read<std::uintptr_t>(storage);
			if (!head)
				continue;

			if (IsLikelyServerClass(head))
				return head;
		}

		return 0;
	}

	bool NameInList(const std::vector<std::string>& names, const std::string& name)
	{
		for (const auto& it : names)
		{
			if (!_stricmp(it.c_str(), name.c_str()))
				return true;
		}
		return false;
	}

	bool QueueHasTable(const std::vector<std::uintptr_t>& queue, std::uintptr_t tableAddress)
	{
		const auto tableNamePtr = g_Memory.Read<std::uintptr_t>(tableAddress + kSendTableName);
		const auto tableName = g_Memory.ReadString(tableNamePtr);
		if (!IsValidReadString(tableName))
			return true;

		for (const auto& it : queue)
		{
			const auto itNamePtr = g_Memory.Read<std::uintptr_t>(it + kSendTableName);
			const auto itName = g_Memory.ReadString(itNamePtr);
			if (IsValidReadString(itName) && !_stricmp(itName.c_str(), tableName.c_str()))
				return true;
		}
		return false;
	}

	void ScheduleTable(
		std::uintptr_t tableAddress,
		std::vector<std::uintptr_t>& queue,
		const std::vector<std::string>& dumpedNames)
	{
		if (!tableAddress)
			return;

		const auto tableNamePtr = g_Memory.Read<std::uintptr_t>(tableAddress + kSendTableName);
		const auto tableName = g_Memory.ReadString(tableNamePtr);
		if (!IsValidReadString(tableName))
			return;
		if (NameInList(dumpedNames, tableName))
			return;
		if (QueueHasTable(queue, tableAddress))
			return;

		queue.push_back(tableAddress);
	}

	void AppendProp(std::ofstream& out, std::uintptr_t propAddress)
	{
		const auto namePtr = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropName);
		const auto name = g_Memory.ReadString(namePtr);
		if (!IsValidReadString(name))
			return;

		int type = g_Memory.Read<int>(propAddress + kSendPropType);
		const int flags = g_Memory.Read<int>(propAddress + kSendPropFlags);
		const int flagsNetworked = flags & ((1 << kSpropNumFlagBitsNetworked) - 1);
		const int bits = g_Memory.Read<int>(propAddress + kSendPropBits);
		const float lowValue = g_Memory.Read<float>(propAddress + kSendPropLowValue);
		const float highValue = g_Memory.Read<float>(propAddress + kSendPropHighValue);
		const auto dataTablePtr = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropDataTable);
		const auto arrayPropPtr = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropArrayProp);
		const auto excludeNamePtr = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropExcludeDTName);
		const auto excludeName = g_Memory.ReadString(excludeNamePtr);
		const int numElements = g_Memory.Read<int>(propAddress + kSendPropNumElements);

		if ((flags & kSpropExclude) != 0)
		{
			out << type
				<< ":" << std::uppercase << std::hex << std::setw(6) << std::setfill('0') << (flagsNetworked & 0xFFFFFF)
				<< ":" << name << ":" << (IsValidReadString(excludeName) ? excludeName : "") << " exclude\n"
				<< std::dec;
			return;
		}

		if (type == 6)
		{
			std::string tableName = "";
			if (dataTablePtr)
			{
				const auto tableNamePtr = g_Memory.Read<std::uintptr_t>(dataTablePtr + kSendTableName);
				tableName = g_Memory.ReadString(tableNamePtr);
			}
			out << type
				<< ":" << std::uppercase << std::hex << std::setw(6) << std::setfill('0') << (flagsNetworked & 0xFFFFFF)
				<< ":" << name << ":" << (IsValidReadString(tableName) ? tableName : "") << "\n"
				<< std::dec;
			return;
		}

		if (type == 5)
		{
			out << type
				<< ":" << std::uppercase << std::hex << std::setw(6) << std::setfill('0') << (flagsNetworked & 0xFFFFFF)
				<< ":" << name << "[" << std::dec << numElements << "]\n";
			return;
		}

		out << type
			<< ":" << std::uppercase << std::hex << std::setw(6) << std::setfill('0') << (flagsNetworked & 0xFFFFFF)
			<< ":" << name << ":"
			<< std::fixed << lowValue << "," << highValue << ","
			<< std::uppercase << std::hex << std::setw(8) << std::setfill('0') << static_cast<std::uint32_t>(bits)
			<< ((flags & kSpropInsideArray) ? " inside array" : "")
			<< std::dec << "\n";
	}

	void DumpAllSendTables(std::uintptr_t headAddress)
	{
		if (!headAddress)
		{
			printf("[senddump] g_pServerClassHead not found.\n");
			return;
		}

		std::ofstream out("sendtables_dump.txt");
		if (!out.is_open())
		{
			printf("[senddump] Failed to open sendtables_dump.txt\n");
			return;
		}

		printf("[senddump] g_pServerClassHead = 0x%llx\n", static_cast<unsigned long long>(headAddress));

		std::vector<std::uintptr_t> queue;
		std::vector<std::string> dumpedNames;
		std::vector<std::uintptr_t> classEntries;
		classEntries.reserve(512);

		for (auto current = headAddress; current; current = g_Memory.Read<std::uintptr_t>(current + kServerClassNext))
		{
			classEntries.push_back(current);
			const auto tableAddress = g_Memory.Read<std::uintptr_t>(current + kServerClassTable);
			ScheduleTable(tableAddress, queue, dumpedNames);
			if (classEntries.size() > 4096)
				break;
		}

		int tableIndex = 0;
		while (!queue.empty())
		{
			const auto tableAddress = queue.front();
			queue.erase(queue.begin());

			const auto tableNamePtr = g_Memory.Read<std::uintptr_t>(tableAddress + kSendTableName);
			const auto tableName = g_Memory.ReadString(tableNamePtr);
			const int propCount = g_Memory.Read<int>(tableAddress + kSendTablePropCount);
			const auto propsBase = g_Memory.Read<std::uintptr_t>(tableAddress + kSendTableProps);
			if (!IsValidReadString(tableName) || propCount < 0 || propCount > 8192 || !propsBase)
				continue;

			if (NameInList(dumpedNames, tableName))
				continue;

			dumpedNames.push_back(tableName);
			out << tableIndex++ << " " << tableName << "\n";
			out << tableName << ":" << propCount << "\n";

			for (int i = 0; i < propCount; ++i)
			{
				const auto propAddress = propsBase + (kSendPropStride * static_cast<std::size_t>(i));
				AppendProp(out, propAddress);

				const int type = g_Memory.Read<int>(propAddress + kSendPropType);
				const int flags = g_Memory.Read<int>(propAddress + kSendPropFlags);
				if (type == 6 && (flags & kSpropExclude) == 0)
				{
					const auto nestedTable = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropDataTable);
					ScheduleTable(nestedTable, queue, dumpedNames);
				}
			}
		}

		out << "serverclasses count: " << classEntries.size() << "\n";
		for (const auto& cls : classEntries)
		{
			const auto classId = g_Memory.Read<int>(cls + kServerClassClassId);
			const auto tableAddress = g_Memory.Read<std::uintptr_t>(cls + kServerClassTable);
			const auto classNamePtr = g_Memory.Read<std::uintptr_t>(cls + kServerClassNetworkName);
			const auto className = g_Memory.ReadString(classNamePtr);
			const auto tableNamePtr = g_Memory.Read<std::uintptr_t>(tableAddress + kSendTableName);
			const auto tableName = g_Memory.ReadString(tableNamePtr);
			if (!IsValidReadString(className) || !IsValidReadString(tableName))
				continue;

			out << "classid " << classId
				<< ", datatable: " << classId
				<< " dtname: " << tableName
				<< " name: " << className << "\n";
		}

		out.close();
		printf("[senddump] Wrote sendtables_dump.txt\n");
	}

	struct FlatProp
	{
		std::uintptr_t propAddress;
		int type;
		int flags;
		int bits;
		float lowValue;
		float highValue;
		int numElements;
		std::string name;
		std::string originDT;
		int offset;
		unsigned char priority;
		std::uintptr_t proxyFn;
		std::uintptr_t dtProxyFn;
		int elementStride;
	};

	// One-time probe: dump every 4-byte slot of a DPT_ARRAY SendProp so we can
	// find the real m_nElements offset on CS:S x64. Expected values:
	//   m_hViewModel       = 2
	//   m_flPoseParameter  = 24
	//   m_iszOverlayNames  = 15
	//   m_flOverlayTimes   = 15
	//   m_ragAngles        = 24
	//   m_ragPos           = 24
	// Whichever offset consistently contains those values is m_nElements.
	static int g_probeCount = 0;
	void ProbeArrayProp(std::uintptr_t propAddress, const std::string& propName, const std::string& currentDT)
	{
		if (g_probeCount >= 10) return;
		g_probeCount++;

		std::ofstream probe("sendprop_layout_probe.txt", std::ios::app);
		if (!probe.is_open()) return;

		probe << "\n=== PROBE #" << g_probeCount << " DPT_ARRAY '" << propName
			<< "' DT=" << currentDT
			<< " addr=0x" << std::hex << propAddress << std::dec << " ===\n";

		for (std::size_t off = 0; off < kSendPropStride; off += 4)
		{
			const auto asInt = g_Memory.Read<int>(propAddress + off);
			const auto asUint = static_cast<std::uint32_t>(asInt);
			probe << "  +0x" << std::hex << std::setw(2) << std::setfill('0') << off
				<< std::dec << std::setfill(' ')
				<< "  i32=" << std::setw(12) << asInt
				<< "  u32=0x" << std::hex << std::setw(8) << std::setfill('0') << asUint << std::setfill(' ')
				<< std::dec << "\n";
		}
		probe.close();
	}

	void BuildFlatPropsRecursive(std::uintptr_t tableAddress, std::vector<FlatProp>& flatProps, const std::string& currentDT, std::map<std::string, bool>& excludeMap)
	{
		if (!tableAddress)
			return;

		const auto tableNamePtr = g_Memory.Read<std::uintptr_t>(tableAddress + kSendTableName);
		const auto tableName = g_Memory.ReadString(tableNamePtr);
		const int propCount = g_Memory.Read<int>(tableAddress + kSendTablePropCount);
		const auto propsBase = g_Memory.Read<std::uintptr_t>(tableAddress + kSendTableProps);

		for (int i = 0; i < propCount; ++i)
		{
			const auto propAddress = propsBase + (kSendPropStride * static_cast<std::size_t>(i));
			const auto namePtr = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropName);
			const auto name = g_Memory.ReadString(namePtr);
			if (!IsValidReadString(name))
				continue;

			const int type = g_Memory.Read<int>(propAddress + kSendPropType);
			const int flags = g_Memory.Read<int>(propAddress + kSendPropFlags);

			// Probe first few DPT_ARRAY props to identify m_nElements offset.
			if (type == 5)
				ProbeArrayProp(propAddress, name, currentDT);

			if (flags & kSpropExclude)
			{
				const auto excludeNamePtr = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropExcludeDTName);
				const auto excludeName = g_Memory.ReadString(excludeNamePtr);
				if (IsValidReadString(excludeName))
					excludeMap[excludeName] = true;
				continue;
			}

			if (flags & kSpropInsideArray)
				continue;

			const auto excludeNamePtr = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropExcludeDTName);
			const auto excludeName = g_Memory.ReadString(excludeNamePtr);
			if (IsValidReadString(excludeName) && excludeMap.count(excludeName))
				continue;

			if (type == 6)
			{
				const auto dataTablePtr = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropDataTable);
				if (flags & kSpropCollapsible)
				{
					BuildFlatPropsRecursive(dataTablePtr, flatProps, currentDT, excludeMap);
				}
				else
				{
					BuildFlatPropsRecursive(dataTablePtr, flatProps, tableName, excludeMap);
				}
			}
			else if (type == 5)
			{
				// DPT_ARRAY: expand into numElements copies of the element prop
				// (at m_pArrayProp, typically the SendProp immediately before this
				// one carrying SPROP_INSIDEARRAY). Mirrors the engine's
				// SendTable_BuildHierarchy behavior.
				const auto elemPropAddr = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropArrayProp);
				const int  numElements   = g_Memory.Read<int>(propAddress + kSendPropNumElements);
				const int  elementStride = g_Memory.Read<int>(propAddress + kSendPropElementStride);
				if (!elemPropAddr || numElements <= 0 || numElements > 4096)
					continue;

				const int   elemType  = g_Memory.Read<int>(elemPropAddr + kSendPropType);
				const int   elemFlags = g_Memory.Read<int>(elemPropAddr + kSendPropFlags) & ~kSpropInsideArray;
				const int   elemBits  = g_Memory.Read<int>(elemPropAddr + kSendPropBits);
				const float elemLow   = g_Memory.Read<float>(elemPropAddr + kSendPropLowValue);
				const float elemHigh  = g_Memory.Read<float>(elemPropAddr + kSendPropHighValue);
				const auto  elemProxy = g_Memory.Read<std::uintptr_t>(elemPropAddr + kSendPropProxyFn);
				const int   arrayOff  = g_Memory.Read<int>(propAddress + kSendPropOffset);
				const unsigned char arrayPriority = g_Memory.Read<unsigned char>(propAddress + kSendPropPriority);

				for (int e = 0; e < numElements; ++e)
				{
					FlatProp fp;
					fp.propAddress   = elemPropAddr;
					fp.type          = elemType;
					fp.flags         = elemFlags;
					fp.bits          = elemBits;
					fp.lowValue      = elemLow;
					fp.highValue     = elemHigh;
					fp.numElements   = 0;
					fp.name          = name + "[" + std::to_string(e) + "]";
					fp.originDT      = currentDT;
					fp.offset        = arrayOff + e * elementStride;
					fp.priority      = arrayPriority;
					fp.proxyFn       = elemProxy;
					fp.dtProxyFn     = 0;
					fp.elementStride = elementStride;
					flatProps.push_back(fp);
				}
			}
			else
			{
				FlatProp fp;
				fp.propAddress = propAddress;
				fp.type = type;
				fp.flags = flags;
				fp.bits = g_Memory.Read<int>(propAddress + kSendPropBits);
				fp.lowValue = g_Memory.Read<float>(propAddress + kSendPropLowValue);
				fp.highValue = g_Memory.Read<float>(propAddress + kSendPropHighValue);
				fp.numElements = g_Memory.Read<int>(propAddress + kSendPropNumElements);
				fp.name = name;
				fp.originDT = currentDT;
				fp.offset = g_Memory.Read<int>(propAddress + kSendPropOffset);
				fp.priority = g_Memory.Read<unsigned char>(propAddress + kSendPropPriority);
				fp.proxyFn = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropProxyFn);
				fp.dtProxyFn = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropDataTableProxyFn);
				fp.elementStride = g_Memory.Read<int>(propAddress + kSendPropElementStride);
				flatProps.push_back(fp);
			}
		}
	}

	void SortFlatPropsByPriority(std::vector<FlatProp>& flatProps)
	{
		int start = 0;
		while (true)
		{
			bool found = false;
			for (int i = start; i < (int)flatProps.size(); ++i)
			{
				if (flatProps[i].flags & (1 << 10))
				{
					std::swap(flatProps[i], flatProps[start]);
					start++;
					found = true;
					break;
				}
			}
			if (!found)
				break;
		}
	}

	void DumpFlatLists(std::uintptr_t headAddress)
	{
		if (!headAddress)
			return;

		std::ofstream out("sendtables_dump.txt", std::ios::app);
		if (!out.is_open())
			return;

		out << "\n=== FLAT LISTS ===\n";

		std::vector<std::uintptr_t> classEntries;
		for (auto current = headAddress; current; current = g_Memory.Read<std::uintptr_t>(current + kServerClassNext))
		{
			classEntries.push_back(current);
			if (classEntries.size() > 4096) break;
		}

		for (const auto& cls : classEntries)
		{
			const auto classId = g_Memory.Read<int>(cls + kServerClassClassId);
			const auto tableAddress = g_Memory.Read<std::uintptr_t>(cls + kServerClassTable);
			const auto tableNamePtr = g_Memory.Read<std::uintptr_t>(tableAddress + kSendTableName);
			const auto tableName = g_Memory.ReadString(tableNamePtr);

			std::vector<FlatProp> flatProps;
			std::map<std::string, bool> excludeMap;
			BuildFlatPropsRecursive(tableAddress, flatProps, tableName, excludeMap);
			SortFlatPropsByPriority(flatProps);

			out << "FLAT " << tableName << " classid=" << classId << " count=" << flatProps.size() << "\n";
			for (int i = 0; i < (int)flatProps.size(); ++i)
			{
				const auto& fp = flatProps[i];
				std::string proxySym = ResolveProxySymbol(fp.proxyFn);
				std::string dtProxySym = ResolveProxySymbol(fp.dtProxyFn);
				out << "  flat[" << i << "] type=" << fp.type
					<< " flags=0x" << std::hex << (fp.flags & ((1 << kSpropNumFlagBitsNetworked) - 1)) << std::dec
					<< " bits=" << fp.bits
					<< " low=" << std::fixed << std::setprecision(9) << fp.lowValue
					<< " high=" << fp.highValue
					<< " nElements=" << fp.numElements
					<< " dotName=" << fp.name
					<< " originDT=" << fp.originDT
					<< " off=" << fp.offset
					<< " priority=" << (int)fp.priority
					<< " proxy=" << proxySym
					<< " dtProxy=" << dtProxySym
					<< " stride=" << fp.elementStride << "\n";
			}
		}

		out.close();
		printf("[senddump] Wrote FLAT LISTS section\n");
	}

	// ── engine-authoritative flat list via CSendTablePrecalc ───────────────────
	//
	// Layout (CS:S x64), verified via ProbeSendTableLayout:
	//   SendTable +0x18 = CSendTablePrecalc *m_pPrecalc
	//
	//   CSendTablePrecalc (has vtable so first 8 bytes are the vptr):
	//     +0x00 vtable ptr
	//     +0x08 CUtlVector #1 (datatable-node list, small count)
	//     +0x28 CUtlVector #2 (prop-proxy list, small count)
	//     +0x48 CUtlVector #3 = m_FlatProps  (array of SendProp*)
	//     +0x68 CUtlVector #4 = m_PropProxyIndices (byte[] same length)
	//
	//   CUtlVector<T> on x64 is 32 bytes:
	//     +0x00 T*   m_pMemory        (CUtlMemory::m_pMemory)
	//     +0x08 int  m_nAllocationCount
	//     +0x0C int  m_nGrowSize
	//     +0x10 int  m_Size
	//     +0x14 int  <pad>
	//     +0x18 T*   m_pElements      (debugger alias of m_pMemory)
	//
	// So m_FlatProps.m_pMemory = precalc+0x48, m_FlatProps.m_Size = precalc+0x58.
	constexpr std::uintptr_t kSendTablePrecalc        = 0x18;
	constexpr std::uintptr_t kPrecalcFlatPropsMemory  = 0x48;
	constexpr std::uintptr_t kPrecalcFlatPropsSize    = 0x58;

	static bool g_stProbeDone = false;
	void ProbeSendTableLayout(std::uintptr_t tableAddress, const std::string& tableName)
	{
		if (g_stProbeDone) return;
		// Only probe a handful of well-known tables.
		if (tableName != "DT_CSPlayer" && tableName != "DT_WORLD" && tableName != "DT_BaseAnimating")
			return;

		std::ofstream probe("sendtable_layout_probe.txt", std::ios::app);
		if (!probe.is_open()) return;

		probe << "\n=== SENDTABLE '" << tableName
			<< "' addr=0x" << std::hex << tableAddress << std::dec << " ===\n";
		for (std::size_t off = 0; off < 0x60; off += 8)
		{
			const auto asPtr = g_Memory.Read<std::uintptr_t>(tableAddress + off);
			const auto asInt = g_Memory.Read<int>(tableAddress + off);
			probe << "  +0x" << std::hex << std::setw(2) << std::setfill('0') << off
				<< std::dec << std::setfill(' ')
				<< "  ptr=0x" << std::hex << asPtr << std::dec
				<< "  i32=" << asInt << "\n";
		}

		// Try to follow the precalc pointer and dump its first 0x80 bytes.
		const auto precalcPtr = g_Memory.Read<std::uintptr_t>(tableAddress + kSendTablePrecalc);
		if (precalcPtr)
		{
			probe << "  -> precalc @ 0x" << std::hex << precalcPtr << std::dec << "\n";
			for (std::size_t off = 0; off < 0x80; off += 4)
			{
				const auto asInt  = g_Memory.Read<int>(precalcPtr + off);
				const auto asUint = static_cast<std::uint32_t>(asInt);
				const auto asPtr  = g_Memory.Read<std::uintptr_t>(precalcPtr + off);
				probe << "    precalc+0x" << std::hex << std::setw(2) << std::setfill('0') << off
					<< std::dec << std::setfill(' ')
					<< "  i32=" << std::setw(10) << asInt
					<< "  u32=0x" << std::hex << std::setw(8) << std::setfill('0') << asUint << std::setfill(' ')
					<< "  ptr=0x" << asPtr
					<< std::dec << "\n";
			}
		}
		probe.close();
	}

	struct EngineFlatSlot
	{
		std::uintptr_t propAddress;
		int   type;
		int   flags;
		int   bits;
		float lowValue;
		float highValue;
		int   numElements;
		std::string name;

		// For DPT_ARRAY (type=5): the element template prop, fetched via m_pArrayProp.
		// hasElem == false for non-array props.
		bool  hasElem = false;
		int   elemType = 0;
		int   elemFlags = 0;
		int   elemBits = 0;
		float elemLow = 0.0f;
		float elemHigh = 0.0f;
	};

	// Read up to [cap] prop pointers from the precalc's m_FlatProps CUtlVector.
	bool ReadEngineFlatProps(std::uintptr_t tableAddress, std::vector<EngineFlatSlot>& out, int& sizeOut)
	{
		const auto precalc = g_Memory.Read<std::uintptr_t>(tableAddress + kSendTablePrecalc);
		if (!precalc) return false;

		const auto arrayPtr = g_Memory.Read<std::uintptr_t>(precalc + kPrecalcFlatPropsMemory);
		const int  size     = g_Memory.Read<int>(precalc + kPrecalcFlatPropsSize);
		sizeOut = size;
		if (!arrayPtr || size <= 0 || size > 8192) return false;

		out.reserve(size);
		for (int i = 0; i < size; ++i)
		{
			const auto slotAddr = arrayPtr + static_cast<std::size_t>(i) * sizeof(std::uintptr_t);
			const auto propAddr = g_Memory.Read<std::uintptr_t>(slotAddr);
			if (!propAddr) continue;

			EngineFlatSlot s;
			s.propAddress = propAddr;
			s.type        = g_Memory.Read<int>(propAddr + kSendPropType);
			s.flags       = g_Memory.Read<int>(propAddr + kSendPropFlags);
			s.bits        = g_Memory.Read<int>(propAddr + kSendPropBits);
			s.lowValue    = g_Memory.Read<float>(propAddr + kSendPropLowValue);
			s.highValue   = g_Memory.Read<float>(propAddr + kSendPropHighValue);
			s.numElements = g_Memory.Read<int>(propAddr + kSendPropNumElements);

			const auto namePtr = g_Memory.Read<std::uintptr_t>(propAddr + kSendPropName);
			s.name = g_Memory.ReadString(namePtr);
			if (!IsValidReadString(s.name)) s.name = "?";

			// For DPT_ARRAY props, fetch the element template via m_pArrayProp at +0x20.
			// The Kotlin decoder needs these to read array values inline (count + elements).
			if (s.type == 5)
			{
				const auto elemPropAddr = g_Memory.Read<std::uintptr_t>(propAddr + kSendPropArrayProp);
				if (elemPropAddr)
				{
					s.hasElem   = true;
					s.elemType  = g_Memory.Read<int>(elemPropAddr + kSendPropType);
					s.elemFlags = g_Memory.Read<int>(elemPropAddr + kSendPropFlags) & ~kSpropInsideArray;
					s.elemBits  = g_Memory.Read<int>(elemPropAddr + kSendPropBits);
					s.elemLow   = g_Memory.Read<float>(elemPropAddr + kSendPropLowValue);
					s.elemHigh  = g_Memory.Read<float>(elemPropAddr + kSendPropHighValue);
				}
			}

			out.push_back(s);
		}
		return true;
	}

	void DumpEngineFlatLists(std::uintptr_t headAddress)
	{
		if (!headAddress) return;

		std::ofstream out("sendtables_dump.txt", std::ios::app);
		if (!out.is_open()) return;

		out << "\n=== ENGINE FLAT LISTS (m_pPrecalc->m_FlatProps) ===\n";

		std::vector<std::uintptr_t> classEntries;
		for (auto current = headAddress; current; current = g_Memory.Read<std::uintptr_t>(current + kServerClassNext))
		{
			classEntries.push_back(current);
			if (classEntries.size() > 4096) break;
		}

		int matchedCount = 0;
		int totalCount   = 0;
		for (const auto& cls : classEntries)
		{
			const auto classId     = g_Memory.Read<int>(cls + kServerClassClassId);
			const auto tableAddr   = g_Memory.Read<std::uintptr_t>(cls + kServerClassTable);
			const auto tableNamePtr = g_Memory.Read<std::uintptr_t>(tableAddr + kSendTableName);
			const auto tableName   = g_Memory.ReadString(tableNamePtr);
			if (!IsValidReadString(tableName)) continue;

			ProbeSendTableLayout(tableAddr, tableName);

			std::vector<EngineFlatSlot> slots;
			int rawSize = 0;
			const bool ok = ReadEngineFlatProps(tableAddr, slots, rawSize);

			out << "ENGINE_FLAT " << tableName << " classid=" << classId
				<< " reportedSize=" << rawSize
				<< " readSize=" << slots.size()
				<< " ok=" << (ok ? 1 : 0) << "\n";

			if (!ok) continue;
			++totalCount;

			for (std::size_t i = 0; i < slots.size(); ++i)
			{
				const auto& s = slots[i];
				out << "  eflat[" << i << "]"
					<< " type=" << s.type
					<< " flags=0x" << std::hex << (s.flags & ((1 << kSpropNumFlagBitsNetworked) - 1)) << std::dec
					<< " bits=" << s.bits
					<< " low=" << std::fixed << std::setprecision(9) << s.lowValue
					<< " high=" << s.highValue
					<< " nElements=" << s.numElements
					<< " dotName=" << s.name
					<< " addr=0x" << std::hex << s.propAddress << std::dec;
				if (s.hasElem)
				{
					out << " elemType=" << s.elemType
						<< " elemFlags=0x" << std::hex << (s.elemFlags & ((1 << kSpropNumFlagBitsNetworked) - 1)) << std::dec
						<< " elemBits=" << s.elemBits
						<< " elemLow=" << std::fixed << std::setprecision(9) << s.elemLow
						<< " elemHigh=" << s.elemHigh;
				}
				out << "\n";
			}
			if (slots.size() > 0) ++matchedCount;
		}

		// Mark probe complete so subsequent runs don't re-probe (but we only ran once anyway).
		g_stProbeDone = true;

		out.close();
		printf("[senddump] Wrote ENGINE FLAT LISTS (%d of %d classes had a precalc)\n",
			matchedCount, totalCount);
	}

	void DumpClassIds(std::uintptr_t headAddress)
	{
		if (!headAddress)
			return;

		std::ofstream out("classid_dump.txt");
		if (!out.is_open())
		{
			printf("[senddump] Failed to open classid_dump.txt\n");
			return;
		}

		out << "enum classIDs {\n";

		std::vector<std::uintptr_t> classEntries;
		for (auto current = headAddress; current; current = g_Memory.Read<std::uintptr_t>(current + kServerClassNext))
		{
			classEntries.push_back(current);
			if (classEntries.size() > 4096) break;
		}

		for (const auto& cls : classEntries)
		{
			const auto classId = g_Memory.Read<int>(cls + kServerClassClassId);
			const auto namePtr = g_Memory.Read<std::uintptr_t>(cls + kServerClassNetworkName);
			const auto name = g_Memory.ReadString(namePtr);
			if (IsValidReadString(name))
			{
				out << "\t" << name << " = " << classId << ",\n";
			}
		}

		out << "};\n";
		out.close();
		printf("[senddump] Wrote classid_dump.txt\n");
	}
}

namespace serverdump
{
	constexpr std::uintptr_t kServerClassNetworkName = 0x0;
	constexpr std::uintptr_t kServerClassTable = 0x8;
	constexpr std::uintptr_t kServerClassNext = 0x10;
	constexpr std::uintptr_t kServerClassClassId = 0x18;
	constexpr std::uintptr_t kServerClassInstanceBaselineIndex = 0x1C;

	constexpr std::uintptr_t kSendTableProps = 0x0;
	constexpr std::uintptr_t kSendTablePropCount = 0x8;
	constexpr std::uintptr_t kSendTableName = 0x10;

	constexpr std::uintptr_t kSendPropType = 0x10;
	constexpr std::uintptr_t kSendPropBits = 0x14;
	constexpr std::uintptr_t kSendPropLowValue = 0x18;
	constexpr std::uintptr_t kSendPropHighValue = 0x1C;
	constexpr std::uintptr_t kSendPropArrayProp = 0x18;
	constexpr std::uintptr_t kSendPropNumElements = 0x28;
	constexpr std::uintptr_t kSendPropElementStride = 0x2C;
	constexpr std::uintptr_t kSendPropExcludeDTName = 0x38;
	constexpr std::uintptr_t kSendPropName = 0x48;
	constexpr std::uintptr_t kSendPropFlags = 0x54;
	constexpr std::uintptr_t kSendPropProxyFn = 0x58;
	constexpr std::uintptr_t kSendPropDataTableProxyFn = 0x60;
	constexpr std::uintptr_t kSendPropPriority = 0x5C;
	constexpr std::uintptr_t kSendPropDataTable = 0x68;
	constexpr std::uintptr_t kSendPropOffset = 0x70;
	constexpr std::size_t kSendPropStride = 0x80;
	constexpr int kSpropExclude = (1 << 6);
	constexpr int kSpropInsideArray = (1 << 8);
	constexpr int kSpropCollapsible = (1 << 11);
	constexpr int kSpropChangesOften = (1 << 10);
	constexpr int kSpropNumFlagBitsNetworked = 16;

	bool IsValidReadString(const std::string& value)
	{
		return !value.empty() && value != "**invalid**";
	}

	void AppendProp(std::ofstream& out, std::uintptr_t propAddress)
	{
		const auto namePtr = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropName);
		const auto name = g_Memory.ReadString(namePtr);
		const auto tableNamePtr = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropDataTable);
		const auto tableName = g_Memory.ReadString(tableNamePtr);
		const int type = g_Memory.Read<int>(propAddress + kSendPropType);
		const int flags = g_Memory.Read<int>(propAddress + kSendPropFlags);
		const int flagsNetworked = flags & ((1 << kSpropNumFlagBitsNetworked) - 1);
		const int bits = g_Memory.Read<int>(propAddress + kSendPropBits);
		const float lowValue = g_Memory.Read<float>(propAddress + kSendPropLowValue);
		const float highValue = g_Memory.Read<float>(propAddress + kSendPropHighValue);
		const auto dataTablePtr = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropDataTable);
		const auto arrayPropPtr = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropArrayProp);
		const auto excludeNamePtr = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropExcludeDTName);
		const auto excludeName = g_Memory.ReadString(excludeNamePtr);
		const int numElements = g_Memory.Read<int>(propAddress + kSendPropNumElements);

		if ((flags & kSpropExclude) != 0)
		{
			out << type
				<< ":" << std::uppercase << std::hex << std::setw(6) << std::setfill('0') << (flagsNetworked & 0xFFFFFF)
				<< ":" << name << ":" << (IsValidReadString(excludeName) ? excludeName : "") << " exclude\n"
				<< std::dec;
			return;
		}

		if (type == 6)
		{
			out << type
				<< ":" << std::uppercase << std::hex << std::setw(6) << std::setfill('0') << (flagsNetworked & 0xFFFFFF)
				<< ":" << name << ":" << (IsValidReadString(tableName) ? tableName : "") << "\n"
				<< std::dec;
			return;
		}

		out << type
			<< ":" << std::uppercase << std::hex << std::setw(6) << std::setfill('0') << (flagsNetworked & 0xFFFFFF)
			<< ":" << name << ":"
			<< std::fixed << lowValue << "," << highValue << ","
			<< std::uppercase << std::hex << std::setw(8) << std::setfill('0') << static_cast<std::uint32_t>(bits)
			<< ((flags & kSpropInsideArray) ? " inside array" : "")
			<< std::dec << "\n";
	}

	void ScheduleTable(std::uintptr_t tableAddress, std::vector<std::uintptr_t>& queue, std::vector<std::string>& dumpedNames)
	{
		if (!tableAddress)
			return;

		const auto tableNamePtr = g_Memory.Read<std::uintptr_t>(tableAddress + kSendTableName);
		const auto tableName = g_Memory.ReadString(tableNamePtr);
		if (!IsValidReadString(tableName))
			return;

		for (const auto& name : dumpedNames)
		{
			if (name == tableName)
				return;
		}

		queue.push_back(tableAddress);
	}

	struct FlatProp
	{
		std::uintptr_t propAddress;
		int type;
		int flags;
		int bits;
		float lowValue;
		float highValue;
		int numElements;
		std::string name;
		std::string originDT;
		int offset;
		unsigned char priority;
		std::uintptr_t proxyFn;
		std::uintptr_t dtProxyFn;
		int elementStride;
	};

	void BuildFlatPropsRecursive(std::uintptr_t tableAddress, std::vector<FlatProp>& flatProps, const std::string& currentDT, std::map<std::string, bool>& excludeMap)
	{
		if (!tableAddress)
			return;

		const auto tableNamePtr = g_Memory.Read<std::uintptr_t>(tableAddress + kSendTableName);
		const auto tableName = g_Memory.ReadString(tableNamePtr);
		const int propCount = g_Memory.Read<int>(tableAddress + kSendTablePropCount);
		const auto propsBase = g_Memory.Read<std::uintptr_t>(tableAddress + kSendTableProps);

		for (int i = 0; i < propCount; ++i)
		{
			const auto propAddress = propsBase + (kSendPropStride * static_cast<std::size_t>(i));
			const auto namePtr = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropName);
			const auto name = g_Memory.ReadString(namePtr);
			if (!IsValidReadString(name))
				continue;

			const int type = g_Memory.Read<int>(propAddress + kSendPropType);
			const int flags = g_Memory.Read<int>(propAddress + kSendPropFlags);

			if (flags & kSpropExclude)
			{
				const auto excludeNamePtr = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropExcludeDTName);
				const auto excludeName = g_Memory.ReadString(excludeNamePtr);
				if (IsValidReadString(excludeName))
					excludeMap[excludeName] = true;
				continue;
			}

			if (flags & kSpropInsideArray)
				continue;

			const auto excludeNamePtr = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropExcludeDTName);
			const auto excludeName = g_Memory.ReadString(excludeNamePtr);
			if (IsValidReadString(excludeName) && excludeMap.count(excludeName))
				continue;

			if (type == 6)
			{
				const auto dataTablePtr = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropDataTable);
				if (flags & kSpropCollapsible)
				{
					BuildFlatPropsRecursive(dataTablePtr, flatProps, currentDT, excludeMap);
				}
				else
				{
					BuildFlatPropsRecursive(dataTablePtr, flatProps, tableName, excludeMap);
				}
			}
			else
			{
				FlatProp fp;
				fp.propAddress = propAddress;
				fp.type = type;
				fp.flags = flags;
				fp.bits = g_Memory.Read<int>(propAddress + kSendPropBits);
				fp.lowValue = g_Memory.Read<float>(propAddress + kSendPropLowValue);
				fp.highValue = g_Memory.Read<float>(propAddress + kSendPropHighValue);
				fp.numElements = g_Memory.Read<int>(propAddress + kSendPropNumElements);
				fp.name = name;
				fp.originDT = currentDT;
				fp.offset = g_Memory.Read<int>(propAddress + kSendPropOffset);
				fp.priority = g_Memory.Read<unsigned char>(propAddress + kSendPropPriority);
				fp.proxyFn = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropProxyFn);
				fp.dtProxyFn = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropDataTableProxyFn);
				fp.elementStride = g_Memory.Read<int>(propAddress + kSendPropElementStride);
				flatProps.push_back(fp);
			}
		}
	}

	void SortFlatPropsByPriority(std::vector<FlatProp>& flatProps)
	{
		int start = 0;
		while (true)
		{
			bool found = false;
			for (int i = start; i < (int)flatProps.size(); ++i)
			{
				if (flatProps[i].flags & (1 << 10))
				{
					std::swap(flatProps[i], flatProps[start]);
					start++;
					found = true;
					break;
				}
			}
			if (!found)
				break;
		}
	}

	std::string ResolveProxySymbol(std::uintptr_t fnPtr)
	{
		if (!fnPtr)
			return "?";
		HMODULE hMods[1024];
		HANDLE hProcess = GetCurrentProcess();
		DWORD cbNeeded;
		if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
		{
			for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
			{
				MODULEINFO modInfo;
				if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo)))
				{
					if (fnPtr >= (std::uintptr_t)modInfo.lpBaseOfDll &&
						fnPtr < (std::uintptr_t)modInfo.lpBaseOfDll + modInfo.SizeOfImage)
					{
						char modName[MAX_PATH];
						char offsetStr[32];
						GetModuleFileNameExA(hProcess, hMods[i], modName, MAX_PATH);
						sprintf_s(offsetStr, "+0x%llx", fnPtr - (std::uintptr_t)modInfo.lpBaseOfDll);
						return std::string(modName) + offsetStr;
					}
				}
			}
		}
		char addrStr[32];
		sprintf_s(addrStr, "0x%llx", fnPtr);
		return std::string(addrStr);
	}

	std::uintptr_t FindServerClassHead()
	{
		const auto serverModule = g_Memory.GetModuleAddress("server.dll");
		if (!serverModule.m_uAddress)
		{
			printf("[serverdump] server.dll not found\n");
			return 0;
		}

		printf("[serverdump] server.dll at 0x%llx, size 0x%x\n", serverModule.m_uAddress, serverModule.m_uSize);

		std::vector<std::uint8_t> moduleBytes(serverModule.m_uSize);
		if (!g_Memory.ReadRaw(serverModule.m_uAddress, moduleBytes.data(), serverModule.m_uSize))
		{
			printf("[serverdump] Failed to read server.dll\n");
			return 0;
		}

		const std::uintptr_t base = serverModule.m_uAddress;

		std::uintptr_t bestCandidate = 0;
		int bestScore = 0;

		for (std::size_t i = 0; i + 0x20 < moduleBytes.size(); ++i)
		{
			const std::uintptr_t candidate = base + i;

			const auto namePtr = g_Memory.Read<std::uintptr_t>(candidate + kServerClassNetworkName);
			const auto tablePtr = g_Memory.Read<std::uintptr_t>(candidate + kServerClassTable);
			const auto nextPtr = g_Memory.Read<std::uintptr_t>(candidate + kServerClassNext);
			const auto classId = g_Memory.Read<int>(candidate + kServerClassClassId);

			if (!namePtr || !tablePtr)
				continue;

			const auto name = g_Memory.ReadString(namePtr);
			if (name.empty() || name == "**invalid**")
				continue;

			const auto tableNamePtr = g_Memory.Read<std::uintptr_t>(tablePtr + kSendTableName);
			const auto tableName = g_Memory.ReadString(tableNamePtr);
			if (tableName.empty() || tableName == "**invalid**")
				continue;

			int score = 0;

			if (classId >= 0 && classId < 1024)
				score++;

			if (nextPtr == 0 || (nextPtr > base && nextPtr < base + serverModule.m_uSize))
				score++;

			if (name.length() > 2 && name.length() < 64)
				score++;

			if (tableName.length() > 2 && tableName.length() < 64)
				score++;

			if (score > bestScore)
			{
				bestScore = score;
				bestCandidate = candidate;
			}
		}

		if (bestScore >= 2)
		{
			printf("[serverdump] Found g_pServerClassHead at 0x%llx (score %d)\n", bestCandidate, bestScore);
			return bestCandidate;
		}

		printf("[serverdump] Could not find g_pServerClassHead\n");
		return 0;
	}

	void DumpAllSendTables(std::uintptr_t headAddress)
	{
		if (!headAddress)
			return;

		std::ofstream out("sendtables_dump_server.txt");
		if (!out.is_open())
		{
			printf("[serverdump] Failed to open sendtables_dump_server.txt\n");
			return;
		}

		printf("[serverdump] g_pServerClassHead = 0x%llx\n", static_cast<unsigned long long>(headAddress));

		std::vector<std::uintptr_t> queue;
		std::vector<std::string> dumpedNames;
		std::vector<std::uintptr_t> classEntries;

		for (auto current = headAddress; current; current = g_Memory.Read<std::uintptr_t>(current + kServerClassNext))
		{
			classEntries.push_back(current);
			if (classEntries.size() > 4096) break;
		}

		for (const auto& cls : classEntries)
		{
			const auto tableAddress = g_Memory.Read<std::uintptr_t>(cls + kServerClassTable);
			ScheduleTable(tableAddress, queue, dumpedNames);
		}

		int tableIndex = 0;
		while (!queue.empty())
		{
			const auto tableAddress = queue.front();
			queue.erase(queue.begin());

			const auto tableNamePtr = g_Memory.Read<std::uintptr_t>(tableAddress + kSendTableName);
			const auto tableName = g_Memory.ReadString(tableNamePtr);
			const int propCount = g_Memory.Read<int>(tableAddress + kSendTablePropCount);
			const auto propsBase = g_Memory.Read<std::uintptr_t>(tableAddress + kSendTableProps);
			if (!senddump::IsValidReadString(tableName) || propCount < 0 || propCount > 8192 || !propsBase)
				continue;

			dumpedNames.push_back(tableName);

			out << tableIndex++ << " " << tableName << "\n";
			out << tableName << ":" << propCount << "\n";

			for (int i = 0; i < propCount; ++i)
			{
				const auto propAddress = propsBase + (kSendPropStride * static_cast<std::size_t>(i));
				AppendProp(out, propAddress);

				const int type = g_Memory.Read<int>(propAddress + kSendPropType);
				const int flags = g_Memory.Read<int>(propAddress + kSendPropFlags);
				if (type == 6 && (flags & kSpropExclude) == 0)
				{
					const auto nestedTable = g_Memory.Read<std::uintptr_t>(propAddress + kSendPropDataTable);
					ScheduleTable(nestedTable, queue, dumpedNames);
				}
			}
		}

		out << "serverclasses count: " << classEntries.size() << "\n";
		for (const auto& cls : classEntries)
		{
			const auto classId = g_Memory.Read<int>(cls + kServerClassClassId);
			const auto tableAddress = g_Memory.Read<std::uintptr_t>(cls + kServerClassTable);
			const auto classNamePtr = g_Memory.Read<std::uintptr_t>(cls + kServerClassNetworkName);
			const auto className = g_Memory.ReadString(classNamePtr);
			const auto tableNamePtr = g_Memory.Read<std::uintptr_t>(tableAddress + kSendTableName);
			const auto tableName = g_Memory.ReadString(tableNamePtr);
			out << "classid " << classId
				<< ", datatable: " << classId
				<< " dtname: " << tableName
				<< " name: " << className << "\n";
		}

		out.close();
		printf("[serverdump] Wrote sendtables_dump_server.txt\n");
	}

	void DumpFlatLists(std::uintptr_t headAddress)
	{
		if (!headAddress)
			return;

		std::ofstream out("sendtables_dump_server.txt", std::ios::app);
		if (!out.is_open())
			return;

		out << "\n=== FLAT LISTS ===\n";

		std::vector<std::uintptr_t> classEntries;
		for (auto current = headAddress; current; current = g_Memory.Read<std::uintptr_t>(current + kServerClassNext))
		{
			classEntries.push_back(current);
			if (classEntries.size() > 4096) break;
		}

		for (const auto& cls : classEntries)
		{
			const auto classId = g_Memory.Read<int>(cls + kServerClassClassId);
			const auto tableAddress = g_Memory.Read<std::uintptr_t>(cls + kServerClassTable);
			const auto tableNamePtr = g_Memory.Read<std::uintptr_t>(tableAddress + kSendTableName);
			const auto tableName = g_Memory.ReadString(tableNamePtr);

			std::vector<senddump::FlatProp> flatProps;
			std::map<std::string, bool> excludeMap;
			BuildFlatPropsRecursive(tableAddress, flatProps, tableName, excludeMap);
			SortFlatPropsByPriority(flatProps);

			out << "FLAT " << tableName << " classid=" << classId << " count=" << flatProps.size() << "\n";
			for (int i = 0; i < (int)flatProps.size(); ++i)
			{
				const auto& fp = flatProps[i];
				std::string proxySym = ResolveProxySymbol(fp.proxyFn);
				std::string dtProxySym = ResolveProxySymbol(fp.dtProxyFn);
				out << "  flat[" << i << "] type=" << fp.type
					<< " flags=0x" << std::hex << (fp.flags & ((1 << kSpropNumFlagBitsNetworked) - 1)) << std::dec
					<< " bits=" << fp.bits
					<< " low=" << std::fixed << std::setprecision(9) << fp.lowValue
					<< " high=" << fp.highValue
					<< " nElements=" << fp.numElements
					<< " dotName=" << fp.name
					<< " originDT=" << fp.originDT
					<< " off=" << fp.offset
					<< " priority=" << (int)fp.priority
					<< " proxy=" << proxySym
					<< " dtProxy=" << dtProxySym
					<< " stride=" << fp.elementStride << "\n";
			}
		}

		out.close();
		printf("[serverdump] Wrote FLAT LISTS section\n");
	}

	void DumpClassIds(std::uintptr_t headAddress)
	{
		if (!headAddress)
			return;

		std::ofstream out("classid_dump_server.txt");
		if (!out.is_open())
		{
			printf("[serverdump] Failed to open classid_dump_server.txt\n");
			return;
		}

		out << "enum classIDs {\n";

		std::vector<std::uintptr_t> classEntries;
		for (auto current = headAddress; current; current = g_Memory.Read<std::uintptr_t>(current + kServerClassNext))
		{
			classEntries.push_back(current);
			if (classEntries.size() > 4096) break;
		}

		for (const auto& cls : classEntries)
		{
			const auto classId = g_Memory.Read<int>(cls + kServerClassClassId);
			const auto namePtr = g_Memory.Read<std::uintptr_t>(cls + kServerClassNetworkName);
			const auto name = g_Memory.ReadString(namePtr);
			if (senddump::IsValidReadString(name))
			{
				out << "\t" << name << " = " << classId << ",\n";
			}
		}

		out << "};\n";
		out.close();
		printf("[serverdump] Wrote classid_dump_server.txt\n");
	}
}

void PrintArrayProperties(CRecvPropEx* prop) {
	if (strstr(prop->GetArrayProp()->GetType().c_str(), "class"))
		printf("\t\t\tHas Props: %s | GetType: %s | Offset: 0x%x\n", prop->GetArrayProp()->GetName().c_str(), prop->GetArrayProp()->GetDataTable()->GetNetTableName(), prop->GetArrayProp()->GetOffset());
	else
		printf("\t\t\tHas Props: %s | GetType: %s | Offset: 0x%x\n", prop->GetArrayProp()->GetName().c_str(), prop->GetType().c_str(), prop->GetArrayProp()->GetOffset());
	if (strstr(prop->GetArrayProp()->GetType().c_str(), "class")) {
		printf("\t\t\tClass: %s\n", prop->GetArrayProp()->GetDataTable()->GetNetTableName().c_str());
	}
}

std::string GetRealType(CRecvPropEx* prop) {
	if (strstr(prop->GetArrayProp()->GetType().c_str(), "class"))
		return prop->GetArrayProp()->GetDataTable()->GetNetTableName();
	else if (strstr(prop->GetArrayProp()->GetType().c_str(), "[]")) {
		return GetRealType(prop->GetArrayProp());
	}
	return prop->GetArrayProp()->GetType().c_str();
}
void DumpProperties(CRecVTableEx* t, bool dumpOffsets) {
	for (int i = 0; i < t->GetPropCount(); i++) {
		auto prop = t->GetPropAtIndex(i);
		if (strstr(prop->GetName().c_str(), "baseclass") && !strstr(prop->GetDataTable()->GetPropAtIndex(0)->GetDataTable()->GetNetTableName().c_str(), "invalid")) {
			printf("\t\tParent: %s\n", prop->GetDataTable()->GetPropAtIndex(0)->GetDataTable()->GetNetTableName().c_str());
			DumpProperties(prop->GetDataTable(), false);
		}
		else if (!strstr(prop->GetName().c_str(), "baseclass")) {
			if (strstr(prop->GetType().c_str(), "class"))
				printf("\t\tProp: %s => 0x%x | %s \n", prop->GetName().c_str(), prop->GetOffset(), prop->GetDataTable()->GetNetTableName().c_str());
			else if (strstr(prop->GetType().c_str(), "[]")) {
				printf("\t\tProp: %s => 0x%x | %s[%i] \n", prop->GetName().c_str(), prop->GetOffset(), GetRealType(prop).c_str(), prop->GetNumberOfElements());
				// PrintArrayProperties(prop);
			}
			else {
				printf("\t\tProp: %s => 0x%x | %s \n", prop->GetName().c_str(), prop->GetOffset(), prop->GetType().c_str());

			}
		}
	}
}

void DumpPropertiesToFile(CRecVTableEx* t, std::ofstream& out, int depth = 0) {
	if (!t)
		return;

	for (int i = 0; i < t->GetPropCount(); i++) {
		auto prop = t->GetPropAtIndex(i);
		if (!prop)
			continue;

		const std::string indent(depth * 2, ' ');
		const auto propName = prop->GetName();
		const auto propType = prop->GetType();
		const auto propOffset = prop->GetOffset();

		if (strstr(propName.c_str(), "baseclass")) {
			auto dataTable = prop->GetDataTable();
			if (dataTable) {
				out << indent << "Parent: " << dataTable->GetNetTableName() << "\n";
				DumpPropertiesToFile(dataTable, out, depth + 1);
			}
			continue;
		}

		if (strstr(propType.c_str(), "class")) {
			out << indent << "Prop: " << propName << " => 0x" << std::hex << propOffset << std::dec
				<< " | " << prop->GetDataTable()->GetNetTableName() << "\n";
		}
		else if (strstr(propType.c_str(), "[]")) {
			out << indent << "Prop: " << propName << " => 0x" << std::hex << propOffset << std::dec
				<< " | " << GetRealType(prop) << "[" << prop->GetNumberOfElements() << "]\n";
		}
		else {
			out << indent << "Prop: " << propName << " => 0x" << std::hex << propOffset << std::dec
				<< " | " << propType << "\n";
		}
	}
}

void DumpRecvTablesToFile()
{
	auto pClient = g_Memory.GetModuleAddress("client.dll");
	if (!pClient.m_uAddress)
	{
		printf("[recvdump] client.dll not found.\n");
		return;
	}

	auto c = g_Memory.Read<ClientClassEx*>(pClient.m_uAddress + 0x6084D8);
	if (!c)
	{
		printf("[recvdump] Client class head not found.\n");
		return;
	}

	std::ofstream out("recvtables_dump.txt");
	if (!out.is_open())
	{
		printf("[recvdump] Failed to open recvtables_dump.txt\n");
		return;
	}

	int guard = 0;
	while (c && guard++ < 4096) {
		auto networkName = c->GetNetworkName();
		auto recvTable = c->GetRecVTable();
		if (recvTable) {
			out << networkName << "\n";
			out << recvTable->GetNetTableName() << ":" << recvTable->GetPropCount() << "\n";
			DumpPropertiesToFile(recvTable, out, 1);
			out << "\n";
		}

		if (strstr(networkName.c_str(), "invalid")) {
			break;
		}
		c = c->GetNext();
	}

	out.close();
	printf("[recvdump] Wrote recvtables_dump.txt\n");
}

int main(int argc, char* argv[]) {
	bool serverMode = false;
	if (argc > 1 && strcmp(argv[1], "--server") == 0)
		serverMode = true;

	if (serverMode)
	{
		g_Memory.Initialize("srcds.exe");
		printf("[serverdump] Listing all modules in srcds.exe:\n");
		HMODULE hMods[1024];
		HANDLE hProcess = GetCurrentProcess();
		DWORD cbNeeded;
		if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
		{
			for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
			{
				char modName[MAX_PATH];
				GetModuleFileNameExA(hProcess, hMods[i], modName, MAX_PATH);
				printf("  [%d] %s\n", i, modName);
			}
		}
		const auto serverHead = serverdump::FindServerClassHead();
		serverdump::DumpAllSendTables(serverHead);
		serverdump::DumpFlatLists(serverHead);
		serverdump::DumpClassIds(serverHead);
	}
	else
	{
		g_Memory.Initialize("cstrike_win64.exe");
		DumpRecvTablesToFile();

		const auto serverHead = senddump::FindServerClassHead();
		senddump::DumpAllSendTables(serverHead);
		senddump::DumpFlatLists(serverHead);
		senddump::DumpEngineFlatLists(serverHead);
		senddump::DumpClassIds(serverHead);
	}

	std::cin.get();

	return 0;
}