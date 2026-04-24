#include <Windows.h>
#include <fstream>
#include <iomanip>
#include <vector>
#include "memory.h"
#include "ClientClassEx.h"

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

	constexpr std::uintptr_t kSendPropType = 0x10;
	constexpr std::uintptr_t kSendPropBits = 0x14;
	constexpr std::uintptr_t kSendPropLowValue = 0x18;
	constexpr std::uintptr_t kSendPropHighValue = 0x1C;
	constexpr std::uintptr_t kSendPropArrayProp = 0x18;
	constexpr std::uintptr_t kSendPropNumElements = 0x28;
	constexpr std::uintptr_t kSendPropExcludeDTName = 0x38;
	constexpr std::uintptr_t kSendPropName = 0x48;
	constexpr std::uintptr_t kSendPropFlags = 0x54;
	constexpr std::uintptr_t kSendPropDataTable = 0x68;
	constexpr std::uintptr_t kSendPropOffset = 0x70;
	constexpr std::size_t kSendPropStride = 0x80;
	constexpr int kSpropExclude = (1 << 6);
	constexpr int kSpropInsideArray = (1 << 8);
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
	else if(strstr(prop->GetArrayProp()->GetType().c_str(), "[]")) {
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
		} else if (!strstr(prop->GetName().c_str(), "baseclass")) {
			if(strstr(prop->GetType().c_str(),"class"))
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
	g_Memory.Initialize("cstrike_win64.exe");

	DumpRecvTablesToFile();

	const auto serverHead = senddump::FindServerClassHead();
	senddump::DumpAllSendTables(serverHead);

	std::cin.get();

	return 0;
}