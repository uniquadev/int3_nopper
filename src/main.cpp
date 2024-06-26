// (c) 2023 uniquadev
// This code is licensed under MIT license

#include <cinttypes>
#include <binaryninjaapi.h>
#include <lowlevelilinstruction.h>
#include <thread>
#include <format>
#include <queue>

using namespace BinaryNinja;

auto logger = Logger("Int3Nopper");

class Int3Nopper {
public:
	Int3Nopper(BinaryView* view)
	{
		this->view = view;
		arch = view->GetDefaultArchitecture();
	}

	static void start(Ref<BinaryView> view)
	{
		std::thread([view]() {
			std::make_unique<Int3Nopper>(view)->run();
		}).detach();
	}
private:
	Ref<BinaryView> view;
	Ref<Architecture> arch;
	Ref<BackgroundTask> task;

	std::queue<Ref<Function>> functions;
	int64_t patched = 0;

	void nopInt3(uint64_t ea)
	{
		view->Write(ea, "\x90", 1);
		view->SetCommentForAddress(ea, "int3");
		patched++;
	}

	void nopInt3s(uint64_t ea, size_t count)
	{
		std::string nop(count, '\x90');
		view->Write(ea, nop.data(), count);
		view->SetCommentForAddress(ea, std::format("int3 ({})", count));
		patched += count;
	}

	size_t handleBlock(BasicBlock* block)
	{
		if (block->GetLength() < 2)
			return 0;

		auto llil = block->GetLowLevelILFunction();
		if (!llil)
			return 0;
			
		LowLevelILInstruction last_nonint3;
		LowLevelILInstruction last_inst;

		last_nonint3 = llil->GetInstruction(block->GetEnd()-2);
		last_inst = llil->GetInstruction(block->GetEnd()-1);

		if (last_inst.operation != LLIL_BP)
			return 0;
		
		uint8_t byte = 0;
		if (!view->Read(&byte, last_inst.address, 1) || byte != 0xCC)
			return 0;
		
		if (last_nonint3.operation == LLIL_CALL || last_nonint3.operation == LLIL_RET)
			return 0;

		uint64_t patches = 0;
		uint64_t ea = last_inst.address;
		do
		{
			patches++; ea++;
		} while (view->Read(&byte, ea, 1) && byte == 0xCC);

		if (patches > 10)
		{
			logger.LogDebug("Skipping %lld int3 instructions at %llx", patches, last_inst.address);
			return 0;
		}

		nopInt3s(last_inst.address, patches);
		return patches;
	}

	size_t handleFunction(Function* func)
	{
	
		auto llil = func->GetLowLevelIL();
		if (!llil)
			return 0;

		size_t patched = 0;
		for (auto& block : llil->GetBasicBlocks())
		{
			if (task->IsCancelled())
				return 0;
			patched += handleBlock(block);
		}
		if (patched > 0)
			func->Reanalyze(BNFunctionUpdateType::FullAutoFunctionUpdate);
		return patched;
	}

	void run()
	{
		if (arch->GetName() != "x86_64" && arch->GetName() != "x86")
		{
			logger.LogError("This plugin only supports x86_64 architecture.");
			return;
		}

		task = new BackgroundTask("Patching int3 instructions", true);
		
		for (const auto& func : view->GetAnalysisFunctionList())
			functions.push(func);

		
		auto start = std::chrono::high_resolution_clock::now();
		size_t patched = 0;
		while (!functions.empty())
		{
			if (task->IsCancelled())
				return;

			auto func = functions.front();
			auto fpatched = handleFunction(func);
			patched += fpatched;

			if (fpatched > 0)
			{
				functions.push(func); // requeue function for further analysis
				logger.LogInfo("Patched %lld int3 in function %s.", fpatched, func->GetSymbol()->GetRawName().c_str());
			}
			functions.pop();

			task->SetProgressText(std::format("Patching int3, {} functions left", functions.size()));
		}
		auto end = std::chrono::high_resolution_clock::now();
		auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - start).count();

		logger.LogInfo("Patched %lld int3 instructions, in %lld seconds.", patched, duration);
		task->Finish();
	}
};


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		PluginCommand::Register(
			"Patch int3 instructions",
			"Nops breakpoint instructions in order to allow analysis continuation.",
			Int3Nopper::start
		);
		return true;
	}
}