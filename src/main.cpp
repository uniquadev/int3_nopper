// (c) 2011 uniquadev
// This code is licensed under MIT license

#include <cinttypes>
#include <binaryninjaapi.h>
#include <lowlevelilinstruction.h>
#include <thread>
#include <format>

using namespace BinaryNinja;

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
	int64_t patched = 0;

	void nopInt3(uint64_t ea)
	{
		view->Write(ea, "\x90", 1);
		view->SetCommentForAddress(ea, "int3");
		patched++;
	}

	uint64_t handleBlock(BasicBlock* block)
	{
		if (block->GetLength() < 2)
			return 0;

		auto llil = block->GetLowLevelILFunction();
		LowLevelILInstruction last_nonint3;
		LowLevelILInstruction last_inst;

		last_nonint3 = llil->GetInstruction(block->GetEnd()-2);
		last_inst = llil->GetInstruction(block->GetEnd()-1);

		if (last_inst.operation != LLIL_BP)
			return 0;

		uint8_t byte = 0;
		if (!view->Read(&byte, last_inst.address, 1))
			return 0;
		
		if (byte != 0xCC)
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
			LogWarn("Skipping %lld int3 instructions at %llx", patches, last_inst.address);
			return 0;
		}
		
		for (uint64_t i = 0; i < patches; i++)
			nopInt3(last_inst.address + i);
		
		return patches;
	}

	void run()
	{
		if (arch->GetName() != "x86_64")
		{
			LogError("This plugin only supports x86_64 architecture.");
			return;
		}

		const Ref<BackgroundTask> task = new BackgroundTask("Patching int3 instructions", true);
		const auto& fs = view->GetAnalysisFunctionList();
		const auto& fsLen = fs.size();

		view->SetAnalysisHold(true);
		int64_t fsCounter = 0;
		for (const auto& func : fs)
		{
			auto llil = func->GetLowLevelIL();
			if (!llil)
				continue;

			uint64_t fPatches = 0;
			for (auto& block : llil->GetBasicBlocks())
			{
				if (task->IsCancelled())
					return;
				fPatches += handleBlock(block);
			}
			if (fPatches > 0)
			{
				LogInfo("Patched %lld int3 in function %s.", fPatches, func->GetSymbol()->GetRawName().c_str());
				func->Reanalyze();
			}
			fsCounter++;
			task->SetProgressText(std::format("Patching int3 instructions {}/{}", fsCounter, fsLen));
		}
		view->SetAnalysisHold(false);
		LogInfo("Patched %lld int3 instructions.", patched);
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