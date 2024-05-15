// (c) 2011 uniquadev
// This code is licensed under MIT license

#include <cinttypes>
#include <binaryninjaapi.h>
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
		if (block->GetLength() < 1)
			return 0;

		const auto end = block->GetEnd();
		auto ea = block->GetStart();
		
		uint64_t patches = 0;
		while (ea < end)
		{
			const auto len = view->GetInstructionLength(arch, ea);
			if (len == 0)
				return 0;

			if (len == 1)
			{
				uint8_t byte = 0;
				if (!view->Read(&byte, ea, 1))
					return 0;

				if (byte != 0xCC)
					goto NEXT_INST;
					
				do
				{
					nopInt3(ea);
					patches++;
					ea++;
				} while (view->Read(&byte, ea, 1) && byte == 0xCC);
			}
			else
			{
				NEXT_INST:
				ea += len;
			}
		}
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
			uint64_t fPatches = 0;
			for (auto& block : func->GetBasicBlocks())
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