// Registrador de crash para as libs do HL: Invasion (client e server).
// Ao receber SIGSEGV/SIGABRT/etc., grava em invasion_crash.log (e no logcat, tag "INV_CRASH"):
//   - sinal e endereco da falha
//   - PC, LR (quem chamou), SP e FP do momento da falha
//   - cadeia de chamadas (frame pointer) a partir da falha
// Depois devolve o sinal ao handler original (Xash/Android).
// Os offsets (pc NNNNNNNN modulo) resolvem com: addr2line -f -C -e <lib com simbolos> 0xNNNNNNNN
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>
#include <ucontext.h>
#include <link.h>
#include <elf.h>
#ifdef __ANDROID__
#include <android/log.h>
#endif

namespace
{
	const int kSignals[] = { SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL };
	const int kNumSignals = sizeof(kSignals) / sizeof(kSignals[0]);
	const int kMaxChain = 24;

	struct sigaction g_old[32];
	char g_altstack[64 * 1024];

	int OpenLog()
	{
		char path[512];
		char pkg[128] = {0};
		int fd = open("/proc/self/cmdline", O_RDONLY);
		if (fd >= 0) { read(fd, pkg, sizeof(pkg) - 1); close(fd); }

		const char* fmt[] = {
			"./invasion_crash.log",
			"/sdcard/Android/data/%s/files/invasion_crash.log",
			"/sdcard/xash/invasion_crash.log",
			"/storage/emulated/0/xash/invasion_crash.log",
			"/sdcard/invasion_crash.log",
			"/data/local/tmp/invasion_crash.log",
		};
		for (unsigned i = 0; i < sizeof(fmt) / sizeof(fmt[0]); i++)
		{
			snprintf(path, sizeof(path), fmt[i], pkg);
			fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
			if (fd >= 0) return fd;
		}
		return -1;
	}

	void Emit(int fd, const char* line)
	{
		if (fd >= 0) { write(fd, line, strlen(line)); }
#ifdef __ANDROID__
		__android_log_print(ANDROID_LOG_ERROR, "INV_CRASH", "%s", line);
#endif
	}

	void EmitBuildId(int fd, void* addr);

	void Describe(int fd, const char* label, void* addr)
	{
		EmitBuildId(fd, addr);
		char line[768];
		Dl_info info;
		memset(&info, 0, sizeof(info));
		if (addr && dladdr(addr, &info) && info.dli_fname)
		{
			const char* mod = strrchr(info.dli_fname, '/');
			mod = mod ? mod + 1 : info.dli_fname;
			unsigned long modOff = (unsigned long)((char*)addr - (char*)info.dli_fbase);
			const char* sym = info.dli_sname;
			unsigned long symOff = info.dli_saddr ? (unsigned long)((char*)addr - (char*)info.dli_saddr) : 0;
			snprintf(line, sizeof(line), "  %-8s pc %08lx  %s  %s+%lu\n", label, modOff, mod,
				sym ? sym : "(sem simbolo)", symOff);
		}
		else
		{
			snprintf(line, sizeof(line), "  %-8s %p  (fora de qualquer lib / nulo)\n", label, addr);
		}
		Emit(fd, line);
	}


	// Build-id (hash unico do binario) da lib onde caiu: serve para conferir se os simbolos baixados sao do mesmo build.
	void EmitBuildId(int fd, void* addr)
	{
		Dl_info info;
		memset(&info, 0, sizeof(info));
		if (!addr || !dladdr(addr, &info) || !info.dli_fbase || !info.dli_fname) return;
		if (!strstr(info.dli_fname, "invasion") && !strstr(info.dli_fname, "client")) return; // so as libs do mod
		static const void* seen[4];
		for (int i = 0; i < 4; i++) if (seen[i] == info.dli_fbase) return; // uma vez por lib
		for (int i = 0; i < 4; i++) if (!seen[i]) { seen[i] = info.dli_fbase; break; }
		const char* base = (const char*)info.dli_fbase;
		if (memcmp(base, ELFMAG, SELFMAG) != 0) return;
#if defined(__LP64__)
		const Elf64_Ehdr* eh = (const Elf64_Ehdr*)base;
		const Elf64_Phdr* ph = (const Elf64_Phdr*)(base + eh->e_phoff);
#else
		const Elf32_Ehdr* eh = (const Elf32_Ehdr*)base;
		const Elf32_Phdr* ph = (const Elf32_Phdr*)(base + eh->e_phoff);
#endif
		for (int i = 0; i < eh->e_phnum; i++)
		{
			if (ph[i].p_type != PT_NOTE) continue;
			const char* p = base + ph[i].p_vaddr;
			const char* end = p + ph[i].p_memsz;
			while (p + 12 <= end)
			{
				unsigned namesz = ((const unsigned*)p)[0], descsz = ((const unsigned*)p)[1], type = ((const unsigned*)p)[2];
				const char* name = p + 12;
				const unsigned char* desc = (const unsigned char*)(name + ((namesz + 3) & ~3u));
				if (type == 3 /*NT_GNU_BUILD_ID*/ && namesz == 4 && memcmp(name, "GNU", 4) == 0 && descsz <= 64)
				{
					char line[240];
					snprintf(line, sizeof(line), "Build-id (%s): ", strrchr(info.dli_fname, '/') ? strrchr(info.dli_fname, '/') + 1 : info.dli_fname);
					size_t n = strlen(line);
					for (unsigned k = 0; k < descsz; k++) n += snprintf(line + n, sizeof(line) - n, "%02x", desc[k]);
					snprintf(line + n, sizeof(line) - n, "\n");
					Emit(fd, line);
					return;
				}
				p = (const char*)desc + ((descsz + 3) & ~3u);
			}
		}
	}

	void Handler(int sig, siginfo_t* si, void* ucv)
	{
		alarm(4); // se algo travar aqui dentro, o processo ainda morre

		if (!getenv("INV_CRASH_LOGGED"))
		{
			setenv("INV_CRASH_LOGGED", "1", 1);
			int fd = OpenLog();
			char line[256];

			snprintf(line, sizeof(line), "==== CRASH sinal %d (%s) code=%d addr=%p tempo=%ld ====\n",
				sig, strsignal(sig), si ? si->si_code : 0, si ? si->si_addr : 0, (long)time(NULL));
			Emit(fd, line);

			ucontext_t* uc = (ucontext_t*)ucv;
			uintptr_t pc = 0, lr = 0, sp = 0, fp = 0;
#if defined(__aarch64__)
			if (uc) { pc = uc->uc_mcontext.pc; lr = uc->uc_mcontext.regs[30]; sp = uc->uc_mcontext.sp; fp = uc->uc_mcontext.regs[29]; }
#elif defined(__arm__)
			if (uc)
			{
				pc = uc->uc_mcontext.arm_pc; lr = uc->uc_mcontext.arm_lr; sp = uc->uc_mcontext.arm_sp;
				fp = (uc->uc_mcontext.arm_cpsr & 0x20) ? uc->uc_mcontext.arm_r7 : uc->uc_mcontext.arm_fp; // Thumb usa r7
			}
#elif defined(__x86_64__)
			if (uc) { pc = uc->uc_mcontext.gregs[REG_RIP]; sp = uc->uc_mcontext.gregs[REG_RSP]; fp = uc->uc_mcontext.gregs[REG_RBP]; }
#endif
			snprintf(line, sizeof(line), "Registradores: pc=%p lr=%p sp=%p fp=%p\n", (void*)pc, (void*)lr, (void*)sp, (void*)fp);
			Emit(fd, line);

			Emit(fd, "Falha em:\n");
			Describe(fd, "PC", (void*)pc);
			Emit(fd, "Chamador (LR):\n");
			Describe(fd, "LR", (void*)lr);

			// Cadeia por frame pointer: [fp] = fp anterior, [fp+1 palavra] = endereco de retorno
			Emit(fd, "Cadeia (FP):\n");
			uintptr_t cur = fp;
			for (int i = 0; i < kMaxChain; i++)
			{
				if (!cur || (cur & (sizeof(uintptr_t) - 1)) || cur < sp || cur > sp + 256 * 1024) break;
				uintptr_t next = ((uintptr_t*)cur)[0];
				uintptr_t ret = ((uintptr_t*)cur)[1];
				if (!ret) break;
				char label[16];
				snprintf(label, sizeof(label), "#%02d", i);
				Describe(fd, label, (void*)ret);
				if (next <= cur) break;
				cur = next;
			}
			Emit(fd, "====\n");
			if (fd >= 0) close(fd);
		}

		// Devolve ao handler original e deixa o sinal acontecer de novo.
		if (sig > 0 && sig < 32)
			sigaction(sig, &g_old[sig], NULL);
	}

	__attribute__((constructor)) void InstallCrashHandler()
	{
		stack_t ss;
		ss.ss_sp = g_altstack;
		ss.ss_size = sizeof(g_altstack);
		ss.ss_flags = 0;
		sigaltstack(&ss, NULL);

		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_sigaction = Handler;
		sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
		sigemptyset(&sa.sa_mask);
		for (int i = 0; i < kNumSignals; i++)
			sigaction(kSignals[i], &sa, &g_old[kSignals[i]]);
	}
}
