#include <idc/idc.idc>

static FindAddress(func, patrn) {
	auto value = 0;
	auto sig = FindBinary(get_imagebase(), SEARCH_DOWN, patrn);
	if(sig != -1) {
		auto insn_name = print_insn_mnem(sig);
		
		auto is_correct_side = 1;
		if((insn_name == "mov" || insn_name == "lea" || insn_name == "add") && decode_insn(sig).size > 6) {
			if(decode_insn(sig).Op1.addr > get_imagebase()) {
				is_correct_side = 1;
			}
			else {
				is_correct_side = 0;
			}
		}
		
		if(insn_name == "call" || insn_name == "jmp") {
			value = decode_insn(sig).Op0.addr;
			Message("Found %s at 0x%X\n", func, value);
			MakeName(value, func);
		}
		else if((insn_name == "mov" || insn_name == "lea" || insn_name == "add") && decode_insn(sig).size > 6 && is_correct_side == 1) {
			value = decode_insn(sig).Op1.addr;
			Message("Found %s at 0x%X\n", func, value);
			MakeName(value, func);
		}
		else {
			value = sig;
			Message("Found %s at 0x%X\n", func, value);
			MakeName(value, func);
		}
	}
	else {
		Message("%s needs updating!\n", func);
	}
}


static main(void) {
	FindAddress("nextstate", "E8 ? ? ? ? 44 0F B7 83 ? ? ? ? 4C 8D 4C 24 ? 0F BF 93 ? ? ? ? B8 ? ? ? ? ");
	FindAddress("flags", "40 53 48 83 EC 20 4C 8B 0D ? ? ? ? 41 0F B7 D8 4D 85 C9   ");
        FindAddress("flags", "48 69 D1 ? ? ? ? 48 03 D0 48 8B C2 74 1B");
	FindAddress("prevState", "4D 8D 88 ? ? ? ? 41 8B D7 48 8D 4D E7 E8 ? ? ? ? 8B 56 0C");
	FindAddress("size", "48 69 D1 ? ? ? ? 48 03 D0 48 8B C2 74 1B ");
	FindAddress("size", "40 53 48 83 EC 20 4C 8B 0D ? ? ? ? 41 0F B7 D8 4D 85 C9   ");
	FindAddress("sightedEnemyFools", "E8 ? ? ? ? 84 C0 74 08 41 09 B4 9F ? ? ? ?");
	FindAddress("FOV", "C5 FA 11 ? ? ? ? ? E8 ? ? ? ? C5 FA 58 54 24 ? C5 FA 11 54 24");
	FindAddress("predictedPlayerState", "48 8d 8a ? ? ? ? e8 ? ? ? ? c5 f0 57 c9 c5");
	FindAddress("predictedPlayerEntity", "C5 FA 11 7C 24 ? E8 ? ? ? ? C5 AA 58 8D ? ? ? ? ");
	FindAddress("kickAVel", "4C 8D A6 ? ? ? ? 45 32 FF");
	FindAddress("rawKickAngles", "8B 8E ? ? ? ? E8 ? ? ? ? 41 8B 7C 24 ?");
	FindAddress("kickAngles", "48 8D BE ? ? ? ? 8B 57 0C");
	FindAddress("shellshock", "85 C0 7E 10 ? ? ? ? ? ? ? ? ? 08 01 41 0F 45 C1 C3");
	FindAddress("ps_ptr", "e8 ? ? ? ? 48 8d 05 ? ? ? ? 8b d7 4a 8b 0c f0");
	FindAddress("cmdNumber", "8D 87 ? ? ? ? 33 87 ? ? ? ? 8D 58 02 0F AF D8 33 9F ? ? ? ? 3B F3 7E 17 41 B8 ? ? ? ? ");
	FindAddress("cmd_number_aab", "8D 87 ? ? ? ? 33 87 ? ? ? ? 8D 58 02 0F AF D8 33 9F ? ? ? ? 3B F3 7E 17 41 B8 ? ? ? ?");
	FindAddress("usercmd", "E8 ? ? ? ? 8D 43 80 3B F0 0F 8E ? ? ? ? 85 F6 0F 8E ? ? ? ? 48 81 C7 ? ? ? ? 83 E6 7F 41 B8");
}
