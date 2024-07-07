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
	FindAddress("s_aab_get_pointer_origin", "48 ? ? 48 ? ? ? 01 10 00 00 0F 85 ? ? ? ? C1 E8 11 A8 01 0F 85");
	FindAddress("m_bgHandler", "49 81 C1 ? ? ? ? ? ? 00 00 00 ? ? ? E8 ? ? ? ? 85 C0");
	FindAddress("cls", "48 8D 0D ? ? ? ? C6 05 ? ? ? ? ? C7 05 ? ? ? ? ? ? ? ? E8");
	FindAddress("PhysicsQuery_LegacyMPCGWeaponSimTrace", "48 8D 44 24 ? 44 89 ? 24 38 C7 44 24 30 01 00 00 00 48 89 44 24 28 48 8D 05 ? ? ? ? 48 89 44 24 20 E8");
	FindAddress("CG_VehicleCam_SetClientViewAngles", "E8 ? ? ? ? ? ? ? 48 ? ? ? 4C ? ? 48 ? ? ? E8");
	FindAddress("swap_chain", "48 8B 0D ? ? ? ? 33 D2 E8 ? ? ? ? 48 C7 05 ? ? ? ? 00 00 00 00 48 83 C4 ? C3");
	FindAddress("command_queue", "48 8D 2D ? ? ? ? 48 89 44 24 ? 4C 8D 0D ? ? ? ? BA");
}
