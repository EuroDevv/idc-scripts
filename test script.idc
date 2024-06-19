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
	FindAddress("Pose", "48 ? ? 48 ? ? ? 01 10 00 00 0F 85 ? ? ? ? C1 E8 11 A8 01 0F 85");
	FindAddress("nextState", "45 84 C9 0F 85 ? ? ? ? F6");
	FindAddress("flags", "45 84 C9 0F 85 ? ? ? ? F6");
	FindAddress("size", "63 CE 48 ? ? ? ? ? ? B9");	
	FindAddress("s_aab_get_pointer_origin", "48 ? ? 48 ? ? ? 01 10 00 00 0F 85 ? ? ? ? C1 E8 11 A8 01 0F 85");	
	FindAddress("cls", "48 8D 0D ? ? ? ? C6 05 ? ? ? ? ? C7 05 ? ? ? ? ? ? ? ? E8");
	FindAddress("cmdNumber", "48 89 7C 24 10 ? 91");
	FindAddress("cmd_number_aab", "48 89 7C 24 10 ? 91");
	FindAddress("cmd_number_aab", "48 89 7C 24 10 ? 91");
}
