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
	FindAddress("flags", "48 69 D1 ? ? ? ? 48 03 D0 48 8B C2 74 1B");
	FindAddress("flags", "40 53 48 83 EC 20 4C 8B 0D ? ? ? ? 41 0F B7 D8 4D 85 C9   ");
	FindAddress("pose", "4C 8D 83 ? ? ? ? 49 F7 D0 48 8D 8B ? ? ? ? 4C 33 83 ? ? ? ? 48 ");
	FindAddress("prevState", "4D 8D 48 74 41 8B D7 48 8D 4D E7 E8 ? ? ? ? 8B 56 0C 4C 8D 45 C7 48 8D 4D E7 E8 ? ? ? ?  ");
	FindAddress("size", "48 69 D1 ? ? ? ? 48 03 D0 48 8B C2 74 1B ");
	FindAddress("size", "40 53 48 83 EC 20 4C 8B 0D ? ? ? ? 41 0F B7 D8 4D 85 C9   ");
	FindAddress("m_frontEndScene", "74 20 49 6B D4 1C ");
	FindAddress("PerksArray", "E8 ? ? ? ? 85 C0 78 2F 8B C8 BA ? ? ? ? ");
	FindAddress("frameTime", "C5 FA 2A 87 ? ? ? ? C5 7A 59 15 ? ? ? ?");
	FindAddress("baseGunAngles", "C5 FA 10 8F ? ? ? ? 8B CE E8 ? ? ? ? 8B CE E8 ? ? ? ? ");
	FindAddress("sightedEnemyFools", "e8 ? ? ? ? 84 c0 74 ? 09 b4 9f");
	FindAddress("FOV", "C5 FA 11 ? ? ? ? ? E8 ? ? ? ? C5 FA 58 54 24 ? C5 FA 11 54 24");
	FindAddress("RefDef", "48 8D 93 ? ? ? ? 48 C7 83 ? ? ? ? ? ? ? ? 44 8B C6 8B CF 48 8B 5C 24 ? 48 8B 74 24 ? 48 83 C4 30 5F E9 ? ? ? ? ");
	FindAddress("equippedOffHand", "4c 8d 83 ? ? ? ? 8b ce e8 ? ? ? ? 8b ce");
	FindAddress("weaponSelect", "48 8d 93 ? ? ? ? 4c 8d 83 ? ? ? ? 8b ce");
}
