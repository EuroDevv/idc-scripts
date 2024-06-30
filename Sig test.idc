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
	FindAddress("seed", "8D 83 ? ? ? ? 33 83 ? ? ? ? 8D 48 02 0F AF C8 8D 83 ? ? ? ? 33 0D ? ? ? ? ");
	FindAddress("angle", "8D 83 ? ? ? ? 33 83 ? ? ? ? 8D 48 02 0F AF C8 8D 83 ? ? ? ? 33 0D ? ? ? ? ");
	FindAddress("angle", "8D 83 ? ? ? ? 03 8B ? ? ? ? 41 B8 ? ? ? ? C5 E2 59 25 ? ? ? ? C5 DA 58 0D ? ? ? ?");
	FindAddress("CG_ClientModel_RuntimeData", "49 8d 8f ? ? ? ? 42 c6 84 3e");
	FindAddress("LUI_DataBinding_Interactions_GetLootItemFromScriptableIndex", "E8 ? ? ? ? 48 85 C0 74 20 48 8B 10 48 8B CE E8 ? ? ? ? B8 ? ? ? ? 48 8B 5C 24 ? 48 8B 74 24 ? 48 83 C4 20 5F C3 ");
	FindAddress("scriptable_id", "41 C7 84 84");
	FindAddress("ClientContext", "49 8b 84 f0 ? ? ? ? 48 69 ca");
	FindAddress("luaVM", "48 8b 0d ? ? ? ? ba ? ? ? ? 44 8b c2 e8 ? ? ? ? 85 c0 74 ? 48 8b 15 ? ? ? ? 48 8d 0d ? ? ? ? e8 ? ? ? ? 48 8b 0d");
	FindAddress("j_lua_remove", "E8 ? ? ? ? EB 11 41 B8 ? ? ? ? 48 8B D3 48 8B CE E8 ? ? ? ? ");
	FindAddress("lua_pushstring", "48 89 5C 24 ? 57 48 83 EC 20 48 8B FA 48 8B D9 48 85 D2 75 10 48 8B 41 28 49 C7 C0 ? ? ? ? 4C 89 00 EB 54 48 8B 49 10 48 8B 81 ? ? ? ? 48 39 81 ? ? ? ? 72 08 48 8B CB E8 ? ? ? ? 49 C7 C0 ? ? ? ? ");
	FindAddress("LuaShared_PCall", "e8 ? ? ? ? 85 c0 74 ? 48 8b 15 ? ? ? ? 48 8d 0d ? ? ? ? e8 ? ? ? ? 48 8b 0d");
	FindAddress("lua_getfield", "48 89 5c 24 ? 48 89 74 24 ? 57 48 83 ec ? 49 8b d8 48 8b f9 e8");
	FindAddress("lua_pushinteger", "48 8b 41 ? c5 f8 57 c0 c4 ? fb");
	FindAddress("lua_pushboolean", "48 8B 41 28 45 33 C0 85 D2 41 0F 95 C0 49 FF C0 49 C1 E0 2F 49 F7 D0 4C 89 00 48 83 41 ? ? 48 8B 41 28 48 3B 41 30 0F 83 ? ? ? ? C3 ");
	FindAddress("lua_registerFunction", "48 89 5C 24 ? 57 48 83 EC 20 49 8B D8 48 8B F9 45 33 C0 E8 ? ? ? ? 45 33 C0 48 8B D3 48 8B CF E8 ? ? ? ? BA ? ? ? ? 48 8B CF ");
	FindAddress("lua_gettop", "48 8B 41 28 48 2B 41 20 48 C1 F8 03 C3 ");
	FindAddress("lua_settop", "48 89 5C 24 ? 57 48 83 EC 20 48 63 FA 48 8B D9 85 D2 78 64 4C 8B 41 20 48 8B 49 28 49 8D 04 F8 48 3B C1 76 44 ");
	FindAddress("UI_SafeTranslateString", "40 ? 48 83 EC ? 80 39 ? 48 8B ? 75 ? 48 FF");
	FindAddress("BG_GetPlayerEyePosition", "e8 ? ? ? ? 4c 8d 44 24 ? 48 8b ce 48 8d 54 24 ? e8 ? ? ? ? 41 8d 45");
	FindAddress("CG_Handler", "e8 ? ? ? ? 8b 94 24 ? ? ? ? 4c 8b c0 48 8b 4c 24 ");
	FindAddress("CG_GetEntWeapon", "e8 ? ? ? ? 33 c9 48 8b f8 e8 ? ? ? ? 48 89 45");
	FindAddress("CG_GetWeaponDisplayName", "40 55 53 56 48 8d ac 24 ? ? ? ? 48 81 ec ? ? ? ? 48 8b 05 ? ? ? ? 48 33 c4 48 89 85 ? ? ? ? 66 83 39 ");
	FindAddress("MSG_PackSignedFloat", "E8 ? ? ? ? C5 FA 10 0D ? ? ? ? C5 FA 10 44 24 ? 41 B8 ? ? ? ? 89 45 A4 E8");
	FindAddress("MSG_UnPackSignedFloat", "C5 F8 28 D9 44 8B C9 BA ? ? ? ? C5 F8 57 C0 41 8D 48 FF C5 E8 57 D2 D3 E2 FF CA 8B C2 41 23 C1 41 D3 F9 C4 E1 EA 2A D0 8B C2 C4 E1 FA 2A C0");
}
