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
	FindAddress("pose", "48 ? ? 48 ? ? ? 01 10 00 00 0F 85 ? ? ? ? C1 E8 11 A8 01 0F 85");
	FindAddress("nextState", "45 84 C9 0F 85 ? ? ? ? F6");
	FindAddress("flags", "45 84 C9 0F 85 ? ? ? ? F6");
	FindAddress("size", "63 CE 48 ? ? ? ? ? ? B9");	
	FindAddress("s_aab_get_pointer_origin", "48 ? ? 48 ? ? ? 01 10 00 00 0F 85 ? ? ? ? C1 E8 11 A8 01 0F 85");	
	FindAddress("cls", "48 8D 0D ? ? ? ? C6 05 ? ? ? ? ? C7 05 ? ? ? ? ? ? ? ? E8");
	FindAddress("cmdNumber", "48 89 7C 24 10 ? 91");
	FindAddress("cmd_number_aab", "48 89 7C 24 10 ? 91");
	FindAddress("cmds", "3B F0 0F 8E ? 00 00 00 85 F6 0F 8E ? 00 00 00");
	FindAddress("CL_Input_ClearAutoForwardFlag", "83 F9 81 7D 03");
	FindAddress("StringTable_GetAsset", "E8 ? ? ? ? 48 8B 8C 24 ? ? ? ? E8 ? ? ? ? 44 ? ? 85 C0 0F 84");
	FindAddress("StringTable_GetColumnValueForRow", "E8 ? ? ? ? ? ? 31 75 ? 80 ? ? 08");
	FindAddress("CL_PlayerData_SetClanTag", "84 C0 74 0E 48 8D 15 ? ? ? ? 8B CF E8 ? ? ? ? 48 8B 5C 24 ? 48 83 C4");
	FindAddress("BG_GetWeaponFireType", "75 15 40 0F B6 D6 48 8B ? E8 ? ? ? ? 83 F8 05 0F 84");
	FindAddress("BG_UsrCmdUnpackAngle", "48 83 EC 28 ? ? ? ? ? ? ? ? 41 B8 14 00 00 00 E8");
	FindAddress("BG_GetPlayerEyePosition", "48 81 C1 ? ? 00 00 45 8B F1 45 89 3C 24 49 8B F0");
	FindAddress("BG_UsrCmdPackAngle", "66 C1 E0 05 66 0B C7");
	FindAddress("BG_UsrCmdUnpackAngle", "48 83 EC 28 ? ? ? ? ? ? ? ? 41 B8 14 00 00 00 E8");
	FindAddress("BG_GetPlayerEyePosition", "48 81 C1 ? ? 00 00 45 8B F1 45 89 3C 24 49 8B F0");
	FindAddress("BG_GetEntityWorldTagPosition", "48 69 D1 ? 01 00 00 48 03 D0 EB 02 33 D2 4D ? ? 45 ? ? 49 ? ? 48 ? ? ? ? 00 00");
	FindAddress("CG_VehicleCam_SetClientViewAngles", "E8 ? ? ? ? ? ? ? 48 ? ? ? 4C ? ? 48 ? ? ? E8");
	FindAddress("UI_SafeTranslateString", "40 53 48 83 EC ? 80 39 1F 48 8B D9");
	FindAddress("GPad_GetButton", "BA 01 00 00 20 ? ? ? E8");
	FindAddress("GScr_EndLobby", "B9 AD 0C 00 00 E8");
	FindAddress("refdef", "33 0D ? ? ? ? 89 8D ? ? ? ? 48 8D 0D ? ? ? ? 33 0D");
	FindAddress("DVARBOOL_cl_packetdup", "E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? ? ? ? ? ? 04 00 0F 8E");
	FindAddress("ms_cgameStaticsArray", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 63 F9 48 8D 35 ? ? ? ? 33 DB 48 8B 34 FE 90");
	FindAddress("aaGlobArray", "48 03 3D ? ? ? ? 48 8B CF E8 ? ? ? ? 48 8D 4C 24 ? 48 8D 9F ? ? ? ? E8");
	FindAddress("bg_weaponCompleteDefs", "E8 ? ? ? ? 0F B7 4C 24 78 8B F8 48 8D");
	FindAddress("g_cgPlayerTraceInfo", "48 63 C1 48 69 C8 60 03 00 00 48 8D ? ? ? ? ? 48 03 C8 E9");
	FindAddress("CgWeaponMap__ms_instance", "48 8D 05 ? ? ? ? 48 63 49 30");
	FindAddress("LUI_luaVM", "8B D9 E8 ? ? ? ? E8 ? ? ? ? 4C 8B 05 ? ? ? ? 48 8D 15");
	FindAddress("swap_chain", "48 8B 0D ? ? ? ? 33 D2 E8 ? ? ? ? 48 C7 05 ? ? ? ? 00 00 00 00 48 83 C4 ? C3");
	FindAddress("kickAngles", "49 8D 90 ? ? ? ? 8B 42 10");
	FindAddress("R_AddCmdDrawText", "44 89 74 24 ? E8 ? ? ? ? 48 8B 4D");
	FindAddress("Lua_VM", "4C 8B 05 ? ? ? ? 48 8D 14 5B");
}
