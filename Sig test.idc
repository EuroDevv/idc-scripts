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
	FindAddress("ClActiveClient", "E8 ? ? ? ? 8B CD E8 ? ? ? ? 4C 8B C3 48 8B D6 8B CD E8 ? ? ? ?");
	FindAddress("LegacyTrace", "E8 ? ? ? ? E8 ? ? ? ? C5 FA 10 5D ? C4 C1 78 2F DC");
	FindAddress("CG_GetPoseOrigin", "E8 ? ? ? ? B0 01 48 8B 74 24 ? 48 8B 5C 24 ? 48 8B 6C 24 ? 48 8B 7C 24 ? 48 83 C4 40");
	FindAddress("CL_SetViewAngle", "89 43 08 E8 ? ? ? ? C5 FA 10 97 ? ? ? ?");
	FindAddress("CG_View_GetFovDvarDefaultValue", "E8 ? ? ? ? 41 8B CC C5 F8 28 F0 E8 ? ? ? ? C5 F8 2E C6");
	FindAddress("CG_View_GetFovDvarValue", "E8 ? ? ? ? C5 FA 59 CE C5 F2 59 05 ? ? ? ? E8 ? ? ? ? C5 FA 59 0D");
	FindAddress("CG_SnapshotMP_GetNextSnap", "E8 ? ? ? ? 48 8B D0 8B CB E8 ? ? ? ? 48 8B 87 ? ? ? ? 8B 48 0C");
	FindAddress("CG_SnapshotMP_GetPrevSnap", "E8 ? ? ? ? 41 8B CD 48 89 44 24 ? 48 8B F8 E8 ? ? ? ? 48 85 C0");
	FindAddress("BG_GetBallisticInfo", "48 89 5c 24 ? 57 48 81 ec ? ? ? ? 48 8b 05 ? ? ? ? 48 33 c4 48 89 84 24 ? ? ? ? 48 8b f9 41 0f b6 c0");
	FindAddress("BG_Ballistics_TravelTimeForDistance", "48 89 5C 24 ? 55 56 57 48 81 EC ? ? ? ? C5 F8 29 B4 24 ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? C5 F8 28 F3 41 0F B6 F8 48 8B DA E8 ? ? ? ?");
	FindAddress("Dvar_GetFloatSafe", "E8 ? ? ? ? C5 FA 11 44 24 ? EB 06 C5 FA 10 44 24 ? C5 FA 5A C8 48 8B CF ");
	FindAddress("missile", "48 8D 05 ? ? ? ? C7 43 ? ? ? ? ? 48 89 03 48 8B C3 C6 43 0B 01 C6 43 1D 01 C7 43 ? ? ? ? ? 48 83 C4 20 5B C3");
	FindAddress("targetassist", "48 8d 05 ? ? ? ? c7 41 ? ? ? ? ? 48 89 01 41 b8 ? ? ? ? 48 83 c1 ? e8 ? ? ? ? 48 8b c3 48 83 c4 ? 5b");
	FindAddress("GPad_GetButton", "E8 ? ? ? ? C5 FA 59 CE BA ? ? ? ? 33 C9 C5 FA 2C F9 E8 ? ? ? ? ");
	FindAddress("GPad_isActive", "E8 ? ? ? ? 84 C0 74 06 3B F7 74 1B FF C7 FF C3");
	FindAddress("BG_GetThirdPersonCrosshairOffset", "48 89 5C 24 ? 57 48 83 EC 40 48 8B FA 48 8B D9 E8 ? ? ? ? 84 C0 75 0F");
	FindAddress("BG_IsThirdPersonMode", "E8 ?? ?? ?? ?? 48 8B 9C 24 ?? ?? ?? ?? 8B CD 84 C0");
	FindAddress("R_AddDObjToScene", "40 56 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? C5 F8 29 B4 24 ? ? ? ?");
	FindAddress("CG_GetViewFovBySpace", "48 89 5c 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8d 6c 24 ? 48 81 ec ? ? ? ? 48 8b 05 ? ? ? ? 48 33 c4 48 89 45 ? 48 63 fa");
	FindAddress("CG_PredictMP_PredictPlayerState", "40 53 48 83 ec ? 8b d9 e8 ? ? ? ? 8b cb e8 ? ? ? ? 8b cb e8 ? ? ? ? e8");
	FindAddress("BG_WeaponFireRecoil", "E8 ? ? ? ? E9 ? ? ? ? 48 8D 9E ? ? ? ? 41 8B CF ");
	FindAddress("CL_GetAgentName", "E8 ? ? ? ? 84 C0 75 18 4C 8D 05 ? ? ? ? BA ? ? ? ? 48 8D 8D ? ? ? ? E8");
	FindAddress("BG_CalculateFinalSpreadForWeapon", "E8 ? ? ? ? 44 0F B6 8C 24 ? ? ? ? 48 8D 8F ? ? ? ? 4C 8B C6 33 D2 C5 FA 11 84 24 ? ? ? ? E8 ? ? ? ?");
	FindAddress("BG_GetSpreadForWeapon", "40 55 53 41 54 41 55 48 8D 6C 24 ? 48 81 EC ? ? ? ? 83 B9 ? ? ? ? ? 4D 8B E1 4C 89 B4 24 ? ? ? ? 4D 8B E8 4C 8B F2 48 8B D9 75 22");
	FindAddress("SL_ConvertToString", "E8 ? ? ? ? 48 8B C8 B2 01 E8 ? ? ? ? 45 33 C9 88 5C 24 20 4D 8B C7 48 8B D0 48 8B CE E8 ? ? ? ?");
	FindAddress("BulletHitEvent_Internal", "48 89 5c 24 ? 48 89 6c 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 81 ec ? ? ? ? 41 8b f8");
	FindAddress("sys_milliseconds", "48 83 EC 28 80 3D ? ? ? ? ? 75 05 E8 ? ? ? ? E8 ? ? ? ? 48 8B C8");
	FindAddress("LUI_CoD_LuaCall_Exec", "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B D9 E8 ? ? ? ? 8B F8 8D 50 FF 83 FA 01 76 0F 48 8D 15 ? ? ? ? 48 8B CB");
	FindAddress("LUI_CoD_LuaCall_Exec_now", "E8 ? ? ? ? BA ? ? ? ? 49 8B CF E8 ? ? ? ? 4C 8D 05 ? ? ? ? BA ? ? ? ? 49 8B CF E8 ? ? ? ? BA ? ? ? ? 49 8B CF E8 ? ? ? ? 85 C0 75 43 8D 50 FE 49 8B CF E8 ? ? ? ? 33 D2 41 B8 ? ? ? ? 49 8B CF E8 ? ? ?");
	FindAddress("unknown_macaddress", "48 83 ec ? 80 3d ? ? ? ? ? 75 ? 48 8d 4c 24");
	FindAddress("CgHandler_GetScriptableDimensions", "48 89 5c 24 ? 48 89 74 24 ? 57 48 83 ec ? 48 8b 0d ? ? ? ? 49 8b f8 48 8b 1d");
	FindAddress("CG_ClientModel_GetModel", "e8 ? ? ? ? 33 f6 4c 8b f0 80 78");
	FindAddress("BG_IsRiotShield", "e8 ? ? ? ? 84 c0 74 ? e8 ? ? ? ? 44 8b 86");
	FindAddress("AimTargetMP_GetTargetBounds", "e8 ? ? ? ? 4c 8d 44 24 ? 48 8b d5 8b ce");
	FindAddress("BG_GetWeaponFlashTagname", "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 45 0F B6 F0 4C 8D 2D ? ? ? ? ");
	FindAddress("CalcMuzzlePoint", "E8 ? ? ? ? 45 33 C9 48 8D 95 ? ? ? ? 45 33 C0 48 8D 8D ? ? ? ? E8 ? ? ? ? C5 F8 57 C0 48 8D 8D ? ? ? ? C5 FA 11 85 ? ? ? ? E8 ? ? ? ? ");
	FindAddress("Slide_EndCheck", "E8 ? ? ? ? 85 C0 74 1D 44 8B C0 48 8B D6 48 8B CB 48 8B 5C 24 ? 48 8B 74 24 ? 48 83 C4 30 5F E9 ? ? ? ?");
	FindAddress("Slide_Start", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 70 C5 F8 29 74 24 ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 ? 48 8B 01 41 8B E8");
	FindAddress("CG_ViewMP_DrawActiveFrame", "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? B8 ? ? ? ? E8 ? ? ? ? 48 2B E0 C5 F8 29 BC 24 ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ?");
	FindAddress("packet_test", "e8 ? ? ? ? 84 c0 74 ? 41 b4 ? 40 84 ed");
	FindAddress("CgTrajectory_CgTrajectory", "e8 ? ? ? ? 8b 57 ? 4c 8d 44 24 ? 48 8d 4c 24");
	FindAddress("BgTrajectory_EvaluatePosTrajectory", "e8 ? ? ? ? 8b 57 ? 4c 8d 44 24 ? 48 8d 4c 24");
	FindAddress("BgTrajectory_LegacyEvaluateTrajectory", "48 83 EC 48 45 33 C9 48 8D 05 ? ? ? ? 44 89 4C 24 ? 4C 89 4C 24 ? 4D 8B C8 44 8B C2 48 89 44 24 ? 48 8B D1 48 8D 4C 24 ? E8 ? ? ? ?");
	FindAddress("CL_PlayerData_SetCustomClanTag", "40 53 41 54 b8");
	FindAddress("unknow_func", "4C 8B D1 48 8D 81 ? ? ? ? 41 B9 ? ? ? ? 48 8D 80 ? ? ? ? C5 F8 10 02 48 8D 92 ? ? ? ? C5 F8 11 40 ?");
	FindAddress("CG_EntityMP_CalcLerpPositions", "E8 ? ? ? ? 48 8B 06 44 8D 43 E3 45 33 C9 48 C7 44 24 ? ? ? ? ? 48 8B D7 48 8B CE FF 50 28 48 8B 5C 24 ?");
	FindAddress("CG_ScoreboardMP_GetClientScore", "E8 ? ? ? ? 4C 8B C8 45 8B C5 48 8B D6 48 8B CD E8 ? ? ? ?");
	FindAddress("bdAntiCheat_reportExtendedAuthInfo", "E8 ? ? ? ? 4C 8B 7C 24 ? 49 8D BC 24");
	FindAddress("hwidprofileshit", "E8 ? ? ? ? 48 89 03 48 8B 0B B0 01 48 89 0F EB 02 32 C0 ");
	FindAddress("Live_GetXuid", "40 53 48 83 EC 20 48 8B D9 8B CA E8 ? ? ? ? 48 8B 90 ? ? ?");
	FindAddress("DWServicesAccess_GetInstance", "E8 ? ? ? ? 8B D3 48 8B C8 E8 ? ? ? ? 48 8B C8 48 8B D8 E8 ? ? ? ? 84 C0 74 3E");
	FindAddress("DWServicesAccess_GetLogin", "E8 ? ? ? ? 48 8B C8 48 8B D8 E8 ? ? ? ? 84 C0 74 3E 48 8B CB E8 ? ? ? ?");
	FindAddress("Com_DDL_CreateContext", "E8 ? ? ? ? 48 8B D3 48 8D 4D 90 E8 ? ? ? ? C5 F9 EF C0");
	FindAddress("Com_DDL_LoadAsset", "E8 ? ? ? ? 4C 8D 4D D0 4C 89 7C 24");
	FindAddress("CL_PlayerData_GetDDLBuffer", "E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? 4C 8B C7 48 8D 8C 24 ? ? ? ?");
	FindAddress("DDL_GetRootState", "33 C0 C7 41 ? ? ? ? ? 48 89 41 10 48 85 D2 89 41 04 0F 95 C0 48 89 51 18 88 01 48 8B");
	FindAddress("DDL_MoveToPath", "E8 ? ? ? ? 84 C0 74 35 48 8D 4C 24 ?");
	FindAddress("DDL_GetType", "E8 ? ? ? ? 83 F8 02 75 26 48 8D 54 24 ?");
	FindAddress("DDL_SetInt", "4C 8B C9 48 85 C9 74 3B ");
	FindAddress("DDL_SetEnum", "48 89 5C 24 ? 57 48 83 EC 20 48 8B FA 48 8B D9 33 D2 49 8B C8 E8 ? ? ? ? 4C 8B 43 10");
	FindAddress("DDL_SetString", "E9 ? ? ? ? 4C 8B C7 48 8B D6 48 8B CB 48 8B 5C 24 ? 48 8B 74 24 ? 48 83 C4 20 5F E9 ? ? ? ? 48 8B 5C 24 ? 32 C0 48 8B 74 24 ? 48 83 C4 20 5F C3");
	FindAddress("Com_ParseNavStrings", "48 83 EC 28 45 33 D2 41 C7 01 00 00 00 00");
	FindAddress("CgWeaponSystem__ms_weaponSystemArray", "48 8B 0D ? ? ? ? 0F BF 90 ? ? ? ? 48 8D 85 ? ? ? ? 48 89 44 24 ? E8 ? ? ? ? ");
	FindAddress("CgVehicleSystem__ms_vehicleSystemArray", "48 8B 0D ? ? ? ? 48 89 5C 24 ? 48 89 7C 24 ? E8 ? ? ? ? 8B 7C 24 30 48 8B C8 48 8B D8 E8 ? ? ? ? ");
	FindAddress("networkadapterMacptr", "0F B6 05 ? ? ? ? 88 44 24 28 0F B6 05 ? ? ? ? 88 44 24 29 0F B6 05 ? ? ? ? 88 44 24 2A 0F B6 05 ? ? ? ? 88 44 24 2B 0F B6 05 ? ? ? ? 88 44 24 2C 0F B6 05 ? ? ? ?");
	FindAddress("swapchain", "48 8B 0D ? ? ? ? 33 D2 E8 ? ? ? ? 48 C7 05 ? ? ? ? 00 00 00 00 48 83 C4 ? C3");
	FindAddress("commandqueue", "8b c1 48 8d 0d ? ? ? ? 48 6b c0 78 48 03 c1 c3");
	FindAddress("Weaponmap", "48 8b 0d ? ? ? ? 48 85 c9 74 ? 48 8d 05 ? ? ? ? 48 89 01 e8 ? ? ? ? 48 c7 05");
	FindAddress("clientinfo", "4c 8d 0d ? ? ? ? 8b d7 4d 8b 0c c9");
	FindAddress("DVARBOOL_cl_packetdup", "0F 84 ? ? ? ? 41 8B BC 24 ? ? ? ? 85 FF 7E 62");
	FindAddress("trampoline", "FF 23");
}
