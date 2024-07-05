uintptr_t decrypt_client_info(const Driver& driver)
{
        const uint64_t mb = driver.base_addr;
        uint64_t rax = mb, rbx = mb, rcx = mb, rdx = mb, rdi = mb, rsi = mb, r8 = mb, r9 = mb, r10 = mb, r11 = mb, r12 = mb, r13 = mb, r14 = mb, r15 = mb;
        ;
        if(!rdx)
                return rdx;
        //Failed to find peb. (mayabe not needed)
        return rdx;
}
//ClientBase pattern scan failed.
uintptr_t decrypt_bone_base(const Driver& driver)
{
        const uint64_t mb = driver.base_addr;
        uint64_t rax = mb, rbx = mb, rcx = mb, rdx = mb, rdi = mb, rsi = mb, r8 = mb, r9 = mb, r10 = mb, r11 = mb, r12 = mb, r13 = mb, r14 = mb, r15 = mb;
        r8 = driver.Read<uintptr_t>(driver.base_addr + 0x1389A788);
        if(!r8)
                return r8;
        rbx= ~driver.target_peb;                //mov rbx, gs:[rax]
        rax = rbx;              //mov rax, rbx
        rax >>= 0xC;            //shr rax, 0x0C
        rax &= 0xF;
        switch(rax) {
        case 0:
        {
                //failed to translate: pop rbx
                r10 = driver.Read<uintptr_t>(driver.base_addr + 0x7AFB274);             //mov r10, [0x00000000052D7C01]
                rax = r8;               //mov rax, r8
                rax >>= 0xD;            //shr rax, 0x0D
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x1A;           //shr rax, 0x1A
                r8 ^= rax;              //xor r8, rax
                rax = driver.base_addr + 0x68CAC119;            //lea rax, [0x0000000066488850]
                rcx = rbx;              //mov rcx, rbx
                rcx = ~rcx;             //not rcx
                rcx += rax;             //add rcx, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x34;           //shr rax, 0x34
                rcx ^= rax;             //xor rcx, rax
                rax = driver.base_addr;                 //lea rax, [0xFFFFFFFFFD7DC71D]
                r8 ^= rcx;              //xor r8, rcx
                r8 -= rax;              //sub r8, rax
                rax = 0x6C585C91A1F593A9;               //mov rax, 0x6C585C91A1F593A9
                r8 *= rax;              //imul r8, rax
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r10;             //xor rax, r10
                rax = _byteswap_uint64(rax);            //bswap rax
                r8 *= driver.Read<uintptr_t>(rax + 0x9);                //imul r8, [rax+0x09]
                rax = r8;               //mov rax, r8
                rax >>= 0x1C;           //shr rax, 0x1C
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x38;           //shr rax, 0x38
                r8 ^= rax;              //xor r8, rax
                rax = 0x7ED5A485EA835715;               //mov rax, 0x7ED5A485EA835715
                r8 += rax;              //add r8, rax
                rax = 0x382D7A6EC038F6A5;               //mov rax, 0x382D7A6EC038F6A5
                r8 *= rax;              //imul r8, rax
                return r8;
        }
        case 1:
        {
                //failed to translate: pop rbx
                r9 = driver.Read<uintptr_t>(driver.base_addr + 0x7AFB274);              //mov r9, [0x00000000052D76D4]
                rax = driver.base_addr + 0xB880;                //lea rax, [0xFFFFFFFFFD7E78BA]
                rax = ~rax;             //not rax
                rax += rbx;             //add rax, rbx
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x23;           //shr rax, 0x23
                r8 ^= rax;              //xor r8, rax
                rax = 0x60348022A61DC036;               //mov rax, 0x60348022A61DC036
                r8 ^= rax;              //xor r8, rax
                rax = 0x2B0C1D1A3CD53DF5;               //mov rax, 0x2B0C1D1A3CD53DF5
                r8 -= rax;              //sub r8, rax
                r8 ^= rbx;              //xor r8, rbx
                rax = r8;               //mov rax, r8
                rax >>= 0x23;           //shr rax, 0x23
                r8 ^= rax;              //xor r8, rax
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r9;              //xor rax, r9
                rax = _byteswap_uint64(rax);            //bswap rax
                r8 *= driver.Read<uintptr_t>(rax + 0x9);                //imul r8, [rax+0x09]
                rax = 0xA89F2BB9CB4BEEF7;               //mov rax, 0xA89F2BB9CB4BEEF7
                r8 *= rax;              //imul r8, rax
                return r8;
        }
        case 2:
        {
                r9 = driver.Read<uintptr_t>(driver.base_addr + 0x7AFB274);              //mov r9, [0x00000000052D70C7]
                rax = driver.base_addr;                 //lea rax, [0xFFFFFFFFFD7DBC01]
                rax += 0x7EE61024;              //add rax, 0x7EE61024
                rax += rbx;             //add rax, rbx
                r8 ^= rax;              //xor r8, rax
                rax = rbx;              //mov rax, rbx
                uintptr_t RSP_0xFFFFFFFFFFFFFF98;
                RSP_0xFFFFFFFFFFFFFF98 = driver.base_addr + 0x4A71DD4B;                 //lea rax, [0x0000000047EF9C0A] : RBP+0xFFFFFFFFFFFFFF98
                rax *= RSP_0xFFFFFFFFFFFFFF98;          //imul rax, [rbp-0x68]
                r8 += rax;              //add r8, rax
                rax = driver.base_addr;                 //lea rax, [0xFFFFFFFFFD7DB9EE]
                r8 -= rax;              //sub r8, rax
                rax = 0xBBC3524940DB19BF;               //mov rax, 0xBBC3524940DB19BF
                r8 *= rax;              //imul r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x5;            //shr rax, 0x05
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0xA;            //shr rax, 0x0A
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x14;           //shr rax, 0x14
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x28;           //shr rax, 0x28
                r8 ^= rax;              //xor r8, rax
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r9;              //xor rax, r9
                rax = _byteswap_uint64(rax);            //bswap rax
                rax = driver.Read<uintptr_t>(rax + 0x9);                //mov rax, [rax+0x09]
                uintptr_t RSP_0x70;
                RSP_0x70 = 0xF2601375988D218B;          //mov rax, 0xF2601375988D218B : RSP+0x70
                rax *= RSP_0x70;                //imul rax, [rsp+0x70]
                r8 *= rax;              //imul r8, rax
                return r8;
        }
        case 3:
        {
                rcx = driver.base_addr + 0x630D4DA5;            //lea rcx, [0x00000000608B05FF]
                r10 = driver.Read<uintptr_t>(driver.base_addr + 0x7AFB274);             //mov r10, [0x00000000052D6A96]
                r8 += rbx;              //add r8, rbx
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r10;             //xor rax, r10
                rax = _byteswap_uint64(rax);            //bswap rax
                r8 *= driver.Read<uintptr_t>(rax + 0x9);                //imul r8, [rax+0x09]
                rax = driver.base_addr;                 //lea rax, [0xFFFFFFFFFD7DB43F]
                r8 ^= rax;              //xor r8, rax
                rax = 0xB1363DEF950ACEB3;               //mov rax, 0xB1363DEF950ACEB3
                r8 *= rax;              //imul r8, rax
                rax = 0x1CED73D774500EA1;               //mov rax, 0x1CED73D774500EA1
                r8 -= rbx;              //sub r8, rbx
                r8 -= rax;              //sub r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x12;           //shr rax, 0x12
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x24;           //shr rax, 0x24
                r8 ^= rax;              //xor r8, rax
                r8 ^= rbx;              //xor r8, rbx
                r8 ^= rcx;              //xor r8, rcx
                return r8;
        }
        case 4:
        {
                r10 = driver.Read<uintptr_t>(driver.base_addr + 0x7AFB274);             //mov r10, [0x00000000052D6633]
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r10;             //xor rax, r10
                rax = _byteswap_uint64(rax);            //bswap rax
                r8 *= driver.Read<uintptr_t>(rax + 0x9);                //imul r8, [rax+0x09]
                rax = 0x8B50241C36A24A05;               //mov rax, 0x8B50241C36A24A05
                r8 *= rax;              //imul r8, rax
                rax = 0xD3CF4E7A41BB1731;               //mov rax, 0xD3CF4E7A41BB1731
                r8 *= rax;              //imul r8, rax
                rax = 0xE818DCD9647EE109;               //mov rax, 0xE818DCD9647EE109
                r8 *= rax;              //imul r8, rax
                rax = rbx;              //mov rax, rbx
                uintptr_t RSP_0xFFFFFFFFFFFFFF80;
                RSP_0xFFFFFFFFFFFFFF80 = driver.base_addr + 0x4698;             //lea rax, [0xFFFFFFFFFD7DFA1E] : RBP+0xFFFFFFFFFFFFFF80
                rax *= RSP_0xFFFFFFFFFFFFFF80;          //imul rax, [rbp-0x80]
                r8 += rax;              //add r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x24;           //shr rax, 0x24
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x1D;           //shr rax, 0x1D
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x3A;           //shr rax, 0x3A
                r8 ^= rax;              //xor r8, rax
                rax = rbx;              //mov rax, rbx
                rax = ~rax;             //not rax
                rax -= driver.base_addr;                //sub rax, [rbp-0x30] -- didn't find trace -> use base
                rax += 0xFFFFFFFFFFFFEBB3;              //add rax, 0xFFFFFFFFFFFFEBB3
                r8 += rax;              //add r8, rax
                return r8;
        }
        case 5:
        {
                r10 = driver.Read<uintptr_t>(driver.base_addr + 0x7AFB274);             //mov r10, [0x00000000052D60EB]
                rax = 0x92E2C216C8D3D92F;               //mov rax, 0x92E2C216C8D3D92F
                r8 *= rax;              //imul r8, rax
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r10;             //xor rax, r10
                rax = _byteswap_uint64(rax);            //bswap rax
                r8 *= driver.Read<uintptr_t>(rax + 0x9);                //imul r8, [rax+0x09]
                rax = 0x568132F8392378D8;               //mov rax, 0x568132F8392378D8
                r8 ^= rax;              //xor r8, rax
                rax = driver.base_addr;                 //lea rax, [0xFFFFFFFFFD7DAC1C]
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x11;           //shr rax, 0x11
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x22;           //shr rax, 0x22
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x15;           //shr rax, 0x15
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x2A;           //shr rax, 0x2A
                rax ^= rbx;             //xor rax, rbx
                r8 ^= rax;              //xor r8, rax
                rax = driver.base_addr + 0x439C1A18;            //lea rax, [0x000000004119C412]
                r8 ^= rax;              //xor r8, rax
                rax = rbx;              //mov rax, rbx
                uintptr_t RSP_0xFFFFFFFFFFFFFFD0;
                RSP_0xFFFFFFFFFFFFFFD0 = driver.base_addr + 0x2493;             //lea rax, [0xFFFFFFFFFD7DD303] : RBP+0xFFFFFFFFFFFFFFD0
                rax *= RSP_0xFFFFFFFFFFFFFFD0;          //imul rax, [rbp-0x30]
                r8 ^= rax;              //xor r8, rax
                return r8;
        }
        case 6:
        {
                rbx = rbx + 0x0;                //lea rbx, [rbx]
                r10 = driver.Read<uintptr_t>(driver.base_addr + 0x7AFB274);             //mov r10, [0x00000000052D5C1B]
                rax = 0x52B012021AA93B51;               //mov rax, 0x52B012021AA93B51
                r8 *= rax;              //imul r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0xA;            //shr rax, 0x0A
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x14;           //shr rax, 0x14
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x28;           //shr rax, 0x28
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0xC;            //shr rax, 0x0C
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x18;           //shr rax, 0x18
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x30;           //shr rax, 0x30
                r8 ^= rax;              //xor r8, rax
                rax = driver.base_addr + 0x1A7C8877;            //lea rax, [0x0000000017FA2F3C]
                rax = ~rax;             //not rax
                rax *= rbx;             //imul rax, rbx
                r8 ^= rax;              //xor r8, rax
                rcx = r8;               //mov rcx, r8
                rcx >>= 0x27;           //shr rcx, 0x27
                rcx ^= r8;              //xor rcx, r8
                rax = rbx;              //mov rax, rbx
                r8 = driver.base_addr + 0x21556B1B;             //lea r8, [0x000000001ED311A8]
                rax = ~rax;             //not rax
                r8 *= rax;              //imul r8, rax
                r8 += rcx;              //add r8, rcx
                r8 -= driver.base_addr;                 //sub r8, [rbp-0x30] -- didn't find trace -> use base
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r10;             //xor rax, r10
                rax = _byteswap_uint64(rax);            //bswap rax
                r8 *= driver.Read<uintptr_t>(rax + 0x9);                //imul r8, [rax+0x09]
                return r8;
        }
        case 7:
        {
                r11 = driver.Read<uintptr_t>(driver.base_addr + 0x7AFB274);             //mov r11, [0x00000000052D5647]
                rax = r8;               //mov rax, r8
                rax >>= 0x1E;           //shr rax, 0x1E
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x3C;           //shr rax, 0x3C
                r8 ^= rax;              //xor r8, rax
                rcx = rbx;              //mov rcx, rbx
                rcx = ~rcx;             //not rcx
                rax = driver.base_addr + 0x7549;                //lea rax, [0xFFFFFFFFFD7E15CB]
                r8 += rax;              //add r8, rax
                r8 += rcx;              //add r8, rcx
                rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
                rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
                rax = driver.base_addr + 0x292BE944;            //lea rax, [0x0000000026A98BDA]
                rax = ~rax;             //not rax
                rdx ^= r11;             //xor rdx, r11
                rax ^= rbx;             //xor rax, rbx
                rcx = rbx;              //mov rcx, rbx
                rcx -= rax;             //sub rcx, rax
                rax = 0xCADA7FD4FBD8611B;               //mov rax, 0xCADA7FD4FBD8611B
                r8 += rcx;              //add r8, rcx
                r8 *= rax;              //imul r8, rax
                rdx = _byteswap_uint64(rdx);            //bswap rdx
                rax = 0x2756CBEE7092BD18;               //mov rax, 0x2756CBEE7092BD18
                r8 += rax;              //add r8, rax
                rax = 0x55CC081ECF330B5D;               //mov rax, 0x55CC081ECF330B5D
                r8 *= driver.Read<uintptr_t>(rdx + 0x9);                //imul r8, [rdx+0x09]
                r8 ^= rax;              //xor r8, rax
                return r8;
        }
        case 8:
        {
                r9 = driver.Read<uintptr_t>(driver.base_addr + 0x7AFB274);              //mov r9, [0x00000000052D51A5]
                rax = r8;               //mov rax, r8
                rax >>= 0x4;            //shr rax, 0x04
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x8;            //shr rax, 0x08
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x10;           //shr rax, 0x10
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x20;           //shr rax, 0x20
                r8 ^= rax;              //xor r8, rax
                rax = 0xEC5E79E7E13C9497;               //mov rax, 0xEC5E79E7E13C9497
                r8 *= rax;              //imul r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x26;           //shr rax, 0x26
                r8 ^= rax;              //xor r8, rax
                rax = rbx;              //mov rax, rbx
                rax = ~rax;             //not rax
                uintptr_t RSP_0x70;
                RSP_0x70 = driver.base_addr + 0xBF4E;           //lea rax, [0xFFFFFFFFFD7E5EDE] : RSP+0x70
                rax += RSP_0x70;                //add rax, [rsp+0x70]
                r8 ^= rax;              //xor r8, rax
                r8 -= rbx;              //sub r8, rbx
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r9;              //xor rax, r9
                rax = _byteswap_uint64(rax);            //bswap rax
                r8 *= driver.Read<uintptr_t>(rax + 0x9);                //imul r8, [rax+0x09]
                rax = rbx;              //mov rax, rbx
                rax -= driver.base_addr;                //sub rax, [rbp-0x30] -- didn't find trace -> use base
                rax += 0xFFFFFFFFFFFF949D;              //add rax, 0xFFFFFFFFFFFF949D
                r8 += rax;              //add r8, rax
                r8 ^= rbx;              //xor r8, rbx
                return r8;
        }
        case 9:
        {
                r11 = driver.base_addr + 0x1D3519CF;            //lea r11, [0x000000001AB2B49E]
                r9 = driver.Read<uintptr_t>(driver.base_addr + 0x7AFB274);              //mov r9, [0x00000000052D4D08]
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r9;              //xor rax, r9
                rax = _byteswap_uint64(rax);            //bswap rax
                r8 *= driver.Read<uintptr_t>(rax + 0x9);                //imul r8, [rax+0x09]
                rax = driver.base_addr;                 //lea rax, [0xFFFFFFFFFD7D976D]
                r8 -= rax;              //sub r8, rax
                rax = 0xD776D892EDD3584E;               //mov rax, 0xD776D892EDD3584E
                r8 ^= rax;              //xor r8, rax
                uintptr_t RSP_0x70;
                RSP_0x70 = 0xF54E2846497C5D19;          //mov rax, 0xF54E2846497C5D19 : RSP+0x70
                r8 *= RSP_0x70;                 //imul r8, [rsp+0x70]
                rax = rbx;              //mov rax, rbx
                rax = ~rax;             //not rax
                rax ^= r11;             //xor rax, r11
                rax += rbx;             //add rax, rbx
                r8 += rax;              //add r8, rax
                rax = driver.base_addr + 0x4C6BA455;            //lea rax, [0x0000000049E93DDF]
                r8 += rax;              //add r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x15;           //shr rax, 0x15
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x2A;           //shr rax, 0x2A
                r8 ^= rax;              //xor r8, rax
                rax = 0x24330C973F0DB51A;               //mov rax, 0x24330C973F0DB51A
                r8 -= rax;              //sub r8, rax
                return r8;
        }
        case 10:
        {
                r9 = driver.Read<uintptr_t>(driver.base_addr + 0x7AFB274);              //mov r9, [0x00000000052D48B7]
                rax = 0x5D28B638532005B9;               //mov rax, 0x5D28B638532005B9
                r8 *= rax;              //imul r8, rax
                rax = 0x74E097F4017F51F7;               //mov rax, 0x74E097F4017F51F7
                r8 *= rax;              //imul r8, rax
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r9;              //xor rax, r9
                rax = _byteswap_uint64(rax);            //bswap rax
                r8 *= driver.Read<uintptr_t>(rax + 0x9);                //imul r8, [rax+0x09]
                rax = driver.base_addr;                 //lea rax, [0xFFFFFFFFFD7D9493]
                rax += 0x197F977A;              //add rax, 0x197F977A
                rax += rbx;             //add rax, rbx
                r8 ^= rax;              //xor r8, rax
                rax = rbx;              //mov rax, rbx
                rax = ~rax;             //not rax
                rax -= driver.base_addr;                //sub rax, [rbp-0x30] -- didn't find trace -> use base
                rax += 0xFFFFFFFFFFFF85D1;              //add rax, 0xFFFFFFFFFFFF85D1
                r8 += rax;              //add r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x21;           //shr rax, 0x21
                r8 ^= rax;              //xor r8, rax
                r8 += 0x12F18E02;               //add r8, 0x12F18E02
                r8 += rbx;              //add r8, rbx
                return r8;
        }
        case 11:
        {
                r9 = driver.Read<uintptr_t>(driver.base_addr + 0x7AFB274);              //mov r9, [0x00000000052D4317]
                rax = r8;               //mov rax, r8
                rax >>= 0x1F;           //shr rax, 0x1F
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x3E;           //shr rax, 0x3E
                r8 ^= rax;              //xor r8, rax
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r9;              //xor rax, r9
                rax = _byteswap_uint64(rax);            //bswap rax
                r8 *= driver.Read<uintptr_t>(rax + 0x9);                //imul r8, [rax+0x09]
                rax = driver.base_addr;                 //lea rax, [0xFFFFFFFFFD7D8FFF]
                r8 ^= rax;              //xor r8, rax
                rax = 0xC428E195BBC0516D;               //mov rax, 0xC428E195BBC0516D
                r8 *= rax;              //imul r8, rax
                rax = 0xDF8A14714590B590;               //mov rax, 0xDF8A14714590B590
                r8 += rax;              //add r8, rax
                r8 += rbx;              //add r8, rbx
                rax = 0x623A6A19190D56E3;               //mov rax, 0x623A6A19190D56E3
                r8 -= rax;              //sub r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x22;           //shr rax, 0x22
                r8 ^= rax;              //xor r8, rax
                return r8;
        }
        case 12:
        {
                rbx = rbx;              //mov rbx, rbx
                r10 = driver.Read<uintptr_t>(driver.base_addr + 0x7AFB274);             //mov r10, [0x00000000052D3DDD]
                rax = 0x207448438694BDED;               //mov rax, 0x207448438694BDED
                r8 *= rax;              //imul r8, rax
                rax = 0xFEB4ED19C891E2E8;               //mov rax, 0xFEB4ED19C891E2E8
                r8 ^= rax;              //xor r8, rax
                r8 += rbx;              //add r8, rbx
                uintptr_t RSP_0xFFFFFFFFFFFFFFC0;
                RSP_0xFFFFFFFFFFFFFFC0 = driver.base_addr + 0x4AFA74B6;                 //lea rax, [0x000000004878002A] : RBP+0xFFFFFFFFFFFFFFC0
                r8 += RSP_0xFFFFFFFFFFFFFFC0;           //add r8, [rbp-0x40]
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r10;             //xor rax, r10
                rax = _byteswap_uint64(rax);            //bswap rax
                r8 *= driver.Read<uintptr_t>(rax + 0x9);                //imul r8, [rax+0x09]
                rax = r8;               //mov rax, r8
                rax >>= 0x1D;           //shr rax, 0x1D
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x3A;           //shr rax, 0x3A
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x28;           //shr rax, 0x28
                rax ^= rbx;             //xor rax, rbx
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x15;           //shr rax, 0x15
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x2A;           //shr rax, 0x2A
                r8 ^= rax;              //xor r8, rax
                return r8;
        }
        case 13:
        {
                rcx = driver.Read<uintptr_t>(driver.base_addr + 0x7AFB274);             //mov rcx, [0x00000000052D3865]
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= rcx;             //xor rax, rcx
                rax = _byteswap_uint64(rax);            //bswap rax
                r8 *= driver.Read<uintptr_t>(rax + 0x9);                //imul r8, [rax+0x09]
                rax = driver.base_addr + 0x6155498A;            //lea rax, [0x000000005ED2CE00]
                rax = ~rax;             //not rax
                rax *= rbx;             //imul rax, rbx
                r8 ^= rax;              //xor r8, rax
                rax = driver.base_addr;                 //lea rax, [0xFFFFFFFFFD7D8465]
                r8 -= rax;              //sub r8, rax
                rax = 0x9D591CC635837C7F;               //mov rax, 0x9D591CC635837C7F
                r8 *= rax;              //imul r8, rax
                rax = 0xDF5D755186D88CC0;               //mov rax, 0xDF5D755186D88CC0
                r8 ^= rax;              //xor r8, rax
                r8 ^= rbx;              //xor r8, rbx
                rax = 0xFF4C025263EECEFB;               //mov rax, 0xFF4C025263EECEFB
                r8 *= rax;              //imul r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x12;           //shr rax, 0x12
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x24;           //shr rax, 0x24
                r8 ^= rax;              //xor r8, rax
                return r8;
        }
        case 14:
        {
                rbx = rbx;              //mov rbx, rbx
                r10 = driver.Read<uintptr_t>(driver.base_addr + 0x7AFB274);             //mov r10, [0x00000000052D346C]
                rax = r8;               //mov rax, r8
                rax >>= 0x6;            //shr rax, 0x06
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0xC;            //shr rax, 0x0C
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x18;           //shr rax, 0x18
                r8 ^= rax;              //xor r8, rax
                rcx = driver.base_addr + 0xCA1;                 //lea rcx, [0xFFFFFFFFFD7D8C12]
                rcx = ~rcx;             //not rcx
                rcx *= rbx;             //imul rcx, rbx
                rax = r8;               //mov rax, r8
                rax >>= 0x30;           //shr rax, 0x30
                rcx ^= rax;             //xor rcx, rax
                r8 ^= rcx;              //xor r8, rcx
                rax = 0x507D65590A5136AC;               //mov rax, 0x507D65590A5136AC
                r8 += rax;              //add r8, rax
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r10;             //xor rax, r10
                rax = _byteswap_uint64(rax);            //bswap rax
                r8 *= driver.Read<uintptr_t>(rax + 0x9);                //imul r8, [rax+0x09]
                rax = r8;               //mov rax, r8
                rax >>= 0xC;            //shr rax, 0x0C
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x18;           //shr rax, 0x18
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x30;           //shr rax, 0x30
                r8 ^= rax;              //xor r8, rax
                rax = 0xA18A24C507C70D43;               //mov rax, 0xA18A24C507C70D43
                r8 *= rax;              //imul r8, rax
                r8 -= rbx;              //sub r8, rbx
                rax = 0x259B3812CC4BCB07;               //mov rax, 0x259B3812CC4BCB07
                r8 ^= rax;              //xor r8, rax
                return r8;
        }
        case 15:
        {
                //failed to translate: pop rbx
                r13 = driver.base_addr + 0x4EC6;                //lea r13, [0xFFFFFFFFFD7DCA4D]
                r10 = driver.Read<uintptr_t>(driver.base_addr + 0x7AFB274);             //mov r10, [0x00000000052D2D9B]
                rax = rbx;              //mov rax, rbx
                rax *= r13;             //imul rax, r13
                r8 -= rax;              //sub r8, rax
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r10;             //xor rax, r10
                rax = _byteswap_uint64(rax);            //bswap rax
                r8 *= driver.Read<uintptr_t>(rax + 0x9);                //imul r8, [rax+0x09]
                rax = driver.base_addr;                 //lea rax, [0xFFFFFFFFFD7D7712]
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x19;           //shr rax, 0x19
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x32;           //shr rax, 0x32
                r8 ^= rax;              //xor r8, rax
                rax = 0xBC6B78BD2A2F968D;               //mov rax, 0xBC6B78BD2A2F968D
                r8 *= rax;              //imul r8, rax
                rax = 0xEDE1CA50D61DC1F8;               //mov rax, 0xEDE1CA50D61DC1F8
                r8 ^= rax;              //xor r8, rax
                rax = driver.base_addr + 0x9E35;                //lea rax, [0xFFFFFFFFFD7E15C8]
                rax = ~rax;             //not rax
                rax += rbx;             //add rax, rbx
                r8 ^= rax;              //xor r8, rax
                rax = 0x71D8156D42150528;               //mov rax, 0x71D8156D42150528
                r8 ^= rax;              //xor r8, rax
                return r8;
        }
        }
}
uint16_t get_bone_index(const Driver& driver, uint32_t bone_index)
{
        const uint64_t mb = driver.base_addr;
        uint64_t rax = mb, rbx = mb, rcx = mb, rdx = mb, rdi = mb, rsi = mb, r8 = mb, r9 = mb, r10 = mb, r11 = mb, r12 = mb, r13 = mb, r14 = mb, r15 = mb;
        rbx = bone_index;
        rcx = rbx * 0x13C8;
        rax = 0x5B220A9734BB1261;               //mov rax, 0x5B220A9734BB1261
        r11 = driver.base_addr;                 //lea r11, [0xFFFFFFFFFD97431D]
        rax = _umul128(rax, rcx, (uintptr_t*)&rdx);             //mul rcx
        r10 = 0xC0DBFAEA33225327;               //mov r10, 0xC0DBFAEA33225327
        rdx >>= 0xB;            //shr rdx, 0x0B
        rax = rdx * 0x1679;             //imul rax, rdx, 0x1679
        rcx -= rax;             //sub rcx, rax
        rax = 0x4A1AB41F6851575;                //mov rax, 0x4A1AB41F6851575
        r8 = rcx * 0x1679;              //imul r8, rcx, 0x1679
        rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
        rdx >>= 0x7;            //shr rdx, 0x07
        rax = rdx * 0x1BA3;             //imul rax, rdx, 0x1BA3
        r8 -= rax;              //sub r8, rax
        rax = 0x27350B88127350B9;               //mov rax, 0x27350B88127350B9
        rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
        rax = r8;               //mov rax, r8
        rax -= rdx;             //sub rax, rdx
        rax >>= 0x1;            //shr rax, 0x01
        rax += rdx;             //add rax, rdx
        rax >>= 0x6;            //shr rax, 0x06
        rcx = rax * 0x6F;               //imul rcx, rax, 0x6F
        rax = 0x446F86562D9FAEE5;               //mov rax, 0x446F86562D9FAEE5
        rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
        rax = r8;               //mov rax, r8
        rax -= rdx;             //sub rax, rdx
        rax >>= 0x1;            //shr rax, 0x01
        rax += rdx;             //add rax, rdx
        rax >>= 0x6;            //shr rax, 0x06
        rcx += rax;             //add rcx, rax
        rax = rcx * 0xCA;               //imul rax, rcx, 0xCA
        rcx = r8 * 0xCC;                //imul rcx, r8, 0xCC
        rcx -= rax;             //sub rcx, rax
        rax = driver.Read<uint16_t>(rcx + r11 * 1 + 0x7B10FB0);                 //movzx eax, word ptr [rcx+r11*1+0x7B10FB0]
        r8 = rax * 0x13C8;              //imul r8, rax, 0x13C8
        rax = r10;              //mov rax, r10
        rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
        rax = r10;              //mov rax, r10
        rdx >>= 0xC;            //shr rdx, 0x0C
        rcx = rdx * 0x153D;             //imul rcx, rdx, 0x153D
        r8 -= rcx;              //sub r8, rcx
        r9 = r8 * 0x2289;               //imul r9, r8, 0x2289
        rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
        rdx >>= 0xC;            //shr rdx, 0x0C
        rax = rdx * 0x153D;             //imul rax, rdx, 0x153D
        r9 -= rax;              //sub r9, rax
        rax = 0x1A7B9611A7B9611B;               //mov rax, 0x1A7B9611A7B9611B
        rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
        rax = r9;               //mov rax, r9
        rax -= rdx;             //sub rax, rdx
        rax >>= 0x1;            //shr rax, 0x01
        rax += rdx;             //add rax, rdx
        rax >>= 0x5;            //shr rax, 0x05
        rcx = rax * 0x3A;               //imul rcx, rax, 0x3A
        rax = 0x7B301ECC07B301ED;               //mov rax, 0x7B301ECC07B301ED
        rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
        rdx >>= 0x6;            //shr rdx, 0x06
        rcx += rdx;             //add rcx, rdx
        rax = rcx * 0x10A;              //imul rax, rcx, 0x10A
        rcx = r9 * 0x10C;               //imul rcx, r9, 0x10C
        rcx -= rax;             //sub rcx, rax
        r15 = driver.Read<uint16_t>(rcx + r11 * 1 + 0x7B16750);                 //movsx r15d, word ptr [rcx+r11*1+0x7B16750]
        return r15;
}

};


namespace vanguard sig test {
        constexpr auto pose = 0x0;
        constexpr auto nextState = 0x350;
        constexpr auto flags = 0x350;
        constexpr auto size = 0x0;
        constexpr auto s_aab_get_pointer_origin = 0x0;
        constexpr auto m_bgHandler = 0x0;
        constexpr auto cls = 0x0;
        constexpr auto cmdNumber = 0x0;
        constexpr auto cmd_number_aab = 0x0;
        constexpr auto cmds = 0x0;
        constexpr auto CG_DObjGetWorldTagPos = 0x0;
        constexpr auto CG_ScoreboardMP_GetClientScore = 0x10;
        constexpr auto CG_VehicleCam_SetClientViewAngles = 0x0;
        constexpr auto ms_cgameStaticsArray = 0x0;
        constexpr auto CgWeaponMap__ms_instance = 0x0;
        constexpr auto command_queue = 0x0;
        constexpr auto swap_chain = 0xFFFFFFFFFFFFFF98;
        constexpr auto ClActiveClient_GetClient = 0xFFFFFFFFFFFFFF98;
        constexpr auto PhysicsQuery_LegacyMPCGWeaponSimTrace = 0xFFFFFFFFFFFFFF98;
        constexpr auto BG_GetWeaponFireType = 0x0;
        constexpr auto BG_UsrCmdUnpackAngle = 0x0;
        constexpr auto BG_GetPlayerEyePosition = 0x0;
        constexpr auto BG_UsrCmdPackAngle = 0x0;
        constexpr auto BG_GetEntityWorldTagPosition = 0x0;
        constexpr auto CgWeaponMap__ms_instance = 0x0;
        constexpr auto g_cgPlayerTraceInfo = 0x0;
};
