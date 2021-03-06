format PE console 5.0
include 'win32ax.inc'
entry    start

section '.data' data readable writeable
        ;������
        buff          dd      ?              ;������, �� ������� ��������� addressOfEntryPoint
        FP            dd      ?
        mode          db      'rb',0
        fName         db      256 dup(1)
        tpt           db      '0x%0X ',0
        tpn           db      '%s',0
        buf           dd      ?
        hOut          dd      ?
        crlf    =   $ - 1

        ;DOS HEADER
        e_magic               dd      ?       ;������������ ��������� pe �����
        e_lfanew              dd      ?       ;������ pe ���������

        ;PE HEADER
        signature             dd      ?

        ;FILE HEADER
        machine               dd      ?
        numsection            dd      ?         ;NumberOfSections
        sizeopthead           dd      ?         ;SizeOfOptionalHeader
        characteristic        dd      ?

        ;OPTIONAL HEADER
        magic                 dd      ?
        addressEntPnt         dd      ?         ;addressOfEntryPoint
        imageBase             dd      ?         ;
        imageBaseHalf         dd      ?
        sectionAlignm         dd      ?         ;SectionsAlignment
        fileAlignm            dd      ?         ;FileAlignment
        majorSybVersion       dd      ?         ;MajorSubsystemVersion
        sizeImage             dd      ?         ;sizeOfImage
        sizeHeader            dd      ?         ;sizeOfHeader
        subSystem             dd      ?
        numberOfRvaAndSizes   dd      ?

        ;������� ������
        name                  dq      ?
        virtualSize           dd      ?
        virtualAddress        dd      ?
        sizeOfRawData         dd      ?
        pointerToRawData      dd      ?
        pointerToRelocations  dd      ?

        ;������� �������
        importTableRVA        dd      ?         ;rva ������� ������
        importTableSize       dd      ?         ;������ ������� ������
        rawImportTable        dd      ?         ;rwa �� ������� �������
        VAImportSection       dd      ?         ;����� ��������� rwa
        VSImportSection       dd      ?         ;����� ��������� rwa
        importPointerRaw      dd      ?         ;����� ��������� rwa

        ;_IMAGE_IMPORT_DESCRIPTOR
        OriginalFirstThunk    dd      ?
        TimeDateStamp         dd      ?
        ForwarderChain        dd      ?
        NameImport            dd      ?
        FirstThunk            dd      ?

        ;��� �������
        buff2                 dd      ?              ;������ ������ ���� ������
        buff3                 dd      ?
        buff4                 dd      ?              ;� ����� , ��� ��������� �������� ������. ��� ����������
        buff5                 dd      ?
        buff6                 dd      ?
        forCmpEntropy         dq      6.7            ;����� ���������� � ���� ������ �������� ������. ���� ��� >, �� �����
        EntrPointSection      dd      ?
        entropyMassiv         dd      256 dup(?)
        entropySum            dq      ?
        curElement            dd      ?
        buffEntropy           dq      ?
        tempEntropy           dq      ?

        ;�������������� �-��
        buffName              db      256 dup(?)
        buffLength            dd      ?
        func1                 db      "lsDebuggerPresent",0
        func2                 db      "GetThreadContext",0
        func3                 db      "ReadProcessMemory",0
        func4                 db      "WriteProcessMemory",0
        func5                 db      "SetWindowsHookExW",0
        func6                 db      "MapViewOfFile",0
        func7                 db      "CryptGenRandom",0
        func8                 db      "CryptAcquireContextW",0
        func9                 db      "OpenThreadToken",0
        func10                 db      "DuplicateTokenEx",0
        func11                 db      "AllocateAndInitializeSid",0
        func12                 db      "CryptCreateHash",0
        func13                 db      "SetNamedSecurityInfoW",0
        func14                 db      "SetNamedSecurityInfo",0
        func15                 db      "SetSecurityDescriptorDacl",0
        func16                 db      "InitializeSecurityDescriptor",0
        func17                 db      "GetTokenInformation",0
        func18                 db      "OpenProcessToken",0
        func19                 db      "IsWellKnownSid",0
        func20                 db      "SetSecurityInfo",0
        func21                 db      "CreateProcessAsUserW",0
        func22                 db      "LookupPrivilegeValueW",0
        func23                 db      "LookupPrivilegeValueA",0
        func24                 db      "CryptGetHashParam",0

macro macroRwa [somethingRva]
{
        ;rwa = rva - VAImportSection + importSectionPointerToRawData
        mov eax,[somethingRva]
        sub eax,[VAImportSection]
        add eax,[importPointerRaw]
        push eax                                                                ;������� � ����
}
macro macroPrint str,[perem]
{
        cinvoke puts,crlf
        cinvoke printf,"    "
        cinvoke printf,str
        cinvoke printf," - "
        cinvoke printf,tpt,[perem]
}
macro macroCmpName buffName,badName
{
  local exit
  invoke lstrlen,buffName
  mov [buffLength],eax
  invoke lstrlen,badName
  .if [buffLength] = eax
      mov ecx,eax
      mov edi,buffName
      mov esi,badName
      repe cmpsb
           jne exit
      cinvoke printf,buffName
      cinvoke puts,crlf
      inc [buff6]
  .endif
exit:
}

section '.text' code readable executable
start:
    finit
    cinvoke printf,"Path to file (no spaces) : "
    invoke scanf,"%s",fName                                                             ;���� �� ����� ��� �������!
    invoke fopen,fName, mode ;O_RDONLY or O_BINARY
    mov [FP], eax
    ;--------------------------DOS HEADER
    invoke  fread,  e_magic, 1,2, [FP]                                                  ;��������� 1� 2� �����(e_magic)
    cmp [e_magic], 5a4dh                                                                ;��������, ����� �� ��� pe file?
        jne notPe
    ;cinvoke printf,"FILE INFO"
    ;cinvoke puts,crlf
    ;cinvoke printf,"[DOS Header]"
    ;macroPrint "e_magic",e_magic

    cinvoke fseek,[FP],3ch,0                                                            ;������ ����� ����, ��� ��������� e_lfanew(��������� �� ������ pe ������)
    invoke fread,e_lfanew,1,4,[FP]                                                      ;������ ��� 4 �����
    ;macroPrint "e_lfanew",e_lfanew

    ;--------------------------PE HEADER
    ;cinvoke puts,crlf
    ;cinvoke puts,crlf
    ;cinvoke printf,"[PE Header]"
    cinvoke fseek,[FP],[e_lfanew],0                                                     ;������ ����� �� ������ pe ������
    invoke fread,signature,1,4,[FP]                                                           ;������ ��� 4 �����
    cmp [signature],4550h                                                                     ;���� ��� = 4550h, �� ��, ��� pe file. ��� ���� ��������
        jne notPe
    ;macroPrint "Signature",signature

    ;--------------------------FILE HEADER
    ;cinvoke puts,crlf
    ;cinvoke puts,crlf
    ;cinvoke printf,"[File Header]"

    invoke fread,machine,1,2,[FP]
    ;macroPrint "Machine",machine
    invoke fread,numsection,1,2,[FP]
    ;macroPrint  "NumberOfSections",numsection

    cinvoke fseek,[FP],12,1
    invoke fread,sizeopthead,1,2,[FP]
    ;macroPrint "SizeOfOptionalHeader",sizeopthead

    invoke fread,characteristic,1,2,[FP]
    ;macroPrint  "Characteristics",characteristic


    ;--------------------------OPTIONAL HEADER
    cinvoke puts,crlf
    ;cinvoke puts,crlf
    ;cinvoke printf,"[Optional Header]"

    invoke fread,magic,1,2,[FP]
    ;macroPrint "Magic",magic

    cinvoke fseek,[FP],14,1
    invoke fread,addressEntPnt,1,4,[FP]
    ;macroPrint "AddressOfEntryPoint",addressEntPnt

    .if [magic] = 20bh                                                          ;���� ����� 64 ������, �� ImageBase = 8 ����.
        ;cinvoke puts,crlf
        cinvoke fseek,[FP],4,1
        invoke fread,imageBase,1,4,[FP]
        invoke fread,imageBaseHalf,1,4,[FP]
        ;cinvoke printf,"    ImageBase - "
        ;cinvoke printf,"0x%x",[imageBaseHalf]
        ;cinvoke printf,"%x",[imageBase]
    .else                                                                       ;����� ImageBase = 4 �����
        cinvoke fseek,[FP],8,1
        invoke fread, imageBase,1,4,[FP]
        ;macroPrint "ImageBase",imageBase
    .endif

    invoke fread,sectionAlignm,1,4,[FP]
    ;macroPrint "SectionAlignment",sectionAlignm

    invoke fread,fileAlignm,1,4,[FP]
    ;macroPrint "FileAlignment",fileAlignm

    cinvoke fseek,[FP],6,1
    invoke fread,majorSybVersion,1,2,[FP]
    ;macroPrint "MajorSubsystemVersion",majorSybVersion

    cinvoke fseek,[FP],8,1
    invoke fread,sizeImage,1,4,[FP]
    ;macroPrint "SizeOfImage",sizeImage
    cinvoke ftell,[FP]
    mov [buff2],eax

    invoke fread,sizeHeader,1,4,[FP]
    ;macroPrint "SizeHeader",sizeHeader

    cinvoke fseek,[FP],4,1
    invoke fread,subSystem,1,2,[FP]
    ;macroPrint "Subsystem",subSystem

    .if [magic] = 20bh                                                          ;���� ���� 64 ���, ��������� �� 38 ����� �����
       cinvoke fseek,[FP],38,1
    .else
       cinvoke fseek,[FP],22,1                                                  ;� ���� ������ 22 �����
    .endif
    invoke fread,numberOfRvaAndSizes,1,4,[FP]
    ;macroPrint "NumberOfRvaAndSizes",numberOfRvaAndSizes
    cinvoke fseek,[FP],8,1
    invoke fread,importTableRVA,1,4,[FP]
    ;macroPrint "Import table rva",importTableRVA
    invoke fread,importTableSize,1,4,[FP]
    ;macroPrint "Import table size",importTableSize

    ;---------------��������� �������� �� ������� ������
    mov eax,[numberOfRvaAndSizes]                                               ;����� ��������� � ������� DataDirectory
    mov ebx,8                                                                   ;8. �.�. � ��������� _IMAGE_DATA_DIRECTORY  2� �������� �� 4 �����
    mul ebx
    sub eax,16
    mov ebx,eax
    ;---------------������ ������� ������
    ;cinvoke puts,crlf
    ;cinvoke puts,crlf
    cinvoke printf,"[Section Table]"
    cinvoke fseek,[FP],ebx,1

    mov [buff],0
markerSectionLoop:
    cinvoke puts,crlf
    invoke fread,name,1,8,[FP]
    cinvoke printf,"    Name - "
    cinvoke printf,name


    invoke fread,virtualSize,1,4,[FP]
    ;macroPrint "VirtualSize",virtualSize

    invoke fread,virtualAddress,1,4,[FP]
    ;macroPrint "VirtualAddress",virtualAddress

    invoke fread,sizeOfRawData,1,4,[FP]
    ;macroPrint "SizeOfRawData",sizeOfRawData

    invoke fread,pointerToRawData,1,4,[FP]
    ;macroPrint "PointerToRawData",pointerToRawData

    invoke fread,pointerToRelocations,1,4,[FP]
    ;macroPrint "PointerToRelocations",pointerToRelocations

    ;�������� RAW ������� �������
    ;���� virtualAddress<=rva<virtualAddress+virtualSize , �� ��� ���� ������
    mov ebx,[importTableRVA]
    .if [virtualAddress]<=ebx
        mov eax,[virtualAddress]
        add eax,[virtualSize]
        .if [importTableRVA]<eax
            ;���������� VA,VS, pointerToRawData ������ ������
            mov eax,[importTableRVA]
            sub eax,[virtualAddress]
            add eax,[pointerToRawData]
            mov [rawImportTable],eax
            mov eax,[virtualAddress]
            mov [VAImportSection],eax
            mov eax,[pointerToRawData]
            mov [importPointerRaw],eax
        .endif
    .endif
    ;���� ������ ������ ������ = 0, �� �� ����� ������ ������ ��� ���� ��������. ������ ������� �� ���� � ��������� �� ���� ������
    .if [sizeOfRawData] = 0
        cinvoke puts,crlf
        cinvoke printf,"            Entropy this section: 0"
        jmp sizeRawDataZero
    .endif
    cinvoke ftell,[FP]                                                  ;����������, ��� �� ������������
    mov [buff2],eax

    cinvoke fseek,[FP],[pointerToRawData],0                             ;��������� � ������ ������ ������
    cinvoke puts,crlf
;��������� ������� �������
getMassivEntropyloop:
    cinvoke fread,buff3,1,1,[FP]                                        ;��������� ������ ����
    ;�������� ���-�� ����
    mov eax,[buff3]                                                     ;��� ���������
    mov ebx,4
    mul ebx                                                             ;�.�. dd (4 �����)
    inc [entropyMassiv+eax]

    inc [buff4]                                                         ;����������� ������� �� 1
    mov eax,[sizeOfRawData]                                             ;����� ���������� ������� � ������ ������(����� ���������� m/r)
    .if [buff4]<eax                                                     ;���� ������, �� ��
       jmp getMassivEntropyloop
    .endif
    mov [buff4],0

    mov esi,0
    mov [buff5],0                                                       ;����� ��������� ���-�� ��������(��� �����)
;������� ��������
calculateEntropy:
    fld1                                                                ;� ���� ���������� 1(��� ���������)_
    fld [entropyMassiv+esi]                                             ;� ���� ������� ������� �������
    fld [sizeOfRawData]                                                 ;� ���� sizeOfRawData
    fdivp                                                               ;������� ������� ������� / sizeOfRawData (� �������� ���������� �������� �� �����)
    fst [tempEntropy]                                                   ;���������� ��� � tempEntropy
    ftst                                                                ;���������� st(0)(������� ������� �������/sizeOfRawData) � 0
    fstsw ax                                                            ;��������� ������� �������� ��������� SR � AX
    sahf                                                                ;��������� ����� SF, ZF, AF, PF, CF �� �������� ah (��������� ������� ��� � ������� cmp)
      jna nextElement                                                   ;st(0)<0? -> nextElement
    FYL2X                                                               ;�������� LOG 2 (tempEntropy)
    FLDLN2                                                              ;� ���� LN2
    FMULP                                                               ;LOG 2 (tempEntropy) * LN2 = ����������� �������� (tempEntropy)
    FLDL2E                                                              ;� ���� LOG 2 (e)
    fmulp                                                               ;����������� �������� (tempEntropy) * LOG 2 (e) = LOG2(tempEntropy)
    fld [tempEntropy]                                                   ;� ���� tempEntropy
    fmulp                                                               ;tempEntropy * LOG2(tempEntropy)
    fabs                                                                ;|tempEntropy * LOG2(tempEntropy)|
    fld [entropySum]                                                    ;� ���� ����� ��������
    faddp                                                               ;+=
    fst [entropySum]                                                    ;��� ����� �������� � entropySum
    fldz                                                                ;� ���� 0
    fstp [entropyMassiv+esi]                                            ; = 0 ��� �������������� �������
nextElement:
    add esi,4                                                           ;���� �������
    inc [buff5]                                                         ;������� +1
    .if [buff5]<256                                                     ;���� �� <256
       finit                                                            ;������� ����
       jmp calculateEntropy                                             ;������� �������� ��� ���� ��������
    .endif
    cinvoke printf,"            Entropy this section: "
    cinvoke printf,"%f",dword [entropySum],dword [entropySum+4]         ;������� �������� ������
    fld [forCmpEntropy]
    fcomp                                                                ;���������� st(0)(������� ������� �������/sizeOfRawData) � 0
    fstsw ax                                                            ;��������� ������� �������� ��������� SR � AX
    sahf                                                                ;��������� ����� SF, ZF, AF, PF, CF �� �������� ah (��������� ������� ��� � ������� cmp)
      jb entropyMore                                                   ;st(0)<0? -> nextElement
m1:
    fldz                                                                ;0 � ����
    fstp [entropySum]                                                   ;0 � entropySum (����� ������� �������)
;���� ����� �����
    mov eax, [addressEntPnt]
    .if   [virtualAddress] < eax                                        ;���� ����������� ����� ������ ������, �� ������� ����������� addressEntPnt
        mov ebx,[buff]                                                  ;�� ��� �� ������, �� ������� ��������� AddressOfEntryPoint
        mov [EntrPointSection],ebx
    .endif

    cinvoke fseek,[FP],[buff2],0
sizeRawDataZero:
    cinvoke fseek,[FP],12,1                                             ;������� �� ���� ������
    cinvoke puts,crlf

    inc [buff]
    mov eax,[numsection]
    .if [buff]< eax
        jmp markerSectionLoop
    .endif

    ;------------------------------------������
    cinvoke puts,crlf
    cinvoke puts,crlf
    cinvoke printf,"%d",[EntrPointSection]
    cinvoke printf," - this section is indicated by an entry point"
    cinvoke puts,crlf
    cinvoke puts,crlf
    cinvoke printf,"Suspicious functions: "
    cinvoke puts,crlf

    ;������� �������
    mov [buff6],0
    cinvoke puts,crlf
nextDll:
    cinvoke fseek,[FP],[rawImportTable],0                                           ;������ ����� �� ������ _IMAGE_IMPORT_DESCRIPTOR
    cinvoke fread,buff2,1,4,[FP]                                                    ;rva �� Import Name Table
    .if [buff2] = 0h
        jmp exitProg
    .endif
    macroRwa buff2
    pop [buff4]                                                                     ;rwa �� ������ Import Name Table
nextRvaFunc:
    cinvoke fseek,[FP],[buff4],0                                                    ;������ ��������� �� ������ Import Name Table
    cinvoke fread,buff3,1,4,[FP]                                                    ;�������� rva �� ��������� Import Name Table
    .if [buff3]=0h                                                                  ;���� ��� = 0 (����� rva �-�� - 4����� = 0 )
        add [rawImportTable],20                                                     ;+20
        jmp nextDll
    .endif
   macroRwa buff3
    pop ebx
    add ebx,2
    cinvoke fseek,[FP],ebx,0                                                         ;����� �� ��������� � hint(2 ����� )� ��� �������
    cld
    mov edi,buffName
    cld
readNameFunc:
    cinvoke fread,buff5,1,1,[FP]                                                     ;������ ����
    mov eax, [buff5]
    stosb
    .if [buff5]<> 100h                                                               ;���� �� != 0
        inc dl
        jmp readNameFunc                                                             ;�� ������ ���� �������
    .endif
    macroCmpName buffName,func1
    macroCmpName buffName,func2
    macroCmpName buffName,func3
    macroCmpName buffName,func4
    macroCmpName buffName,func5
    macroCmpName buffName,func6
    macroCmpName buffName,func7
    macroCmpName buffName,func8
    macroCmpName buffName,func9
    macroCmpName buffName,func10
    macroCmpName buffName,func11
    macroCmpName buffName,func12
    macroCmpName buffName,func13
    macroCmpName buffName,func14
    macroCmpName buffName,func15
    macroCmpName buffName,func16
    macroCmpName buffName,func17
    macroCmpName buffName,func18
    macroCmpName buffName,func19
    macroCmpName buffName,func20
    macroCmpName buffName,func21
    macroCmpName buffName,func22
    macroCmpName buffName,func23
    macroCmpName buffName,func24


    add [buff4],4                                                                    ;��������� 4 ����
    jmp nextRvaFunc                                                                  ;������ ���� rva �������


exitProg:
    .if [buff6] = 0
        cinvoke printf,"no suspicious functions"
    .endif
    invoke _getch
    invoke ExitProcess, 0
    invoke  exit, 0

entropyMore:
    cinvoke puts,crlf
    cinvoke printf,"            [WARNING!] Entropy this section >6.7"
    jmp m1

notPe:
    cinvoke puts,crlf
    cinvoke printf,"not pe file"


    invoke _getch
    invoke  exit, 0
; import data in the same section
section '.idata' import data readable
 library  msvcrt,'MSVCRT.DLL',\
          kernel, 'KERNEL32.DLL'
 
 import msvcrt,\
    _getch,'_getch',\
    printf,'printf',\
    puts,'puts',\
    ferror,'ferror',\
    fclose,'fclose',\
    fread,'fread',\
    fopen,'fopen',\
    ftell,'ftell',\
    exit,'exit',\
    fseek,'fseek',\
    scanf, 'scanf'
 import kernel,\
        ExitProcess,'ExitProcess',\
        lstrlen,'lstrlen'