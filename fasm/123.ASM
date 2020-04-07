format PE console 5.0
include 'win32ax.inc'
entry    start

section '.data' data readable writeable
        ;РАЗНОЕ
        buff          dd      ?              ;секция, на которую указывает addressOfEntryPoint
        FP            dd      ?
        mode          db      'rb',0
        fName         db      256 dup(1)
        tpt           db      '0x%0X ',0
        tpn           db      '%s',0
        buf           dd      ?
        hOut          dd      ?
        crlf    =   $ - 1

        ;DOS HEADER
        e_magic               dd      ?       ;обязательная сигнатура pe файла
        e_lfanew              dd      ?       ;начало pe заголвока

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

        ;ТАБЛИЦА СЕКЦИЙ
        name                  dq      ?
        virtualSize           dd      ?
        virtualAddress        dd      ?
        sizeOfRawData         dd      ?
        pointerToRawData      dd      ?
        pointerToRelocations  dd      ?

        ;ТАБЛИЦА ИМПОРТА
        importTableRVA        dd      ?         ;rva таблицы импорт
        importTableSize       dd      ?         ;размер таблицы ипорта
        rawImportTable        dd      ?         ;rwa до таблицы импорта
        VAImportSection       dd      ?         ;чтобы вычислять rwa
        VSImportSection       dd      ?         ;чтобы вычислять rwa
        importPointerRaw      dd      ?         ;чтобы вычислять rwa

        ;_IMAGE_IMPORT_DESCRIPTOR
        OriginalFirstThunk    dd      ?
        TimeDateStamp         dd      ?
        ForwarderChain        dd      ?
        NameImport            dd      ?
        FirstThunk            dd      ?

        ;ДЛЯ АНАЛИЗА
        buff2                 dd      ?              ;храним начало след секции
        buff3                 dd      ?
        buff4                 dd      ?              ;в цикле , где считается энтропия секций. под переменную
        buff5                 dd      ?
        buff6                 dd      ?
        forCmpEntropy         dq      6.7            ;будем сравнивать с этим числом энтропию секций. если она >, то плохо
        EntrPointSection      dd      ?
        entropyMassiv         dd      256 dup(?)
        entropySum            dq      ?
        curElement            dd      ?
        buffEntropy           dq      ?
        tempEntropy           dq      ?

        ;подозрительынй ф-ии
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
        push eax                                                                ;заносим в стек
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
    invoke scanf,"%s",fName                                                             ;путь до файла БЕЗ ПРОБЕЛА!
    invoke fopen,fName, mode ;O_RDONLY or O_BINARY
    mov [FP], eax
    ;--------------------------DOS HEADER
    invoke  fread,  e_magic, 1,2, [FP]                                                  ;считываем 1е 2а байта(e_magic)
    cmp [e_magic], 5a4dh                                                                ;проверка, точно ли это pe file?
        jne notPe
    ;cinvoke printf,"FILE INFO"
    ;cinvoke puts,crlf
    ;cinvoke printf,"[DOS Header]"
    ;macroPrint "e_magic",e_magic

    cinvoke fseek,[FP],3ch,0                                                            ;ставим метку туда, где находится e_lfanew(указывает на начало pe секции)
    invoke fread,e_lfanew,1,4,[FP]                                                      ;читаем эти 4 байта
    ;macroPrint "e_lfanew",e_lfanew

    ;--------------------------PE HEADER
    ;cinvoke puts,crlf
    ;cinvoke puts,crlf
    ;cinvoke printf,"[PE Header]"
    cinvoke fseek,[FP],[e_lfanew],0                                                     ;ставим метку на начало pe секции
    invoke fread,signature,1,4,[FP]                                                           ;читаем эти 4 байта
    cmp [signature],4550h                                                                     ;если они = 4550h, то ок, это pe file. ещё одна проверка
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

    .if [magic] = 20bh                                                          ;если файла 64 битный, то ImageBase = 8 байт.
        ;cinvoke puts,crlf
        cinvoke fseek,[FP],4,1
        invoke fread,imageBase,1,4,[FP]
        invoke fread,imageBaseHalf,1,4,[FP]
        ;cinvoke printf,"    ImageBase - "
        ;cinvoke printf,"0x%x",[imageBaseHalf]
        ;cinvoke printf,"%x",[imageBase]
    .else                                                                       ;иначе ImageBase = 4 байта
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

    .if [magic] = 20bh                                                          ;если файл 64 бит, переходим на 38 байта вперёд
       cinvoke fseek,[FP],38,1
    .else
       cinvoke fseek,[FP],22,1                                                  ;в ином случае 22 байта
    .endif
    invoke fread,numberOfRvaAndSizes,1,4,[FP]
    ;macroPrint "NumberOfRvaAndSizes",numberOfRvaAndSizes
    cinvoke fseek,[FP],8,1
    invoke fread,importTableRVA,1,4,[FP]
    ;macroPrint "Import table rva",importTableRVA
    invoke fread,importTableSize,1,4,[FP]
    ;macroPrint "Import table size",importTableSize

    ;---------------ВЫЧИСЛЯЕМ СМЕЩЕНИЕ ДО ТАБЛИЦЫ СЕКЦИЙ
    mov eax,[numberOfRvaAndSizes]                                               ;чмсло каталогов в массиве DataDirectory
    mov ebx,8                                                                   ;8. т.к. в структуре _IMAGE_DATA_DIRECTORY  2а элемента по 4 байта
    mul ebx
    sub eax,16
    mov ebx,eax
    ;---------------ЧИТАЕМ ТАБЛИЦУ СЕКЦИЙ
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

    ;ПОЛУЧАЕМ RAW ТАБЛИЦЫ ИМПОРТА
    ;если virtualAddress<=rva<virtualAddress+virtualSize , то это наша секция
    mov ebx,[importTableRVA]
    .if [virtualAddress]<=ebx
        mov eax,[virtualAddress]
        add eax,[virtualSize]
        .if [importTableRVA]<eax
            ;запоминаем VA,VS, pointerToRawData данной секции
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
    ;ЕСЛИ РАЗМЕР ДАННЫХ СЕКЦИИ = 0, ТО НЕ ИМЕЕТ СМЫСЛА ИСКАТЬ ДЛЯ НЕГО ЭНТРОПИЮ. ПРОСТО ГОВОРИМ ОБ ЭТОМ И ПЕРЕХОДИМ НА СЛЕД СЕКЦИЮ
    .if [sizeOfRawData] = 0
        cinvoke puts,crlf
        cinvoke printf,"            Entropy this section: 0"
        jmp sizeRawDataZero
    .endif
    cinvoke ftell,[FP]                                                  ;запоминаем, где мы остановились
    mov [buff2],eax

    cinvoke fseek,[FP],[pointerToRawData],0                             ;переходим к данным данной секции
    cinvoke puts,crlf
;ЗАПОЛНЯЕМ МАССИВА БАЙТАМИ
getMassivEntropyloop:
    cinvoke fread,buff3,1,1,[FP]                                        ;считываем первый байт
    ;Получаем кол-во байт
    mov eax,[buff3]                                                     ;для адресации
    mov ebx,4
    mul ebx                                                             ;т.к. dd (4 байта)
    inc [entropyMassiv+eax]

    inc [buff4]                                                         ;увеличиваем счетчик на 1
    mov eax,[sizeOfRawData]                                             ;чтобы сравнивать счетчик и размер данных(можно сравнивать m/r)
    .if [buff4]<eax                                                     ;если меньше, то на
       jmp getMassivEntropyloop
    .endif
    mov [buff4],0

    mov esi,0
    mov [buff5],0                                                       ;ЧТОБЫ СЧИТЫВАТЬ КОЛ-ВО ПРОХОДОВ(ДЛЯ ЦИКЛА)
;СЧИТАЕМ ЭНТРОПИЮ
calculateEntropy:
    fld1                                                                ;В СТЕК ОТПРАВЛЯЕМ 1(ДЛЯ ЛОГАРИФМА)_
    fld [entropyMassiv+esi]                                             ;В СТЕК ТЕКУЩИЙ ЭЛЕМЕНТ МАССИВА
    fld [sizeOfRawData]                                                 ;В СТЕК sizeOfRawData
    fdivp                                                               ;ТЕКУЩИЙ ЭЛЕМЕНТ МАССИВА / sizeOfRawData (С УДАЛЕНИМ ПОСЛЕДНЕГО ЭЛЕМЕНТА ИЗ СТЕКА)
    fst [tempEntropy]                                                   ;ЗАПОМИНАЕМ ЭТО В tempEntropy
    ftst                                                                ;сравниваем st(0)(текущий элемент массива/sizeOfRawData) с 0
    fstsw ax                                                            ;сохраняет текущее значение регистров SR в AX
    sahf                                                                ;загружает флаги SF, ZF, AF, PF, CF из регистра ah (позволяет работаь как с обычным cmp)
      jna nextElement                                                   ;st(0)<0? -> nextElement
    FYL2X                                                               ;ПОЛУЧАЕМ LOG 2 (tempEntropy)
    FLDLN2                                                              ;В СТЕК LN2
    FMULP                                                               ;LOG 2 (tempEntropy) * LN2 = НАТУРАЛЬНЫЙ ЛОГАРИФМ (tempEntropy)
    FLDL2E                                                              ;В СТЕК LOG 2 (e)
    fmulp                                                               ;НАТУРАЛЬНЫЙ ЛОГАРИФМ (tempEntropy) * LOG 2 (e) = LOG2(tempEntropy)
    fld [tempEntropy]                                                   ;В СТЕК tempEntropy
    fmulp                                                               ;tempEntropy * LOG2(tempEntropy)
    fabs                                                                ;|tempEntropy * LOG2(tempEntropy)|
    fld [entropySum]                                                    ;В СТЕК СУММУ ЭНТРОПИИ
    faddp                                                               ;+=
    fst [entropySum]                                                    ;УЖЕ НОВОЕ ЗНАЧЕНИЕ В entropySum
    fldz                                                                ;В СТЕК 0
    fstp [entropyMassiv+esi]                                            ; = 0 УЖЕ ИСПОЛЬЗОВАННЫЙ ЭЛЕМЕНТ
nextElement:
    add esi,4                                                           ;СЛЕД ЭЛЕМЕНТ
    inc [buff5]                                                         ;СЧЕТЧИК +1
    .if [buff5]<256                                                     ;ЕСЛИ ОН <256
       finit                                                            ;ОЧИЩАЕМ СТЕК
       jmp calculateEntropy                                             ;СЧИТАЕМ ЭНТРОПИЮ ДЛЯ СЛЕД ЭЛЕМЕНТА
    .endif
    cinvoke printf,"            Entropy this section: "
    cinvoke printf,"%f",dword [entropySum],dword [entropySum+4]         ;ВЫВОДИМ ЭНТРОПИЮ СЕКЦИИ
    fld [forCmpEntropy]
    fcomp                                                                ;сравниваем st(0)(текущий элемент массива/sizeOfRawData) с 0
    fstsw ax                                                            ;сохраняет текущее значение регистров SR в AX
    sahf                                                                ;загружает флаги SF, ZF, AF, PF, CF из регистра ah (позволяет работаь как с обычным cmp)
      jb entropyMore                                                   ;st(0)<0? -> nextElement
m1:
    fldz                                                                ;0 В СТЕК
    fstp [entropySum]                                                   ;0 В entropySum (ТАКИМ ОБРАЗОМ ОЧИЩАЕМ)
;ИЩЕМ ТОЧКУ ВХОДА
    mov eax, [addressEntPnt]
    .if   [virtualAddress] < eax                                        ;если виртуальынй адрес меньше адреса, на который указывается addressEntPnt
        mov ebx,[buff]                                                  ;то это та секция, на которую указывает AddressOfEntryPoint
        mov [EntrPointSection],ebx
    .endif

    cinvoke fseek,[FP],[buff2],0
sizeRawDataZero:
    cinvoke fseek,[FP],12,1                                             ;переход на след секцию
    cinvoke puts,crlf

    inc [buff]
    mov eax,[numsection]
    .if [buff]< eax
        jmp markerSectionLoop
    .endif

    ;------------------------------------АНАЛИЗ
    cinvoke puts,crlf
    cinvoke puts,crlf
    cinvoke printf,"%d",[EntrPointSection]
    cinvoke printf," - this section is indicated by an entry point"
    cinvoke puts,crlf
    cinvoke puts,crlf
    cinvoke printf,"Suspicious functions: "
    cinvoke puts,crlf

    ;ТАБЛИЦА ИМПОРТА
    mov [buff6],0
    cinvoke puts,crlf
nextDll:
    cinvoke fseek,[FP],[rawImportTable],0                                           ;ставим метку на первый _IMAGE_IMPORT_DESCRIPTOR
    cinvoke fread,buff2,1,4,[FP]                                                    ;rva до Import Name Table
    .if [buff2] = 0h
        jmp exitProg
    .endif
    macroRwa buff2
    pop [buff4]                                                                     ;rwa до начала Import Name Table
nextRvaFunc:
    cinvoke fseek,[FP],[buff4],0                                                    ;ставим указатель на начало Import Name Table
    cinvoke fread,buff3,1,4,[FP]                                                    ;получаем rva на структуру Import Name Table
    .if [buff3]=0h                                                                  ;если она = 0 (конец rva ф-ий - 4байта = 0 )
        add [rawImportTable],20                                                     ;+20
        jmp nextDll
    .endif
   macroRwa buff3
    pop ebx
    add ebx,2
    cinvoke fseek,[FP],ebx,0                                                         ;метка на структуру с hint(2 байта )и имя функции
    cld
    mov edi,buffName
    cld
readNameFunc:
    cinvoke fread,buff5,1,1,[FP]                                                     ;читаем байт
    mov eax, [buff5]
    stosb
    .if [buff5]<> 100h                                                               ;если он != 0
        inc dl
        jmp readNameFunc                                                             ;то читаем след элемент
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


    add [buff4],4                                                                    ;добавляем 4 байт
    jmp nextRvaFunc                                                                  ;читаем след rva функции


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