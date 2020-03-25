format PE console 5.0
include 'win32ax.inc'
include 'INCLUDE\MACRO\IF.INC'
entry    start

     macro macroPrint str,[perem]
     {
        cinvoke puts,crlf
        cinvoke printf,"    "
        cinvoke printf,str
        cinvoke printf," - "
        cinvoke printf,tpt,[perem]
     }
section '.data' data readable writeable
        ;–ј«Ќќ≈
        buff          dd      ?              ;секци€, на которую указывает addressOfEntryPoint
        buff2         dd      ?              ;храним начало след секции
        buff3         dd      ?
        buff4         dd      ?              ;в цикле , где считаетс€ энтропи€ секций. под переменную
        FP            dd      ?
        mode          db      'rb',0
        fName         db      'C:\Users\admin\Desktop\peAnalyzerSoft\peFIles\run_pe64.exe',0
        tpt           db      '0x%0X ',0
        tpn           db      '%s',0
        buf           dd      ?
        hOut          dd      ?
        crlf    =   $ - 1

        ;DOS HEADER
        e_magic               dd      ?       ;об€зательна€ сигнатура pe файла
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

        ;“јЅЋ»÷ј —≈ ÷»…
        name                  dq      ?
        virtualSize           dd      ?
        virtualAddress        dd      ?
        sizeOfRawData         dd      ?
        pointerToRawData      dd      ?
        pointerToRelocations  dd      ?

        ;ƒЋя јЌјЋ»«ј
         EntrPointSection     dd      ?
         entropyMassiv        dd      256 dup(?)

section '.text' code readable executable
start:


    invoke  fopen,fName, mode ;O_RDONLY or O_BINARY
    mov [FP], eax
    ;--------------------------DOS HEADER
    invoke  fread,  e_magic, 1,2, [FP]                                                  ;считываем 1е 2а байта(e_magic)
    cmp [e_magic], 5a4dh                                                                ;проверка, точно ли это pe file?
        jne notPe
    cinvoke printf,"FILE INFO"
    cinvoke puts,crlf
    cinvoke printf,"[DOS Header]"
    macroPrint "e_magic",e_magic

    cinvoke fseek,[FP],3ch,0                                                            ;ставим метку туда, где находитс€ e_lfanew(указывает на начало pe секции)
    invoke fread,e_lfanew,1,4,[FP]                                                      ;читаем эти 4 байта
    macroPrint "e_lfanew",e_lfanew

    ;--------------------------PE HEADER
    cinvoke puts,crlf
    cinvoke puts,crlf
    cinvoke printf,"[PE Header]"
    cinvoke fseek,[FP],[e_lfanew],0                                                     ;ставим метку на начало pe секции
    invoke fread,signature,1,4,[FP]                                                           ;читаем эти 4 байта
    cmp [signature],4550h                                                                     ;если они = 4550h, то ок, это pe file. ещЄ одна проверка
        jne notPe
    macroPrint "Signature",signature

    ;--------------------------FILE HEADER
    cinvoke puts,crlf
    cinvoke puts,crlf
    cinvoke printf,"[File Header]"

    invoke fread,machine,1,2,[FP]
    macroPrint "Machine",machine
    invoke fread,numsection,1,2,[FP]
    macroPrint  "NumberOfSections",numsection

    cinvoke fseek,[FP],12,1
    invoke fread,sizeopthead,1,2,[FP]
    macroPrint "SizeOfOptionalHeader",sizeopthead

    invoke fread,characteristic,1,2,[FP]
    macroPrint  "Characteristics",characteristic


    ;--------------------------OPTIONAL HEADER
    cinvoke puts,crlf
    cinvoke puts,crlf
    cinvoke printf,"[Optional Header]"

    invoke fread,magic,1,2,[FP]
    macroPrint "Magic",magic

    cinvoke fseek,[FP],14,1
    invoke fread,addressEntPnt,1,4,[FP]
    macroPrint "AddressOfEntryPoint",addressEntPnt

    .if [magic] = 20bh                                                          ;если файла 64 битный, то ImageBase = 8 байт.
        cinvoke puts,crlf
        cinvoke fseek,[FP],4,1
        invoke fread,imageBase,1,4,[FP]
        invoke fread,imageBaseHalf,1,4,[FP]
        cinvoke printf,"    ImageBase - "
        cinvoke printf,"0x%x",[imageBaseHalf]
        cinvoke printf,"%x",[imageBase]
    .else                                                                       ;иначе ImageBase = 4 байта
        cinvoke fseek,[FP],8,1
        invoke fread, imageBase,1,4,[FP]
        macroPrint "ImageBase",imageBase
    .endif

    invoke fread,sectionAlignm,1,4,[FP]
    macroPrint "SectionAlignment",sectionAlignm

    invoke fread,fileAlignm,1,4,[FP]
    macroPrint "FileAlignment",fileAlignm

    cinvoke fseek,[FP],6,1
    invoke fread,majorSybVersion,1,2,[FP]
    macroPrint "MajorSubsystemVersion",majorSybVersion

    cinvoke fseek,[FP],8,1
    invoke fread,sizeImage,1,4,[FP]
    macroPrint "SizeOfImage",sizeImage
    cinvoke ftell,[FP]
    mov [buff2],eax
    cinvoke printf,tpt,buff2

    invoke fread,sizeHeader,1,4,[FP]
    macroPrint "SizeHeader",sizeHeader

    cinvoke fseek,[FP],4,1
    invoke fread,subSystem,1,2,[FP]
    macroPrint "Subsystem",subSystem

    .if [magic] = 20bh                                                          ;если файл 64 бит, переходим на 38 байта вперЄд
       cinvoke fseek,[FP],38,1
    .else
       cinvoke fseek,[FP],22,1                                                  ;в ином случае 22 байта
    .endif
    invoke fread,numberOfRvaAndSizes,1,4,[FP]
    macroPrint "NumberOfRvaAndSizes",numberOfRvaAndSizes

    ;---------------¬џ„»—Ћя≈ћ —ћ≈ў≈Ќ»≈ ƒќ “јЅЋ»÷џ —≈ ÷»…
    mov eax,[numberOfRvaAndSizes]                                               ;чмсло каталогов в массиве DataDirectory
    mov ebx,8                                                                   ;8. т.к. в структуре _IMAGE_DATA_DIRECTORY  2а элемента по 4 байта
    mul ebx
    mov ebx,eax

    ;---------------„»“ј≈ћ “јЅЋ»÷” —≈ ÷»…
    cinvoke puts,crlf
    cinvoke puts,crlf
    cinvoke printf,"[Section Table]"
    cinvoke fseek,[FP],ebx,1

    mov [buff],0
markerSectionLoop:
    cinvoke puts,crlf
    invoke fread,name,1,8,[FP]
    cinvoke printf,"    Name - "
    cinvoke printf,name

    invoke fread,virtualSize,1,4,[FP]
    macroPrint "VirtualSize",virtualSize

    invoke fread,virtualAddress,1,4,[FP]
    macroPrint "VirtualAddress",virtualAddress

    invoke fread,sizeOfRawData,1,4,[FP]
    macroPrint "SizeOfRawData",sizeOfRawData

    invoke fread,pointerToRawData,1,4,[FP]
    macroPrint "PointerToRawData",pointerToRawData

    invoke fread,pointerToRelocations,1,4,[FP]
    macroPrint "PointerToRelocations",pointerToRelocations

    cinvoke ftell,[FP]                                                  ;запоминаем, где мы остановились
    mov [buff2],eax

    cinvoke fseek,[FP],[pointerToRawData],0                             ;переходим к данным данной секции
    ;mov eax,[sizeOfRawData]
    ;mov [buff4],eax
    cinvoke puts,crlf

entropyloop:
    cinvoke fread,buff3,1,1,[FP]
    cinvoke printf,"%X ",[buff3]
    inc [buff4]
    mov eax,[sizeOfRawData]
    .if [buff4]<eax
       jmp  entropyloop
    .endif
    mov [buff4],0

    mov eax, [addressEntPnt]
    .if   [virtualAddress] < eax
        mov ebx,[buff]
        mov [EntrPointSection],ebx
    .endif

    cinvoke puts,crlf
    cinvoke fseek,[FP],[buff2],0
    cinvoke fseek,[FP],12,1                                             ;переход на след секцию

    inc [buff]
    mov eax,[numsection]
    cmp [buff],eax
        jb markerSectionLoop

    ;------------------------------------јЌјЋ»«
    cinvoke puts,crlf
    cinvoke puts,crlf
    cinvoke printf,"ANALYSIS"
    cinvoke puts,crlf
    cinvoke puts,crlf
    cinvoke printf,"%d",[EntrPointSection]
    cinvoke printf," - na ety section ykazivaet addressOfEntryPoint"




    invoke _getch
    invoke  exit, 0

notPe:
    cinvoke puts,crlf
    cinvoke printf,"not pe file"

    invoke _getch
    invoke  exit, 0
; import data in the same section
section '.idata' import data readable
 library  msvcrt,'MSVCRT.DLL'
 
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
    fseek,'fseek'