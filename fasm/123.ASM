format PE console 5.0
include 'win32ax.inc'
include 'INCLUDE\MACRO\IF.INC'
entry    start

section '.data' data readable writeable
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
        sizeImage             dd      ?         ;sizeOfUmage
        sizeHeader            dd      ?         ;sizeOfHeader
        subSystem             dd      ?
        numberOfRvaAndSizes   dd      ?

        ;“јЅЋ»÷ј —≈ ÷»…
        name                  dq      ?


section '.text' code readable executable
start:
    invoke GetStdHandle,STD_OUTPUT_HANDLE                                                           ;???????? ?????????? ?????? ? ???????
        mov [hOut],eax

    invoke  fopen,fName, mode ;O_RDONLY or O_BINARY
    mov [FP], eax

    ;--------------------------DOS HEADER
    cinvoke printf,"[DOS Header]"
    cinvoke puts,crlf
    invoke  fread,  e_magic, 1,2, [FP]                                                  ;считываем 1е 2а байта(e_magic)
    cmp [e_magic], 5a4dh                                                                ;проверка, точно ли это pe file?
        jne notPe
    cinvoke printf,"    e_magic - "
    cinvoke printf,tpt,[e_magic]

    cinvoke fseek,[FP],3ch,0                                                            ;ставим метку туда, где находитс€ e_lfanew(указывает на начало pe секции)
    invoke fread,e_lfanew,1,4,[FP]                                                      ;читаем эти 4 байта
    cinvoke puts,crlf
    cinvoke printf,"    e_lfanew - "
    cinvoke printf,tpt,[e_lfanew]

    ;--------------------------PE HEADER
    cinvoke puts,crlf
    cinvoke puts,crlf
    cinvoke printf,"[PE Header]"
    cinvoke fseek,[FP],[e_lfanew],0                                                     ;ставим метку на начало pe секции
    invoke fread,signature,1,4,[FP]                                                           ;читаем эти 4 байта
    cmp [signature],4550h                                                                     ;если они = 4550h, то ок, это pe file. ещЄ одна проверка
        jne notPe
    cinvoke puts,crlf
    cinvoke printf,"    Signature - "
    cinvoke printf,tpt,[signature]

    ;--------------------------FILE HEADER
    cinvoke puts,crlf
    cinvoke puts,crlf
    cinvoke printf,"[File Header]"

    invoke fread,machine,1,2,[FP]
    cinvoke puts,crlf
    cinvoke printf,"    Machine - "
    cinvoke printf,tpt,[machine]

    invoke fread,numsection,1,2,[FP]
    cinvoke puts,crlf
    cinvoke printf,"    NumberOfSections - "
    cinvoke printf,tpt,[numsection]

    cinvoke fseek,[FP],12,1
    invoke fread,sizeopthead,1,2,[FP]
    cinvoke puts,crlf
    cinvoke printf,"    SizeOfOptionalHeader - "
    cinvoke printf,tpt,[sizeopthead]

    invoke fread,characteristic,1,2,[FP]
    cinvoke puts,crlf
    cinvoke printf,"    Characteristics - "
    cinvoke printf,tpt,[characteristic]


    ;--------------------------OPTIONAL HEADER
    cinvoke puts,crlf
    cinvoke puts,crlf
    cinvoke printf,"[Optional Header]"

    invoke fread,magic,1,2,[FP]
    cinvoke puts,crlf
    cinvoke printf,"    Magic - "
    cinvoke printf,tpt,[magic]

    cinvoke fseek,[FP],14,1
    invoke fread,addressEntPnt,1,4,[FP]
    cinvoke puts,crlf
    cinvoke printf,"    AddressOfEntryPoint - "
    cinvoke printf,tpt,[addressEntPnt]

    cinvoke puts,crlf
    .if [magic] = 20bh                                                          ;если файла 64 битный, то ImageBase = 8 байт.
        cinvoke fseek,[FP],4,1
        invoke fread,imageBase,1,4,[FP]
        invoke fread,imageBaseHalf,1,4,[FP]
        cinvoke printf,"    ImageBase - "
        cinvoke printf,"0x%x",[imageBaseHalf]
        cinvoke printf,"%x",[imageBase]
    .else                                                                       ;иначе ImageBase = 4 байта
        cinvoke fseek,[FP],8,1
        invoke fread, imageBase,1,4,[FP]
        cinvoke printf,"    ImageBase - "
        cinvoke printf,tpt,[imageBase]
    .endif

    invoke fread,sectionAlignm,1,4,[FP]
    cinvoke puts,crlf
    cinvoke printf,"    SectionAlignment - "
    cinvoke printf,tpt,[sectionAlignm]

    invoke fread,fileAlignm,1,4,[FP]
    cinvoke puts,crlf
    cinvoke printf,"    FileAlignment - "
    cinvoke printf,tpt,[fileAlignm]

    cinvoke fseek,[FP],6,1
    invoke fread,majorSybVersion,1,2,[FP]
    cinvoke puts,crlf
    cinvoke printf,"    MajorSubsystemVersion - "
    cinvoke printf,tpt,[majorSybVersion]

    cinvoke fseek,[FP],8,1
    invoke fread,sizeImage,1,4,[FP]
    cinvoke puts,crlf
    cinvoke printf,"    SizeOfImage - "
    cinvoke printf,tpt,[sizeImage]

    invoke fread,sizeHeader,1,4,[FP]
    cinvoke puts,crlf
    cinvoke printf,"    SizeHeader - "
    cinvoke printf,tpt,[sizeHeader]

    cinvoke fseek,[FP],4,1
    invoke fread,subSystem,1,2,[FP]
    cinvoke puts,crlf
    cinvoke printf,"    Subsystem - "
    cinvoke printf,tpt,[subSystem]

    .if [magic] = 20bh                                                          ;если файл 64 бит, переходим на 38 байта вперЄд
       cinvoke fseek,[FP],38,1
    .else
       cinvoke fseek,[FP],22,1                                                  ;в ином случае 22 байта
    .endif
    invoke fread,numberOfRvaAndSizes,1,4,[FP]
    cinvoke puts,crlf
    cinvoke printf,"    NumberOfRvaAndSizes - "
    cinvoke printf,tpt,[numberOfRvaAndSizes]

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

    cinvoke puts,crlf
    invoke fread,name,1,8,[FP]
    cinvoke printf,"    Name - "
    cinvoke printf,name




notPe:
    cinvoke puts,crlf
    invoke WriteConsoleA,[hOut],"not pe",6,0,0

    invoke _getch
    invoke  exit, 0
; import data in the same section
section '.idata' import data readable
 library kernel,'KERNEL32.DLL',\
    msvcrt,'MSVCRT.DLL'
 
 import kernel,\
    GetStdHandle,'GetStdHandle',\
    WriteConsoleA,'WriteConsoleA'
 
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