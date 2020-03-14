format PE console 5.0
include 'win32ax.inc'
include 'INCLUDE\MACRO\IF.INC'
entry    start

section '.data' data readable writeable
        FP            dd      ?
        mode          db      'rb',0
        fName         db      'C:\Users\admin\Desktop\peAnalyzerSoft\peFIles\run_pe64.exe',0
        tpt           db      '0x%0X ',0
        buf           dd      ?
        hOut          dd      ?
        crlf    =   $ - 1

        ;DOS HEADER
        e_magic       dd      ?       ;об€зательна€ сигнатура pe файла
        e_lfanew      dd      ?       ;начало pe заголвока

        ;PE HEADER
        signature     dd      ?

        ;FILE HEADER
        machine               dd      ?
        numsection            dd      ?
        sizeopthead           dd      ?
        characteristic        dd      ?

section '.text' code readable executable
start:
    invoke GetStdHandle,STD_OUTPUT_HANDLE                                                           ;???????? ?????????? ?????? ? ???????
        mov [hOut],eax

    invoke  fopen,fName, mode ;O_RDONLY or O_BINARY
    mov [FP], eax

    ;--------------------------DOS HEADER
    invoke WriteConsoleA,[hOut],"[DOS Header]",12,0,0
    cinvoke puts,crlf
    invoke  fread,  e_magic, 1,2, [FP]                                                  ;считываем 1е 2а байта(e_magic)
    cmp [e_magic], 5a4dh                                                                ;проверка, точно ли это pe file?
        jne notPe
    invoke WriteConsoleA,[hOut],"       e_magic - ",17,0,0
    cinvoke printf,tpt,[e_magic]

    cinvoke fseek,[FP],3ch,0                                                            ;ставим метку туда, где находитс€ e_lfanew(указывает на начало pe секции)
    invoke fread,e_lfanew,1,4,[FP]                                                      ;читаем эти 4 байта
    cinvoke puts,crlf
    invoke WriteConsoleA,[hOut],"       e_lfanew - ",18,0,0
    cinvoke printf,tpt,[e_lfanew]

    ;--------------------------PE HEADER
    cinvoke puts,crlf
    cinvoke puts,crlf
    invoke WriteConsoleA,[hOut],"[PE Header]",11,0,0
    cinvoke fseek,[FP],[e_lfanew],0                                                     ;ставим метку на начало pe секции
    invoke fread,signature,1,4,[FP]                                                           ;читаем эти 4 байта
    cmp [signature],4550h                                                                     ;если они = 4550h, то ок, это pe file. ещЄ одна проверка
        jne notPe
    cinvoke puts,crlf
    invoke WriteConsoleA,[hOut],"       Signature - ",19,0,0
    cinvoke printf,tpt,[signature]

    ;--------------------------FILE HEADER
    cinvoke puts,crlf
    cinvoke puts,crlf
    invoke WriteConsoleA,[hOut],"       [FILE HEADER]",20,0,0

    invoke fread,machine,1,2,[FP]
    cinvoke puts,crlf
    invoke  WriteConsoleA,[hOut],"              Machine - ",24,0,0
    cinvoke printf,tpt,[machine]

    invoke fread,numsection,1,2,[FP]
    cinvoke puts,crlf
    invoke  WriteConsoleA,[hOut],"              NumberOfSections - ",33,0,0
    cinvoke printf,tpt,[numsection]

    cinvoke fseek,[FP],12,1
    invoke fread,sizeopthead,1,2,[FP]
    cinvoke puts,crlf
    invoke  WriteConsoleA,[hOut],"              SizeOfOptionalHeader - ",37,0,0
    cinvoke printf,tpt,[sizeopthead]

    invoke fread,characteristic,1,2,[FP]
    cinvoke puts,crlf
    invoke  WriteConsoleA,[hOut],"              Characteristics - ",32,0,0
    cinvoke printf,tpt,[characteristic]

notPe:
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