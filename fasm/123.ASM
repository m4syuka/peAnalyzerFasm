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

        e_magic       dd      ?       ;об€зательна€ сигнатура pe файла
        e_lfanew      dd      ?       ;начало pe заголвока
        crlf    =   $ - 1
        hello         db 'Hello world!', 10, 0

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
    invoke printf,tpt,[e_magic]

    cinvoke fseek,[FP],3ch,0                                                            ;ставим метку туда, где находитс€ e_lfanew(указывает на начало pe секции)
    invoke fread,e_lfanew,1,4,[FP]                                                      ;читаем эти 4 байта
    cinvoke puts,crlf
    invoke WriteConsoleA,[hOut],"       e_lfanew - ",19,0,0
    invoke printf,tpt,[e_lfanew]

    cinvoke fseek,[FP],[e_lfanew],0                                                     ;ставим метку на начало pe секции
    invoke fread,buf,1,4,[FP]                                                           ;читаем эти 4 байта
    cmp [buf],4550h                                                                     ;если они = 4550h, то ок, это pe file. ещЄ одна проверка
    cinvoke puts,crlf
    invoke printf,tpt,[buf]


notPe:

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