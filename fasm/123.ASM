format   PE64
include  'win64a.inc'
include  'INCLUDE\MACRO\IF.INC'
entry    start

section '.data' data readable writeable
;------

fName     db  'C:\Users\admin\Desktop\peAnalyzerSoft\peFIles\run_pe64.exe',0        ; имя файла
buff      dd  ?                                                                        ; текст для записи
hOut      dd  ?                                                                        ; дескриптор вывода
hFile     dd  ?                                                                        ; дескриптор файла
PeSig     dd  ?                                                                        ; начало pe сигнатуры

section '.text' code readable executable
;------
start:  invoke GetStdHandle,STD_OUTPUT_HANDLE                                                           ;получаем дескриптор вывода в консоль
        mov [hOut],eax

        invoke  CreateFileA,fName,GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_ARCHIVE,0               ;открываем файл
        mov     [hFile],eax                                                                             ;запомним его дескриптор
        cmp eax, INVALID_HANDLE_VALUE                                                                   ;проверяем дескриптор на валидность
            je errorExit

        invoke ReadFile,[hFile],buff,2,0,0                                                              ;считываем первый 2а байта(e_magic)
        cmp [buff],5a4dh                                                                                ;если !=mz, то notPe
            jne notPe

        invoke SetFilePointer,[hFile],3ch,0,FILE_BEGIN                                                  ;получаем метку начала pe заголовка (e_lfanew)
        invoke ReadFile,[hFile],buff,4,0,0
        ;invoke WriteConsoleA,[hOut],buff,5,0,0

        mov eax,[buff]                                                                                  ;начало pe сигнатуры и проверка,что это pe file
        mov [PeSig],eax
        invoke SetFilePointer, [hFile],[PeSig],0,FILE_BEGIN
        invoke ReadFile,[hFile],PeSig,4,0,0
        invoke WriteConsoleA,[hOut],PeSig,5,0,0
        cmp [PeSig],4550h
            jne notPe


        ;.if [buff] = 5a4dh  ;
         ; invoke WriteConsoleA,[hOut],"pe",10,10,0
          ;invoke Sleep,5000
       ; .else
        ;   invoke WriteConsoleA,[hOut],"not pe",10,10,0
         ;  invoke Sleep,5000
       ; .endif
        invoke Sleep,5000
       ; invoke ExitProcess,0

errorExit: invoke WriteConsoleA,[hOut],"Error Exit",10,10,0
           invoke Sleep,5000
notPe:     invoke WriteConsoleA,[hOut],"not pe",6,0,0
           invoke Sleep,5000
;пппппппппппппппппппппппппппппппппппп
section '.idata' import data readable

  library kernel, 'KERNEL32.DLL'

  import  kernel,\                     ; API для импорта из кернел32.
             CreateFileA,'CreateFileA',\
             ReadFile,'ReadFile',\
             Sleep,'Sleep',\
             ExitProcess,'ExitProcess',\
             GetStdHandle,'GetStdHandle',\
             WriteConsoleA,'WriteConsoleA',\
             SetFilePointer,'SetFilePointer'