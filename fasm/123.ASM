format   PE64
include  'win64a.inc'
include  'INCLUDE\MACRO\IF.INC'
entry    start

section '.data' data readable writeable
;------

fName     db  'C:\Users\admin\Desktop\peAnalyzerSoft\peFIles\run_pe64.exe',0        ; ��� �����
buff      dd  ?                                                                        ; ����� ��� ������
hOut      dd  ?                                                                        ; ���������� ������
hFile     dd  ?                                                                        ; ���������� �����
PeSig     dd  ?                                                                        ; ������ pe ���������

section '.text' code readable executable
;------
start:  invoke GetStdHandle,STD_OUTPUT_HANDLE                                                           ;�������� ���������� ������ � �������
        mov [hOut],eax

        invoke  CreateFileA,fName,GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_ARCHIVE,0               ;��������� ����
        mov     [hFile],eax                                                                             ;�������� ��� ����������
        cmp eax, INVALID_HANDLE_VALUE                                                                   ;��������� ���������� �� ����������
            je errorExit

        invoke ReadFile,[hFile],buff,2,0,0                                                              ;��������� ������ 2� �����(e_magic)
        cmp [buff],5a4dh                                                                                ;���� !=mz, �� notPe
            jne notPe

        invoke SetFilePointer,[hFile],3ch,0,FILE_BEGIN                                                  ;�������� ����� ������ pe ��������� (e_lfanew)
        invoke ReadFile,[hFile],buff,4,0,0
        ;invoke WriteConsoleA,[hOut],buff,5,0,0

        mov eax,[buff]                                                                                  ;������ pe ��������� � ��������,��� ��� pe file
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
;������������������������������������
section '.idata' import data readable

  library kernel, 'KERNEL32.DLL'

  import  kernel,\                     ; API ��� ������� �� ������32.
             CreateFileA,'CreateFileA',\
             ReadFile,'ReadFile',\
             Sleep,'Sleep',\
             ExitProcess,'ExitProcess',\
             GetStdHandle,'GetStdHandle',\
             WriteConsoleA,'WriteConsoleA',\
             SetFilePointer,'SetFilePointer'