#include <openssl/des.h>    
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DES_BLOCK_SIZE 8


FILE *fp;
FILE *rp;
FILE *op;
size_t count;   
char * buffer;
int bytes_read, bytes_written;
unsigned char indata[DES_BLOCK_SIZE]; 
unsigned char outdata[DES_BLOCK_SIZE];

DES_cblock cb1 = { 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE };
DES_cblock cb2 = { 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE };
DES_cblock cb3 = { 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE };

DES_key_schedule ks1;
DES_key_schedule ks2;
DES_key_schedule ks3;

DES_cblock cblock = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

void encrypt(){ 
  DES_set_odd_parity(&cblock);


      fp=fopen("input.txt","a+b");
      op=fopen("output.txt","w");
      if (fp==NULL) {fputs ("File error",stderr); exit (1);}   
      if (op==NULL) {fputs ("File error",stderr); exit (1);}      

while (1) {     

    bytes_read = fread(indata, 1, DES_BLOCK_SIZE, fp); 

    DES_ede3_cbc_encrypt(indata, outdata, DES_BLOCK_SIZE, &ks1, &ks2, &ks3,&cblock, 1);
    bytes_written = fwrite(outdata, 1, bytes_read, op); 
    if (bytes_read < DES_BLOCK_SIZE) 
    break; 
  }   

  fclose (fp); 
  fclose (op);
  free (buffer); 
}

void decrypt(){
  //Opening files where text cipher text is read and the plaintext recovered   
  memset(cblock,0,sizeof(DES_cblock));      
  DES_set_odd_parity(&cblock);

  rp=fopen("recovered.txt","w");
  op=fopen("output.txt","a+b");
  if (rp==NULL) {fputs ("File error",stderr); exit (1);}   
  if (op==NULL) {fputs ("File error",stderr); exit (1);} 

  //Initializing the encryption KEY
  while (1) {     

    bytes_read = fread(indata, 1, DES_BLOCK_SIZE, op);

    DES_ede3_cbc_encrypt(indata, outdata, DES_BLOCK_SIZE, &ks1, &ks2, &ks3, &cblock,0);
    bytes_written = fwrite(outdata, 1, bytes_read, rp); 
    if (bytes_read < DES_BLOCK_SIZE)
    break; 
    }   
  fclose (rp); 
  fclose (op);
  free (buffer); 
}

int main() {

  encrypt();
  decrypt();  
  return 0;
}
