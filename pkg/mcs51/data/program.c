#ifdef __SDCC_ds390
#include <ds80c390.h>
#else
#include <8051.h>
#endif
unsigned char __sdcc_external_startup(void){return 0;}
volatile __data unsigned char total;
unsigned char mix(unsigned char a,unsigned char b){unsigned char s=0;for(unsigned char i=0;i<9;i++){if(a&1)s+=b;else s^=a;a=(a<<1)|1;}return s;}
void main(void){total=mix(17,3);for(;;){}}
