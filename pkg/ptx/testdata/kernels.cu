extern "C" {
__attribute__((device)) unsigned helper(unsigned x) { return (x<<7)^(x>>3); }
__attribute__((global)) void vector(float *out, const float *a,const float *b,unsigned n) {
 unsigned i=__nvvm_read_ptx_sreg_tid_x()+__nvvm_read_ptx_sreg_ctaid_x()*__nvvm_read_ptx_sreg_ntid_x();
 if(i<n)out[i]=a[i]*2.0f+b[i];
}
__attribute__((global)) void integer(unsigned *out,unsigned n) {unsigned i=__nvvm_read_ptx_sreg_tid_x();if(i<n){unsigned a=out[i];out[i]=helper(a)+__builtin_popcount(a);}}
}
