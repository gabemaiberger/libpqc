typedef struct {
long double x;
long double y;
} point;

typedef struct {
long double h_p;
long double k_p;
long double h_q;
long double k_q;
} isogeny;

unsigned char sidh_generate_parameters();
unsigned char sidh_generate_isogeny();
long double *sidh_compute_key();
long double generate_prime(long double w_a, long double w_b, long double e_a, long double e_b, long double f);
long double j_invariant(long double a, long double b);

extern point p_a;
extern point q_a;
extern point p_b;
extern point q_b;

extern point p_aphi;
extern point q_aphi;
extern point p_bphi;
extern point q_bphi;
