#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <math.h>

#include <sys/time.h>


typedef struct {
long double x;
long double y;
} point;

typedef struct {
long double a;
long double b;
} curve;

typedef struct {
long double p_h;
long double p_k;
long double q_h;
long double q_k;
} isogeny;

unsigned char sidh_generate_parameters();
unsigned char sidh_generate_isogeny();
long double *sidh_compute_key();
long double generate_prime(long double w_a, long double w_b, long double e_a, long double e_b, long double f);
long double j_invariant(long double a, long double b);

long double prime;
long double w_a=2;
long double w_b=3;
long double e_a=63;
long double e_b=41;
long double f=11;

curve base={1,1};
curve E_0;

point p_a;
point q_a;
point p_b;
point q_b;

point p_aphi;
point q_aphi;
point p_bphi;
point q_bphi;

point r_a;
point s_ba;

long double m_a;
long double n_a;

isogeny phi;
isogeny psi;

unsigned char sidh_generate_parameters(){
	prime=generate_prime(w_a, w_b, e_a, e_b, f);

	E_0=(curve){base.a/prime, base.b/prime};

	struct timeval tm1;
	gettimeofday(&tm1, NULL);
	srand48(tm1.tv_sec+tm1.tv_usec);

	gettimeofday(&tm1, NULL);
	srand48(tm1.tv_sec+tm1.tv_usec);
	long double x1=lrand48();

	gettimeofday(&tm1, NULL);
	srand48(tm1.tv_sec+tm1.tv_usec);
	long double x2=lrand48();

	long double y1=sqrt(powl(x1, 3)+x1);
	long double y2=sqrt(powl(x2, 3)+x2);

	p_a=(point){x1,y1};
	q_a=(point){x2,y2};

	p_bphi=(point){0, 0};
	q_bphi=(point){0, 0};
}

unsigned char sidh_generate_isogeny(){
	struct timeval tm2;
	gettimeofday(&tm2, NULL);
	srand48(tm2.tv_sec+tm2.tv_usec);
	m_a=(long int)lrand48()%((long int)powl(w_a, e_a));

	gettimeofday(&tm2, NULL);
	srand48(tm2.tv_sec+tm2.tv_usec);
	n_a=(long int)lrand48()%((long int)powl(w_a, e_a));

	r_a=(point){m_a*p_a.x+n_a*q_a.x, m_a*p_a.y+n_a*q_a.y};

	p_aphi=(point){p_b.x+r_a.x, p_b.y+r_a.y};
	q_aphi=(point){q_b.x+r_a.x, q_b.y+r_a.y};
}

long double *sidh_compute_key(){
	s_ba=(point){m_a*(p_a.x+p_bphi.x)+n_a*(q_a.x+q_bphi.x), m_a*(p_a.y+p_bphi.y)+n_a*(q_a.y+q_bphi.y)};

	printf("%Lf, ", p_aphi.x);
	printf("%Lf\n", p_aphi.y);
	printf("%Lf, ", p_bphi.x);
	printf("%Lf\n", p_bphi.y);

	printf("%Lf, ", s_ba.x);
	printf("%Lf\n", s_ba.y);

	long double key=j_invariant(s_ba.x, s_ba.y);

	return &key;
}

long double generate_prime(long double w_a, long double w_b, long double e_a, long double e_b, long double f){
	long double p=powl(w_a, e_a)*powl(w_b,e_b)*f-1;
	return p;
}

long double j_invariant(long double a, long double b){
	long double j=1728*((4*powl(a, 3))/((4*powl(a, 3))*(27*powl(b, 2))));
	return j;
}
