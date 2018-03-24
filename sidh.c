/*
Supersingular Isogeny Diffie Hellman (SIDH) Key Exchange
Copyright (C) 2017-2018 Gabriel Nathan Maiberger

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
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
long double h;
long double k;
} curve;

typedef struct {
long double x;
long double y;
} isogeny;

unsigned char sidh_generate_parameters();
unsigned char sidh_generate_isogeny();
long double sidh_compute_key();
long double generate_prime(long double w_a, long double w_b, long double e_a, long double e_b, long double f);
long double j_invariant(long double a, long double b);

long double prime;
long double w_a=2;
long double w_b=3;
long double e_a=63;
long double e_b=41;
long double f=11;

curve E_0;
curve E_A;
curve E_B;

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

	E_0=(curve){1,1,0,0};

	struct timeval tm1;
	gettimeofday(&tm1, NULL);
	srand48(tm1.tv_sec+tm1.tv_usec);
	long double x1=lrand48();

	gettimeofday(&tm1, NULL);
	srand48(tm1.tv_sec+tm1.tv_usec);
	long double x2=lrand48();

	long double y1=sqrt(fmod((powl(x1, 3)+(E_0.a*x1)+E_0.b), powl(prime,2)));
	long double y2=sqrt(fmod((powl(x2, 3)+(E_0.a*x2)+E_0.b), powl(prime,2)));

	p_a=(point){x1,y1};
	q_a=(point){x2,y2};
}

unsigned char sidh_generate_isogeny(){
	struct timeval tm2;
	gettimeofday(&tm2, NULL);
	srand48(tm2.tv_sec+tm2.tv_usec);
	m_a=fmod(lrand48(), powl(w_a, e_a));
	n_a=fmod(lrand48(), powl(w_a, e_a));

	r_a=(point){m_a*p_a.x+n_a*q_a.x, m_a*p_a.y+n_a*q_a.y};

	long double g_px=3*powl(r_a.x, 2)+E_0.a;
	long double g_py=(-2*r_a.y);
	long double v_p=2*g_px;
	long double u_p=powl(g_py, 2);

	long double v;
	long double w;

	int i;
	for(i=0; i<w_a; i++){
		v+=v_p;
		w+=u_p+r_a.x*v_p;
	}

	long double sum_x;
	long double sum_y;

	for(i=0; i<e_a; i++){
		sum_x+=(v_p/(E_0.h-r_a.x))-(u_p/powl(E_0.h-r_a.x, 2));
		sum_y+=(2*u_p*E_0.k/powl(E_0.h-r_a.x, 3))+v_p*((E_0.k-r_a.y-g_px*g_py)/powl(E_0.h-r_a.x, 2));
	}

	phi=(isogeny){r_a.x+sum_x, r_a.y-sum_y};

	E_A=(curve){(E_0.a-5*v), (E_0.b-7*w), r_a.x, r_a.y};

	p_aphi=(point){p_b.x+phi.x, p_b.y+phi.y};
	q_aphi=(point){q_b.x+phi.x, q_b.y+phi.y};
}

long double sidh_compute_key(){
	s_ba=(point){m_a*p_bphi.x+n_a*q_bphi.x, m_a*p_bphi.y+n_a*q_bphi.y};

	/*printf("r_a: %Lf, ", r_a.x);
	printf("%Lf\n", r_a.y);

	printf("s_ba: %Lf, ", s_ba.x);
	printf("%Lf\n", s_ba.y);*/

	long double g_px=3*powl(s_ba.x, 2)+E_B.a;
	long double g_py=(-2*s_ba.y);
	long double v_p=2*g_px;
	long double u_p=powl(g_py, 2);

	long double v;
	long double w;

	int i;
	for(i=0; i<w_a; i++){
		v+=v_p;
		w+=(u_p+s_ba.x*v_p);
	}

	long double sum_x;
	long double sum_y;

	for(i=0; i<e_a; i++){
		sum_x+=(v_p/(E_B.h-s_ba.x))-(u_p/powl(E_B.h-s_ba.x, 2));
		sum_y+=(2*u_p*E_B.k/powl(E_B.h-s_ba.x, 3))+v_p*((E_B.k-s_ba.y-g_px*g_py)/powl(E_B.h-s_ba.x, 2));
	}

	psi=(isogeny){s_ba.x+sum_x, s_ba.y-sum_y};

	curve E_BA=(curve){(E_B.a-5*v), (E_B.b-7*w), s_ba.x, s_ba.y};

	/*printf("g_px: %Lf\n", g_px);
	printf("g_py: %Lf\n", g_py);

	printf("v_p: %Lf\n", v_p);
	printf("u_p: %Lf\n", u_p);

	printf("v: %Lf\n", v);
	printf("w: %Lf\n", w);

	printf("psi: %Lf, ", psi.x);
	printf("%Lf\n", psi.y);

	printf("E_A: %Lf, ", E_A.a);
	printf("%Lf\n", E_A.b);
	printf("%Lf, ", E_A.h);
	printf("%Lf\n", E_A.k);

	printf("E_B: %Lf, ", E_B.a);
	printf("%Lf\n", E_B.b);
	printf("%Lf, ", E_B.h);
	printf("%Lf\n", E_B.k);

	printf("E_BA: %Lf, ", E_BA.a);
	printf("%Lf\n", E_BA.b);
	printf("%Lf, ", E_BA.h);
	printf("%Lf\n", E_BA.k);*/

	long double key=j_invariant(E_BA.a, E_BA.b);

	printf("%Lf\n", key);

	return key;
}

long double generate_prime(long double w_a, long double w_b, long double e_a, long double e_b, long double f){
	long double p=powl(w_a, e_a)*powl(w_b,e_b)*f-1;
	return p;
}

long double j_invariant(long double a, long double b){
	long double j=(1728*((4*powl(a, 3))/((4*powl(a, 3))*(27*powl(b, 2)))));
	return j;
}
