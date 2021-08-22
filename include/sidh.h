/*
Supersingular Isogeny Diffie Hellman (SIDH) Key Exchange
Copyright (C) 2017-2021 Gabriel Nathan Maiberger

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
long double h_p;
long double k_p;
long double h_q;
long double k_q;
} isogeny;

unsigned char sidh_generate_parameters();
unsigned char sidh_generate_isogeny();
long double sidh_compute_key();
long double generate_prime(long double w_a, long double w_b, long double e_a, long double e_b, long double f);
long double j_invariant(long double a, long double b);

extern curve E_0;
extern curve E_A;
extern curve E_B;

extern point p_a;
extern point q_a;
extern point p_b;
extern point q_b;

extern point p_aphi;
extern point q_aphi;
extern point p_aphipb;
extern point q_aphiqb;
extern point p_bphi;
extern point q_bphi;
