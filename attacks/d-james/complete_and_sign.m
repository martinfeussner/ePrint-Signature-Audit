/*
  Public-only full d-james-128-q5 post-recovery equivalent signer.

  The input basis file is regenerated from the public Dragon tensor by
  recover.m.  This script loads no secret-key value: it certifies the
  recovered parent code, completes the aa
  block to an equivalent HFE-IP witness, and signs a fresh fixed-RHS message.
*/

load "work/public-data.m";
load "work/recovered-basis.m";
SetOutputFile("work/full-attack-results.txt" : Overwrite := true);

F := GF(q);
e := extension_degree;
ell := code_length;
kpub := public_dimension;
assert parameter_name eq "d-james-128-q5";
assert q eq 5 and e eq 94 and ell eq 73 and kpub eq 111;
assert #AAUpper eq e*(e+1) div 2;
assert #FreshHashes gt 0 and #ChangedHashes gt 0;
assert RecoveredSchema eq "djames-q5-128-public-basis-v1";
assert InputSHA256 eq
  "51c295dbf1ecd9ce77a890b5436391365f919505971f5a1b19e8f17341dc1e3a";
assert RecoveredInputSHA256 eq InputSHA256;
assert #RecoveredModulusCoefficients eq e+1;
assert #RecoveredGammaCoords eq e;
assert #RecoveredTraceTCoords eq ell;

t_start := Cputime();
PF<xx> := PolynomialRing(F);
field_modulus := PF!RecoveredModulusCoefficients;
assert IsIrreducible(field_modulus);
K<alpha> := ext<F|field_modulus>;
power_basis := [K!1] cat [alpha^i : i in [1..e-1]];
function FromCoords(coords)
    return &+[K!(F!coords[i])*power_basis[i] : i in [1..e]];
end function;
gamma := [FromCoords(row) : row in RecoveredGammaCoords];
trace_t := [FromCoords(row) : row in RecoveredTraceTCoords];
gamma_coords := Matrix(F,e,e,&cat RecoveredGammaCoords);
trace_t_coords := Matrix(F,ell,e,&cat RecoveredTraceTCoords);
assert Rank(gamma_coords) eq e;
assert Rank(trace_t_coords) eq ell;

/* gamma is trace-dual to the recovered primal X-basis sigma. */
gram := Matrix(F,e,e,
    &cat [ [ Trace(gamma[i]*power_basis[c],F) : c in [1..e] ]
           : i in [1..e] ]);
assert Rank(gram) eq e;
gram_inv := gram^-1;
sigma := [ &+[ K!(gram_inv[c,j])*power_basis[c] : c in [1..e] ]
           : j in [1..e] ];
assert Matrix(F,e,e,
    &cat [ [ Trace(gamma[i]*sigma[j],F) : j in [1..e] ]
           : i in [1..e] ]) eq IdentityMatrix(F,e);

/* Public certificate that the supplied basis unexpands the cross tensor to
   a two-dimensional generalized Gabidulin parent with evaluation vector t. */
unexpanded := Matrix(K,kpub,ell,
    &cat [ [ &+[ gamma[i]*K!(F!PublicFlat[s][(i-1)*ell+j])
                  : i in [1..e] ]
             : j in [1..ell] ]
           : s in [1..kpub] ]);
parent_space := RowSpace(unexpanded);
assert Dimension(parent_space) eq 2;
assert Vector(K,trace_t) in parent_space;
printf "basis_load_and_public_certificate_seconds=%.6o recovery_schema=%o gamma_rank=%o parent_dimension=%o output_trace_rank=%o\n",
       Cputime(t_start),RecoveredSchema,Rank(gamma_coords),
       Dimension(parent_space),Rank(trace_t_coords);

/* ---------- public aa polar operators ---------- */

function AAIndex(i,j,n)
    if i gt j then
        tmp := i; i := j; j := tmp;
    end if;
    return ((i-1)*(2*n-i+2)) div 2 + (j-i) + 1;
end function;

moore := Matrix(K,e,e,
    &cat [ [ sigma[i]^(q^s) : s in [0..e-1] ] : i in [1..e] ]);
assert Rank(moore) eq e;
moore_solve := Transpose(moore)^-1;
all_images := [];
first_linearized := [];
gamma_scaled := [[K!c*gamma[j] : j in [1..e]] : c in [0..q-1]];
for out in [1..ell] do
    images := [];
    for i in [1..e] do
        image := K!0;
        for j in [1..e] do
            c := F!AAUpper[AAIndex(i,j,e)][out];
            if i eq j then c *:= 2; end if;
            if c ne 0 then
                image +:= gamma_scaled[Integers()!c+1][j];
            end if;
        end for;
        Append(~images,image);
    end for;
    if out eq 1 then
        first_linearized := Eltseq(Vector(K,images)*moore_solve);
        assert [ &+[ first_linearized[s+1]*sigma[i]^(q^s)
                      : s in [0..e-1] ] : i in [1..e] ] eq images;
    end if;
    Append(~all_images,images);
end for;

/* Rank-decode L_t = H_t + E_t.  H_t has q-support {-1,0,1}; E_t
   has image rank at most 2r=4.  An image-space annihilator

       V(Y)=v_0 Y+...+v_3 Y^(q^3)+Y^(q^4)

   gives a cyclic recurrence on the known linearized coefficients. */
function DecodeSparsePlusRankFour(lcoeff)
    rerr := 4;
    special := {@ e-1,0,1 @};
    rows := [];
    rhs := [];
    for k in [0..e-1] do
        good := true;
        for j in [0..rerr] do
            if ((k-j) mod e) in special then good := false; end if;
        end for;
        if good then
            Append(~rows,[ lcoeff[((k-j) mod e)+1]^(q^j)
                           : j in [0..rerr-1] ]);
            Append(~rhs,-lcoeff[((k-rerr) mod e)+1]^(q^rerr));
        end if;
    end for;
    recmat := Matrix(K,#rows,rerr,&cat rows);
    recvec := Eltseq(Solution(Transpose(recmat),Vector(K,rhs)));
    vcoeff := recvec cat [K!1];
    assert &and [ &+[ vcoeff[j+1]*lcoeff[((k-j) mod e)+1]^(q^j)
                       : j in [0..rerr] ] eq 0
                  : k in [0..e-1]
                  | &and [ not (((k-j) mod e) in special)
                            : j in [0..rerr] ] ];

    /* Recover the three erased error coefficients via F_q-linear algebra. */
    erows := [];
    erhs := [];
    for k in [0..e-1] do
        known := K!0;
        effects := [K!0 : z in [1..3*e]];
        for j in [0..rerr] do
            idx := (k-j) mod e;
            if idx in special then
                block := Index(special,idx)-1;
                for c in [1..e] do
                    effects[block*e+c] +:= vcoeff[j+1]*power_basis[c]^(q^j);
                end for;
            else
                known +:= vcoeff[j+1]*lcoeff[idx+1]^(q^j);
            end if;
        end for;
        effect_coords := [Eltseq(z) : z in effects];
        known_coords := Eltseq(-known);
        for d in [1..e] do
            Append(~erows,[F!effect_coords[z][d] : z in [1..3*e]]);
            Append(~erhs,F!known_coords[d]);
        end for;
    end for;
    emat := Matrix(F,#erows,3*e,&cat erows);
    esol := Eltseq(Solution(Transpose(emat),Vector(F,erhs)));
    error_coeff := lcoeff;
    for block in [0..2] do
        idx := special[block+1];
        error_coeff[idx+1] := &+[ K!esol[block*e+c]*power_basis[c]
                                  : c in [1..e] ];
    end for;
    assert &and [ &+[ vcoeff[j+1]*error_coeff[((k-j) mod e)+1]^(q^j)
                       : j in [0..rerr] ] eq 0 : k in [0..e-1] ];
    hcoeff := [lcoeff[i]-error_coeff[i] : i in [1..e]];
    assert &and [hcoeff[i+1] eq 0 : i in [2..e-2]];
    return hcoeff,error_coeff;
end function;

t_decode := Cputime();
hcoeff,error_coeff := DecodeSparsePlusRankFour(first_linearized);
lambda0 := hcoeff[1]/(K!2*trace_t[1]);
lambda1 := hcoeff[2]/trace_t[1];
assert hcoeff[e] eq (trace_t[1]*lambda1)^(q^(e-1));
printf "hfe_decode_seconds=%.6o decoded_support=%o\n",
       Cputime(t_decode),[i-1 : i in [1..e] | hcoeff[i] ne 0];

/* Build and validate all rank-four IP residual operators. */
error_images := [];
image_spaces := [];
for out in [1..ell] do
    tt := trace_t[out];
    images := [];
    for i in [1..e] do
        X := sigma[i];
        hX := 2*tt*lambda0*X + tt*lambda1*X^q
              + (tt*lambda1*X)^(q^(e-1));
        Append(~images,all_images[out][i]-hX);
    end for;
    Append(~error_images,images);
    space := RowSpace(Matrix(F,e,e,
        &cat [ [ F!z : z in Eltseq(images[i]) ] : i in [1..e] ]));
    assert Dimension(space) le 4;
    Append(~image_spaces,space);
end for;
zspace := image_spaces[1];
for out in [2..ell] do
    zspace := zspace meet image_spaces[out];
end for;
assert Dimension(zspace) eq 2;
zeta := [ &+[ K!(F!Eltseq(w)[c])*power_basis[c] : c in [1..e] ]
          : w in Basis(zspace) ];
zmatrix := Matrix(F,2,e,&cat [ [F!z : z in Eltseq(zeta[j])]
                               : j in [1..2] ]);
printf "error_ranks=%o z_plane_dimension=%o\n",
       [Dimension(s) : s in image_spaces],Dimension(zspace);

/* Choose X_1,X_2 dual to the recovered Z-plane. */
z_on_sigma := Matrix(F,2,e,
    &cat [ [ Trace(zeta[j]*sigma[i],F) : i in [1..e] ]
           : j in [1..2] ]);
x_dual_coords := [];
x_dual := [];
for j in [1..2] do
    target := Vector(F,[j eq h select F!1 else F!0 : h in [1..2]]);
    cc := Eltseq(Solution(Transpose(z_on_sigma),target));
    Append(~x_dual_coords,cc);
    Append(~x_dual,&+[ K!cc[i]*sigma[i] : i in [1..e] ]);
end for;
assert Matrix(F,2,2,
    &cat [ [Trace(zeta[j]*x_dual[h],F) : h in [1..2]]
           : j in [1..2] ]) eq IdentityMatrix(F,2);

function ApplyFromBasis(images,coords)
    return &+[ K!coords[i]*images[i] : i in [1..e] ];
end function;

/* E_t(X_l) = t*mu_l modulo the fixed Z-plane.  Solve all these
   membership constraints for an equivalent pair mu_1,mu_2. */
mu := [];
for which in [1..2] do
    mrows := [];
    mrhs := [];
    for out in [1..ell] do
        w := ApplyFromBasis(error_images[out],x_dual_coords[which]);
        effects := [trace_t[out]*power_basis[c] : c in [1..e]] cat
                   [-zeta[1],-zeta[2]];
        ec := [Eltseq(z) : z in effects];
        wc := Eltseq(w);
        for d in [1..e] do
            row := [F!ec[c][d] : c in [1..e]] cat
                   &cat [ [(out eq k select F!1 else F!0)*F!ec[e+j][d]
                            : j in [1..2]]
                          : k in [1..ell] ];
            Append(~mrows,row);
            Append(~mrhs,F!wc[d]);
        end for;
    end for;
    mmat := Matrix(F,#mrows,e+2*ell,&cat mrows);
    msol := Eltseq(Solution(Transpose(mmat),Vector(F,mrhs)));
    Append(~mu,&+[K!msol[c]*power_basis[c] : c in [1..e]]);
end for;

function MuOperatorValue(tt,X)
    return &+[ tt*mu[j]*Trace(zeta[j]*X,F)
               + zeta[j]*Trace(tt*mu[j]*X,F) : j in [1..2] ];
end function;

/* The remaining operator is the polar of G(z_1,z_2).  Read its three
   projected scalar coefficients, then choose arbitrary K lifts. */
g11_proj := [];
g12_proj := [];
g22_proj := [];
for out in [1..ell] do
    r1 := ApplyFromBasis(error_images[out],x_dual_coords[1])
          - MuOperatorValue(trace_t[out],x_dual[1]);
    r2 := ApplyFromBasis(error_images[out],x_dual_coords[2])
          - MuOperatorValue(trace_t[out],x_dual[2]);
    c1 := Eltseq(Solution(zmatrix,Vector(F,Eltseq(r1))));
    c2 := Eltseq(Solution(zmatrix,Vector(F,Eltseq(r2))));
    assert c1[2] eq c2[1];
    Append(~g11_proj,c1[1]/(F!2));
    Append(~g12_proj,c1[2]);
    Append(~g22_proj,c2[2]/(F!2));
end for;
trace_matrix := Matrix(F,ell,e,
    &cat [ [Trace(trace_t[out]*power_basis[c],F) : c in [1..e]]
           : out in [1..ell] ]);
assert Rank(trace_matrix) eq ell;
function LiftProjected(vals)
    cc := Eltseq(Solution(Transpose(trace_matrix),Vector(F,vals)));
    return &+[K!cc[c]*power_basis[c] : c in [1..e]];
end function;
G11 := LiftProjected(g11_proj);
G12 := LiftProjected(g12_proj);
G22 := LiftProjected(g22_proj);
assert [Trace(trace_t[j]*G11,F) : j in [1..ell]] eq g11_proj;
assert [Trace(trace_t[j]*G12,F) : j in [1..ell]] eq g12_proj;
assert [Trace(trace_t[j]*G22,F) : j in [1..ell]] eq g22_proj;

/* Validate the full residual operator on every basis input/output. */
for out in [1..ell] do
    tt := trace_t[out];
    for i in [1..e] do
        X := sigma[i];
        z1 := Trace(zeta[1]*X,F);
        z2 := Trace(zeta[2]*X,F);
        gop := zeta[1]*(2*Trace(tt*G11,F)*z1 + Trace(tt*G12,F)*z2)
               + zeta[2]*(Trace(tt*G12,F)*z1 + 2*Trace(tt*G22,F)*z2);
        assert error_images[out][i] eq MuOperatorValue(tt,X)+gop;
    end for;
end for;
printf "ip_completion_valid=true\n";

/* ---------- recover the Dragon maps ---------- */

pair := [];
for j1 in [1..ell] do
    for j2 in [j1+1..ell] do
        test := Matrix(K,2,2,
            [trace_t[j1],trace_t[j1]^(q^(e-1)),
             trace_t[j2],trace_t[j2]^(q^(e-1))]);
        if Rank(test) eq 2 then pair := [j1,j2]; break; end if;
    end for;
    if #pair eq 2 then break; end if;
end for;
assert #pair eq 2;
dragon_matrix := Matrix(K,2,2,
    [trace_t[pair[1]],trace_t[pair[1]]^(q^(e-1)),
     trace_t[pair[2]],trace_t[pair[2]]^(q^(e-1))]);
Lambda0 := [];
Lambda1 := [];
for s in [1..kpub] do
    sol := Eltseq(Solution(Transpose(dragon_matrix),
                          Vector(K,[unexpanded[s,pair[1]],
                                    unexpanded[s,pair[2]]])));
    l0 := sol[1];
    l1 := sol[2]^q;
    assert &and [unexpanded[s,j] eq trace_t[j]*l0
                    + (trace_t[j]*l1)^(q^(e-1)) : j in [1..ell]];
    Append(~Lambda0,l0);
    Append(~Lambda1,l1);
end for;
printf "dragon_maps_recovered=%o dragon_fit_valid=true\n",kpub;

/* Lift the fixed all-ones public RHS through the recovered output trace map. */
target_f := [F!x : x in FixedTarget];
target_C := LiftProjected(target_f);
assert [Trace(trace_t[j]*target_C,F) : j in [1..ell]] eq target_f;

function CentralValue(a,y)
    X := &+[K!a[i]*sigma[i] : i in [1..e]];
    z1 := Trace(zeta[1]*X,F);
    z2 := Trace(zeta[2]*X,F);
    l0 := &+[K!y[s]*Lambda0[s] : s in [1..kpub]];
    l1 := &+[K!y[s]*Lambda1[s] : s in [1..kpub]];
    return lambda0*X^2 + lambda1*X^(q+1) + l0*X + l1*X^q
           + X*(mu[1]*z1+mu[2]*z2)
           + G11*z1^2+G12*z1*z2+G22*z2^2;
end function;

function PublicEvaluate(a,y)
    out := [F!0 : j in [1..ell]];
    for i in [1..e] do
        for j in [i..e] do
            c := a[i]*a[j];
            if c ne 0 then
                idx := AAIndex(i,j,e);
                for outj in [1..ell] do
                    out[outj] +:= c*F!AAUpper[idx][outj];
                end for;
            end if;
        end for;
    end for;
    for i in [1..e] do
        for s in [1..kpub] do
            c := a[i]*y[s];
            if c ne 0 then
                for outj in [1..ell] do
                    out[outj] +:= c*F!PublicFlat[s][(i-1)*ell+outj];
                end for;
            end if;
        end for;
    end for;
    return out;
end function;

/* Independent public-coefficient reconstruction checks. */
SetSeed(20261007);
for trial in [1..8] do
    aa := [Random(F) : i in [1..e]];
    yy := [Random(F) : s in [1..kpub]];
    assert PublicEvaluate(aa,yy) eq
           [Trace(trace_t[j]*CentralValue(aa,yy),F) : j in [1..ell]];
end for;
printf "full_public_map_reconstruction_valid=true\n";

/* ---------- fresh fixed-RHS equivalent signing ---------- */

R<Xvar> := PolynomialRing(K);
forged := false;
forge_a := [];
forge_salt := 0;
t_forge := Cputime();
root_attempts := 0;
for salt_index in [1..#FreshHashes] do
    y := [F!x : x in FreshHashes[salt_index]];
    l0 := &+[K!y[s]*Lambda0[s] : s in [1..kpub]];
    l1 := &+[K!y[s]*Lambda1[s] : s in [1..kpub]];
    for z1 in F do
        for z2 in F do
            poly := lambda0*Xvar^2 + lambda1*Xvar^(q+1)
                    + (l0+mu[1]*z1+mu[2]*z2)*Xvar + l1*Xvar^q
                    + G11*z1^2+G12*z1*z2+G22*z2^2-target_C;
            root_attempts +:= 1;
            for rr in Roots(poly) do
                XX := rr[1];
                if Trace(zeta[1]*XX,F) eq z1 and
                   Trace(zeta[2]*XX,F) eq z2 then
                    candidate := [Trace(gamma[i]*XX,F) : i in [1..e]];
                    if &or [c ne 0 : c in candidate] and
                       PublicEvaluate(candidate,y) eq target_f then
                        forged := true;
                        forge_a := candidate;
                        forge_salt := salt_index-1;
                        break;
                    end if;
                end if;
            end for;
            if forged then break; end if;
        end for;
        if forged then break; end if;
    end for;
    if forged then break; end if;
end for;
assert forged;
fresh_y := [F!x : x in FreshHashes[forge_salt+1]];
assert PublicEvaluate(forge_a,fresh_y) eq target_f;
changed_accepts := 0;
for hh in ChangedHashes do
    if PublicEvaluate(forge_a,[F!x : x in hh]) eq target_f then
        changed_accepts +:= 1;
    end if;
end for;
printf "fresh_message_hex=%o salt=%o root_attempts=%o forge_seconds=%.6o\n",
       FreshMessageHex,forge_salt,root_attempts,Cputime(t_forge);
printf "forged_signature_fq=%o public_fixed_rhs_accept=true changed_message_accepting_salts=%o changed_message_reject=%o\n",
       [Integers()!x : x in forge_a],changed_accepts,changed_accepts eq 0;
printf "total_seconds=%.6o magma_memory_bytes_at_end=%o\n",
       Cputime(t_start),GetMemoryUsage();
printf "ATTACK_REPRODUCTION: PASS\n";

UnsetOutputFile();
quit;
