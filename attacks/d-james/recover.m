/*
  Public-only full q5/128 cross-code recovery.

  Input is regenerated directly from the sanitized public-key JSON by
  export_public_magma.py.  No prior determinant, resultant, field,
  hidden basis, trace support, or secret fixture is loaded.
*/

load "work/public-data.m";
assert InputSHA256 eq
  "51c295dbf1ecd9ce77a890b5436391365f919505971f5a1b19e8f17341dc1e3a";
assert Nrows(A0) eq 111 and Ncols(A0) eq 94;
assert Nrows(A1) eq 111 and Ncols(A1) eq 94;
assert Nrows(A2) eq 111 and Ncols(A2) eq 94;

n := 94;
P<u,v> := PolynomialRing(F,2);
E<a> := ext<F | 3>;
points := [x : x in E][1..n+1];
vandermonde := Matrix(E,n+1,n+1,
    [points[i]^(j-1) : i,j in [1..n+1]]);
vandermonde_inverse := vandermonde^-1;

function InterpolateMaximalMinor(rows,label)
    B0 := ChangeRing(Submatrix(A0,rows,[1..n]),E);
    B1 := ChangeRing(Submatrix(A1,rows,[1..n]),E);
    B2 := ChangeRing(Submatrix(A2,rows,[1..n]),E);
    started_real := Realtime();
    started_cpu := Cputime();
    coefficients_by_v_point := ZeroMatrix(E,n+1,n+1);
    for j in [1..n+1] do
        values := Matrix(E,n+1,1,
            [Determinant(B0 + points[i]*B1 + points[j]*B2)
             : i in [1..n+1]]);
        u_coefficients := vandermonde_inverse*values;
        for i in [1..n+1] do
            coefficients_by_v_point[i,j] := u_coefficients[i,1];
        end for;
    end for;
    coefficients := ZeroMatrix(E,n+1,n+1);
    for i in [1..n+1] do
        v_coefficients := vandermonde_inverse*
            Matrix(E,n+1,1,[coefficients_by_v_point[i,j] : j in [1..n+1]]);
        for j in [1..n+1] do
            coefficients[i,j] := v_coefficients[j,1];
        end for;
    end for;
    assert &and[z^q eq z : z in Eltseq(coefficients)];
    assert &and[coefficients[i,j] eq 0 : i,j in [1..n+1]
                | i+j-2 gt n];
    determinant := &+[F!coefficients[i,j]*u^(i-1)*v^(j-1)
                      : i,j in [1..n+1]];
    printf "INTERPOLATED label=%o real_seconds=%.6o cpu_seconds=%.6o terms=%o " cat
           "degree_u=%o degree_v=%o memory_bytes=%o\n",
           label,Realtime(started_real),Cputime(started_cpu),#Terms(determinant),
           Degree(determinant,1),Degree(determinant,2),GetMemoryUsage();
    return determinant;
end function;

total_real := Realtime();
total_cpu := Cputime();
D1 := InterpolateMaximalMinor([1..94],"rows-1-94");
D2 := InterpolateMaximalMinor([18..111],"rows-18-111");
D3 := InterpolateMaximalMinor([1..93] cat [95],"rows-1-93-plus-95");

resultant_start := Realtime();
R12 := Resultant(D1,D2,1);
printf "RESULTANT pair=12 real_seconds=%.6o degree_v=%o terms=%o memory_bytes=%o\n",
       Realtime(resultant_start),Degree(R12,2),#Terms(R12),GetMemoryUsage();
resultant_start := Realtime();
R13 := Resultant(D1,D3,1);
printf "RESULTANT pair=13 real_seconds=%.6o degree_v=%o terms=%o memory_bytes=%o\n",
       Realtime(resultant_start),Degree(R13,2),#Terms(R13),GetMemoryUsage();

Q<t> := PolynomialRing(F);
function ToUnivariateInV(poly)
    return &+[F!MonomialCoefficient(poly,v^i)*t^i
              : i in [0..Degree(poly,2)]];
end function;
common := GCD(ToUnivariateInV(R12),ToUnivariateInV(R13));
factorization := Factorization(common);
printf "COMMON degree=%o factor_degrees=%o\n",Degree(common),
       [<Degree(pair[1]),pair[2]> : pair in factorization];
candidates := [pair[1] : pair in factorization | Degree(pair[1]) eq n];
printf "DEGREE_94_CANDIDATES count=%o\n",#candidates;

valid := 0;
for modulus in candidates do
    K<vv> := ext<F | modulus>;
    KU<uu> := PolynomialRing(K);
    function SubstituteV(poly)
        out := KU!0;
        for monomial in Monomials(poly) do
            exponents := Exponents(monomial);
            out +:= K!MonomialCoefficient(poly,monomial)*
                    uu^exponents[1]*vv^exponents[2];
        end for;
        return out;
    end function;
    common_u := GCD(GCD(SubstituteV(D1),SubstituteV(D2)),SubstituteV(D3));
    printf "U_GCD degree=%o roots=%o\n",Degree(common_u),#Roots(common_u);
    for root_pair in Roots(common_u) do
        uv := root_pair[1];
        pencil := ChangeRing(A0,K) + uv*ChangeRing(A1,K) + vv*ChangeRing(A2,K);
        right_kernel := Kernel(Transpose(pencil));
        if Rank(pencil) eq n-1 and Dimension(right_kernel) eq 1 then
            gamma := Eltseq(Basis(right_kernel)[1]);
            gamma_coordinates := Matrix(F,n,n,
                &cat[[F!z : z in Eltseq(gamma[i])] : i in [1..n]]);
            if Rank(gamma_coordinates) eq n then
                unexpanded := Matrix(K,public_dimension,code_length,
                    &cat[[&+[gamma[i]*K!(F!PublicFlat[s][(i-1)*code_length+j])
                              : i in [1..n]]
                           : j in [1..code_length]]
                          : s in [1..public_dimension]]);
                parent := RowSpace(unexpanded);
                parent_basis := Basis(parent);
                parent_q := RowSpace(Matrix(K,#parent_basis,code_length,
                    &cat[[z^q : z in Eltseq(word)] : word in parent_basis]));
                intersection := parent meet parent_q;
                if Rank(unexpanded) eq 2 and Dimension(intersection) eq 1 then
                    trace_t := Eltseq(Basis(intersection)[1]);
                    trace_coordinates := Matrix(F,code_length,n,
                        &cat[[F!z : z in Eltseq(trace_t[j])]
                             : j in [1..code_length]]);
                    valid +:= 1;
                    SetOutputFile("work/recovered-basis.m"
                                  : Overwrite := true);
                    print "RecoveredSchema := \"djames-q5-128-public-basis-v1\";";
                    print "RecoveredInputSHA256 := \"" cat InputSHA256 cat "\";";
                    print "RecoveredModulusCoefficients :=",
                          [Integers()!z : z in Eltseq(modulus)],";";
                    print "RecoveredVCoords :=",
                          [Integers()!z : z in Eltseq(vv)],";";
                    print "RecoveredUCoords :=",
                          [Integers()!z : z in Eltseq(uv)],";";
                    print "RecoveredGammaCoords :=",
                          [[Integers()!z : z in Eltseq(gamma[i])]
                           : i in [1..n]],";";
                    print "RecoveredTraceTCoords :=",
                          [[Integers()!z : z in Eltseq(trace_t[j])]
                           : j in [1..code_length]],";";
                    UnsetOutputFile();
                    printf "VALID_RECOVERY ordinal=%o pencil_rank=%o kernel_dim=%o " cat
                           "gamma_rank=%o parent_rank=%o intersection_dim=%o " cat
                           "trace_t_rank=%o\n",valid,Rank(pencil),
                           Dimension(right_kernel),Rank(gamma_coordinates),
                           Rank(unexpanded),Dimension(intersection),
                           Rank(trace_coordinates);
                end if;
            end if;
        end if;
    end for;
end for;
assert valid eq 1;
printf "PUBLIC_RECOVERY_PASS valid=%o total_real_seconds=%.6o " cat
       "total_cpu_seconds=%.6o memory_bytes=%o\n",
       valid,Realtime(total_real),Cputime(total_cpu),GetMemoryUsage();
quit;
