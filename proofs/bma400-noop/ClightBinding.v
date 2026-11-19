(* Recognize the complete changed statement in the two projected translation
   units. The local interpretation below is deliberately specific to this cut. *)
From Coq Require Import List ZArith.
From compcert Require Import Integers AST Ctypes Cop Clight Clightdefs.
From Bma400 Require Import BulkRead Original Guarded.
Import ListNotations.
Import Guarded.

Definition callback_type := Tfunction (Tcons (tptr tvoid) Tnil) tvoid cc_default.
Definition callback_field :=
  Efield (Efield (Ederef (Etempvar _map (tptr (Tstruct _regmap noattr)))
                          (Tstruct _regmap noattr))
                 _format (Tstruct _regmap_format noattr))
         _parse_inplace (tptr callback_type).
Definition different_callback :=
  Ebinop One callback_field (Evar _regmap_parse_inplace_noop callback_type) tint.

Definition index := Etempvar _i tint.
Definition width := Etempvar _val_bytes tulong.
Definition count := Etempvar _val_count tulong.
Definition byte_address := Ebinop Oadd
  (Ecast (Etempvar _val (tptr tvoid)) (tptr tuchar)) index (tptr tuchar).
Definition callback_loop :=
  Ssequence (Sset _i (Econst_int (Int.repr 0) tint))
    (Sloop
      (Ssequence
        (Sifthenelse (Ebinop Olt index (Ebinop Omul count width tulong) tint)
                     Sskip Sbreak)
        (Scall None callback_field [byte_address]))
      (Sset _i (Ecast (Ebinop Oadd index width tulong) tint))).
Definition guarded_loop := Sifthenelse different_callback callback_loop Sskip.

(* Search only the statement forms that enclose this cut. If either unit gains
   another such loop or changes its body, the concrete equalities below fail. *)
Fixpoint loops (s : statement) : list statement :=
  match s with
  | Ssequence (Sset _ _) (Sloop _ _) => [s]
  | Ssequence a b | Sifthenelse _ a b => loops a ++ loops b
  | _ => []
  end.

Fixpoint guard_loops (s : statement) : statement :=
  match s with
  | Ssequence (Sset _ _) (Sloop _ _) => Sifthenelse different_callback s Sskip
  | Ssequence a b => Ssequence (guard_loops a) (guard_loops b)
  | Sifthenelse e a b => Sifthenelse e (guard_loops a) (guard_loops b)
  | _ => s
  end.

Lemma actual_cuts :
  loops (fn_body Original.f_regmap_bulk_read) = [callback_loop] /\
  fn_body Guarded.f_regmap_bulk_read = guard_loops (fn_body Original.f_regmap_bulk_read) /\
  fn_body Original.f_regmap_parse_inplace_noop = Sskip /\
  fn_body Guarded.f_regmap_parse_inplace_noop = Sskip.
Proof. repeat split; reflexivity. Qed.

(* Evaluate the loop indices at val_count=6, val_bytes=1. There is a seventh
   comparison after the last call. Exhausting fuel before a break is a failure. *)
Fixpoint trace_indices (fuel : nat) (i : int) : option (list nat) :=
  match fuel with
  | O => None
  | S rest =>
      if Int64.ltu (Int64.repr (Int.signed i)) (Int64.mul (Int64.repr 6) Int64.one)
      then match trace_indices rest (Int.repr (Int.signed i + 1)) with
           | Some xs => Some (Z.to_nat (Int.signed i) :: xs)
           | None => None
           end
      else Some []
  end.

Lemma actual_offsets : trace_indices 7 Int.zero = Some BulkRead.offsets.
Proof. reflexivity. Qed.

Section Observations.
  Variable advance : nat -> visible -> visible.
  Variable convert : nat -> nat -> visible -> visible.
  Variable installed : target.
  Variable read_target : nat -> target.
  Variable p : prefix.

  (* This interpretation has two defined statements and no catch-all case.
     I/O and errors reach both sides from the same unchanged prefix. *)
  Inductive observes : statement -> result -> Prop :=
  | observes_original : observes callback_loop
      (finish (run_loop advance convert read_target offsets) p)
  | observes_guarded : observes guarded_loop
      (finish (optimized advance convert installed read_target offsets) p).

  Theorem bound_cut_preserves :
    (installed = Empty -> forall i, In i offsets -> read_target i = Empty) ->
    forall r, observes callback_loop r <-> observes guarded_loop r.
  Proof.
    intros stable r.
    pose proof (same_bulk_observations advance convert p installed read_target stable) as equal.
    split; intro obs; inversion obs; subst.
    - rewrite equal. constructor.
    - rewrite <- equal. constructor.
  Qed.
End Observations.

Print Assumptions actual_cuts.
Print Assumptions actual_offsets.
Print Assumptions bound_cut_preserves.
