(* Local observation model for the six-byte, one-byte-per-value bulk read.
   The common raw call supplies its actual result, including any partial write. *)
From Coq Require Import List ZArith Ascii.
Import ListNotations.

Inductive target := Empty | Converter (identity : nat).
Inductive event :=
| Transfer (address : nat) (length : nat) (status : Z)
| BulkReadSuccess (start : nat) (count : nat)
| OtherEvent (identity : nat).

Record visible := { buffer : list ascii; events : list event }.
Record result := { rc : Z; contents : visible }.

Definition offsets := seq 0 6.

(* An environment action can change the observed world. A separate function
   supplies the callback read at each iteration, so stability is an explicit
   condition rather than a consequence of the definition of the loop. *)
Section Execution.
  Variable advance : nat -> visible -> visible.
  Variable convert : nat -> nat -> visible -> visible.

  Fixpoint run_loop (read_target : nat -> target) (todo : list nat) (s : visible) :=
    match todo with
    | [] => s
    | i :: rest =>
        let next := advance i s in
        let after_call :=
          match read_target i with
          | Empty => next
          | Converter id => convert id i next
          end in
        run_loop read_target rest after_call
    end.

  Fixpoint run_environment (todo : list nat) (s : visible) :=
    match todo with
    | [] => s
    | i :: rest => run_environment rest (advance i s)
    end.

  Definition optimized (guard : target) (read_target : nat -> target) todo s :=
    match guard with
    | Empty => run_environment todo s
    | Converter _ => run_loop read_target todo s
    end.

  Lemma empty_loop : forall todo read_target s,
    (forall i, In i todo -> read_target i = Empty) ->
    run_loop read_target todo s = run_environment todo s.
  Proof.
    induction todo as [|i rest IH]; intros read_target s stable; simpl; auto.
    rewrite (stable i (or_introl eq_refl)).
    apply IH. intros j inside. apply stable. now right.
  Qed.

  Definition success s :=
    {| rc := 0; contents := {| buffer := buffer s;
       events := events s ++ [BulkReadSuccess 4 6] |} |}.

  (* Rejected covers the unchanged early returns. Raw and Fallback store the
     result of the same prefix call; its I/O is not replayed by the suffix. *)
  Inductive prefix := Rejected (r : result) | Fallback (r : result) | Raw (r : result).

  Definition finish (on_raw_success : visible -> visible) (p : prefix) :=
    match p with
    | Rejected r => r
    | Fallback r => if Z.eqb (rc r) 0 then success (contents r) else r
    | Raw r => if Z.eqb (rc r) 0 then success (on_raw_success (contents r)) else r
    end.

  Theorem same_bulk_observations : forall p guard read_target,
    (guard = Empty -> forall i, In i offsets -> read_target i = Empty) ->
    finish (run_loop read_target offsets) p =
    finish (optimized guard read_target offsets) p.
  Proof.
    intros p guard read_target stable. destruct p as [r|r|r]; unfold finish; try reflexivity.
    destruct (Z.eqb (rc r) 0); [|reflexivity].
    destruct guard; unfold optimized; [|reflexivity].
    now rewrite empty_loop by (apply stable; reflexivity).
  Qed.

  Theorem raw_error_keeps_prefix : forall guard read_target r,
    rc r <> 0%Z -> finish (optimized guard read_target offsets) (Raw r) = r.
  Proof.
    intros. simpl. apply Z.eqb_neq in H. now rewrite H.
  Qed.
End Execution.

(* A read-only configured object gives the caller an especially simple way to
   discharge the six-read condition. Its lifetime is a separate Linux contract. *)
Corollary fixed_object : forall advance convert p installed,
  finish (run_loop advance convert (fun _ => installed) offsets) p =
  finish (optimized advance convert installed (fun _ => installed) offsets) p.
Proof.
  intros. apply same_bulk_observations. intros E i _. exact E.
Qed.

(* A later nonempty converter writes a byte. The guard alone does not suffice. *)
Example changing_target_breaks_the_rule :
  let init := {| buffer := []; events := [] |} in
  let pause := fun (_ : nat) (s : visible) => s in
  let write := fun (_ i : nat) (s : visible) =>
    {| buffer := ascii_of_nat i :: buffer s; events := events s |} in
  let read := fun i => if Nat.eqb i 1 then Converter 1 else Empty in
  run_loop pause write read offsets init <>
  optimized pause write Empty read offsets init.
Proof. discriminate. Qed.

Print Assumptions same_bulk_observations.
Print Assumptions raw_error_keeps_prefix.
Print Assumptions fixed_object.
Print Assumptions changing_target_breaks_the_rule.
