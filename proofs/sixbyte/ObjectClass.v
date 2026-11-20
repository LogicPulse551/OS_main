(* An object identifier here is a CompCert block, not a Linux device ID.
   The installed function is represented by its linked block and zero offset.
   The byte-range and lifetime conditions below must be justified by a caller
   and a concrete build. This file has no axiom about Linux. *)
From Coq Require Import ZArith List Lia.
From compcert Require Import Coqlib Integers AST Values Memory.
From Bma400 Require Import BulkRead.
Import ListNotations.
Local Open Scope Z_scope.

Section Field.
Variable object noop : block.
Variable field : Z.

Definition slot (b : block) (i : Z) : Prop :=
  b = object /\ field <= i < field + size_chunk Mint64.

(* All primitive effects until the last conversion read. Reads do not write
   memory. Freeing the map block and partial overlapping stores are excluded.
   An allocation is safe even when it uses the same numerical address in some
   machine representation: fresh blocks in this model have distinct identity. *)
Inductive action : mem -> mem -> Prop :=
| write_scalar c m b ofs v t :
    Mem.store c m b ofs v = Some t ->
    (forall i, ofs <= i < ofs + size_chunk c -> ~slot b i) ->
    action m t
| write_range m b ofs bytes t :
    Mem.storebytes m b ofs bytes = Some t ->
    (forall i, ofs <= i < ofs + Z.of_nat (length bytes) -> ~slot b i) ->
    action m t
| allocate m lo hi t b : Mem.alloc m lo hi = (t,b) -> action m t
| free_peer m b lo hi t :
    b <> object -> Mem.free m b lo hi = Some t -> action m t.

Inductive segment : mem -> mem -> Prop :=
| stay m : segment m m
| add_action m t u : segment m t -> action t u -> segment m u.

Lemma action_frame m t : action m t -> Mem.unchanged_on slot m t.
Proof.
  intros H; destruct H.
  - eapply Mem.store_unchanged_on; eauto.
  - eapply Mem.storebytes_unchanged_on; eauto.
  - eapply Mem.alloc_unchanged_on; eauto.
  - eapply Mem.free_unchanged_on; eauto. intros i _ [E _]; contradiction.
Qed.

Definition installed (m : mem) : Prop :=
  Mem.load Mint64 m object field = Some (Vptr noop Ptrofs.zero).

Lemma initialize m t :
  Mem.store Mint64 m object field (Vptr noop Ptrofs.zero) = Some t -> installed t.
Proof. exact (Mem.load_store_same Mint64 m object field (Vptr noop Ptrofs.zero) t). Qed.

Lemma preserves m t : segment m t -> installed m -> installed t.
Proof.
  intro H; induction H; intro K; auto.
  unfold installed in *; eapply Mem.load_unchanged_on.
  - apply action_frame; eauto.
  - intros i R. split; auto.
  - apply IHsegment; auto.
Qed.

(* The result of a successful native function-pointer comparison. The fallback
   marker is used only outside the established installed case. *)
Definition classify (m : mem) : target :=
  match Mem.load Mint64 m object field with
  | Some (Vptr b ofs) =>
      if andb (Pos.eqb b noop) (Ptrofs.eq ofs Ptrofs.zero)
      then Empty else Converter 0
  | _ => Converter 0
  end.

Lemma recognizes m : installed m -> classify m = Empty.
Proof. unfold installed, classify; intros ->. rewrite Pos.eqb_refl, Ptrofs.eq_true. reflexivity. Qed.

Record window (before_store guard : mem) (at_read : nat -> mem) (n : nat) : Prop := {
  constructor_and_publication :
    exists initial, Mem.store Mint64 before_store object field (Vptr noop Ptrofs.zero) = Some initial
                 /\ segment initial guard;
  first_read : (0 < n)%nat -> segment guard (at_read 0%nat);
  between_reads : forall i, (S i < n)%nat -> segment (at_read i) (at_read (S i))
}.

Lemma window_values m g r n : window m g r n ->
  classify g = Empty /\ forall i, (i < n)%nat -> classify (r i) = Empty.
Proof.
  intros [[init [S0 S1]] FIRST MORE].
  assert (G : installed g) by (eapply preserves; [exact S1|eapply initialize; eauto]).
  split. now apply recognizes.
  intros i R. apply recognizes.
  induction i as [|i IH].
  - apply (preserves _ _ (FIRST R) G).
  - apply (preserves _ _ (MORE i R)); apply IH; lia.
Qed.

Theorem original_six m g r advance convert p :
  window m g r 6 ->
  finish (run_loop advance convert (fun i => classify (r i)) offsets) p =
  finish (optimized advance convert (classify g) (fun i => classify (r i)) offsets) p.
Proof.
  intro W; apply same_bulk_observations. intros _ i I.
  apply (proj2 (window_values _ _ _ _ W)); apply in_seq in I; lia.
Qed.

(* The original success event hardcodes register 4 and count 6. Carry caller
   register and count through the same prefix and successful return. *)
Definition success_at addr n s : result :=
  {| rc := 0; contents := {| buffer := buffer s; events := events s ++ [BulkReadSuccess addr n] |} |}.

Definition finish_at addr n (after : visible -> visible) (p : prefix) : result :=
  match p with
  | Rejected r => r
  | Fallback r => if Z.eqb (rc r) 0 then success_at addr n (contents r) else r
  | Raw r => if Z.eqb (rc r) 0 then success_at addr n (after (contents r)) else r
  end.

Lemma agrees_with_original f p : finish_at 4 6 f p = finish f p.
Proof. destruct p; reflexivity. Qed.

Theorem one_byte_bulk addr n m g r advance convert p :
  window m g r n ->
  finish_at addr n (run_loop advance convert (fun i => classify (r i)) (seq 0 n)) p =
  finish_at addr n (optimized advance convert (classify g) (fun i => classify (r i)) (seq 0 n)) p.
Proof.
  intros W. destruct (window_values _ _ _ _ W) as [G R].
  rewrite G. unfold optimized.
  destruct p as [v|v|v]; cbn [finish_at]; try reflexivity.
  destruct (Z.eqb (rc v) 0); [|reflexivity].
  rewrite empty_loop; [reflexivity|]. intros i I; apply R; apply in_seq in I; lia.
Qed.

Corollary adxl_event_shape m g r advance convert p :
  window m g r 6 ->
  finish_at 50 6 (run_loop advance convert (fun i => classify (r i)) offsets) p =
  finish_at 50 6 (optimized advance convert (classify g) (fun i => classify (r i)) offsets) p.
Proof. apply one_byte_bulk. Qed.
End Field.

Print Assumptions original_six.
Print Assumptions agrees_with_original.
Print Assumptions one_byte_bulk.
Print Assumptions adxl_event_shape.
