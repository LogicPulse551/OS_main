(* This layout belongs to the certificate's Clight projection.
   The object-class frame in ObjectClass.v is parameterized by the offset. *)
From Coq Require Import ZArith List Bool Lia.
From compcert Require Import Coqlib Maps Integers AST Values Memory Events Globalenvs
 Smallstep Ctypes Cop Clight Clightdefs.
From Bma400 Require Import BulkRead Original Guarded ClightBinding NativeNoop ObjectClass.
Import Guarded.
Local Open Scope Z_scope.

Definition guard_ge := globalenv Guarded.prog.
Definition known_code : block :=
  match Genv.find_symbol guard_ge _regmap_parse_inplace_noop with
  | Some b => b | None => 1%positive end.

Lemma linked_empty_callback :
  Genv.find_symbol guard_ge _regmap_parse_inplace_noop = Some known_code /\
  Genv.find_funct guard_ge (Vptr known_code Ptrofs.zero) =
    Some (Internal Guarded.f_regmap_parse_inplace_noop) /\
  fn_body Guarded.f_regmap_parse_inplace_noop = Sskip.
Proof. vm_compute; repeat split; reflexivity. Qed.

Lemma field_value e le m b :
  PTree.get _map le = Some (Vptr b Ptrofs.zero) ->
  installed b known_code 8 m ->
  eval_expr guard_ge e le m callback_field (Vptr known_code Ptrofs.zero).
Proof.
  intros T V. unfold callback_field.
  eapply eval_Elvalue.
  - eapply eval_Efield_struct.
    + eapply eval_Elvalue.
      * eapply eval_Efield_struct.
        -- eapply eval_Elvalue; [apply eval_Ederef; apply eval_Etempvar; exact T
                               |apply deref_loc_copy; reflexivity].
        -- reflexivity.
        -- vm_compute; reflexivity.
        -- vm_compute; reflexivity.
      * apply deref_loc_copy; reflexivity.
    + reflexivity.
    + vm_compute; reflexivity.
    + vm_compute; reflexivity.
  - eapply deref_loc_value; [reflexivity|]. exact V.
Qed.

Theorem actual_guard_false e le m b :
  PTree.get _regmap_parse_inplace_noop e = None ->
  PTree.get _map le = Some (Vptr b Ptrofs.zero) ->
  installed b known_code 8 m ->
  Mem.weak_valid_pointer m known_code 0 = true ->
  eval_expr guard_ge e le m different_callback (Vint Int.zero).
Proof.
  intros LOCAL T V LIVE. unfold different_callback.
  eapply eval_Ebinop.
  - eapply field_value; eauto.
  - eapply eval_Elvalue.
    + apply eval_Evar_global; [exact LOCAL|apply (proj1 linked_empty_callback)].
    + apply deref_loc_reference; reflexivity.
  - change (option_map Val.of_bool
              (if Mem.weak_valid_pointer m known_code 0 && Mem.weak_valid_pointer m known_code 0
               then Some false else None) = Some (Vint Int.zero)).
    rewrite LIVE. reflexivity.
Qed.

Theorem projected_cut_original_contract m g reads b advance convert p :
  window b known_code 8 m g reads 6 ->
  forall result,
  observes advance convert (classify b known_code 8 g)
    (fun i => classify b known_code 8 (reads i)) p callback_loop result <->
  observes advance convert (classify b known_code 8 g)
    (fun i => classify b known_code 8 (reads i)) p guarded_loop result.
Proof.
  intro W. apply bound_cut_preserves. intros _ i INSIDE.
  apply (proj2 (window_values _ _ _ _ _ _ _ W)); apply in_seq in INSIDE; lia.
Qed.

Print Assumptions linked_empty_callback.
Print Assumptions actual_guard_false.
Print Assumptions projected_cut_original_contract.
