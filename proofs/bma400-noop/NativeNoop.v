From Coq Require Import List.
From compcert Require Import Coqlib Maps AST Values Memory Events Smallstep Ctypes Clight.
From Bma400 Require Import Original Guarded.
Import ListNotations.

(* In Clight's temporary-parameter semantics the callback's argument lives in
   its private temporary environment. The empty body never inspects its value. *)
Definition callback_frame (arg : val) : temp_env :=
  PTree.set Original._buf arg (create_undef_temps []).

Lemma callback_entry ge arg m :
  function_entry2 ge Original.f_regmap_parse_inplace_noop [arg] m
    empty_env (callback_frame arg) m.
Proof.
  constructor.
  - constructor.
  - repeat constructor. simpl. tauto.
  - unfold list_disjoint. simpl. tauto.
  - constructor.
  - reflexivity.
Qed.

Lemma generated_callbacks_identical :
  Guarded.f_regmap_parse_inplace_noop = Original.f_regmap_parse_inplace_noop.
Proof. reflexivity. Qed.

Lemma callback_entry_unique ge arg m e le m' :
  function_entry2 ge Original.f_regmap_parse_inplace_noop [arg] m e le m' ->
  e = empty_env /\ le = callback_frame arg /\ m' = m.
Proof.
  intros ENTRY. inversion ENTRY; subst.
  match goal with
  | A : alloc_variables _ _ _ _ _ _ |- _ => inversion A; subst
  end.
  match goal with
  | B : bind_parameter_temps _ _ _ = _ |- _ =>
      change (Some (callback_frame arg) = Some le) in B; inversion B; auto
  end.
Qed.

(* Invert every possible transition, including its event trace and memory. *)
Theorem callback_only_entry ge arg m k t next :
  step2 ge
    (Callstate (Internal Original.f_regmap_parse_inplace_noop) [arg] k m) t next ->
  t = E0 /\ next = State Original.f_regmap_parse_inplace_noop
                         Sskip k empty_env (callback_frame arg) m.
Proof.
  intros STEP. inversion STEP; subst.
  match goal with
  | H : function_entry2 _ _ _ _ _ _ _ |- _ =>
      destruct (callback_entry_unique _ _ _ _ _ _ H) as [-> [-> ->]]; auto
  end.
Qed.

Theorem callback_only_exit ge arg m k t next :
  is_call_cont k ->
  step2 ge (State Original.f_regmap_parse_inplace_noop Sskip k
              empty_env (callback_frame arg) m) t next ->
  t = E0 /\ next = Returnstate Vundef k m.
Proof.
  intros K STEP. destruct k; simpl in K; try contradiction; inversion STEP; subst;
    match goal with
    | FREE : Mem.free_list ?old _ = Some ?new |- _ =>
        change (Some old = Some new) in FREE; injection FREE as <-; auto
    end.
Qed.

Theorem callback_two_silent_steps ge arg m k :
  is_call_cont k ->
  let f := Original.f_regmap_parse_inplace_noop in
  let body := State f Sskip k empty_env (callback_frame arg) m in
  step2 ge (Callstate (Internal f) [arg] k m) E0 body /\
  step2 ge body E0 (Returnstate Vundef k m).
Proof.
  intros H. split.
  - apply step_internal_function. apply callback_entry.
  - apply step_skip_call; [exact H | reflexivity].
Qed.

Lemma callback_returns ge arg m k :
  is_call_cont k ->
  star step2 ge
    (Callstate (Internal Original.f_regmap_parse_inplace_noop) [arg] k m) E0
    (Returnstate Vundef k m).
Proof.
  intros H. destruct (callback_two_silent_steps ge arg m k H) as [ENTER EXIT].
  eapply star_step; [exact ENTER | apply star_one; exact EXIT | reflexivity].
Qed.

Theorem original_noop_returns arg m k :
  is_call_cont k ->
  star step2 (globalenv Original.prog)
    (Callstate (Internal Original.f_regmap_parse_inplace_noop) [arg] k m) E0
    (Returnstate Vundef k m).
Proof. apply callback_returns. Qed.

Theorem guarded_noop_returns arg m k :
  is_call_cont k ->
  star step2 (globalenv Guarded.prog)
    (Callstate (Internal Guarded.f_regmap_parse_inplace_noop) [arg] k m) E0
    (Returnstate Vundef k m).
Proof. rewrite generated_callbacks_identical. apply callback_returns. Qed.

(* A void call in the real loop has no destination. Any caller continuation
   may sit underneath its call frame, including the loop's next iteration. *)
Theorem void_callback_resumes ge arg m caller e le k :
  star step2 ge
    (Callstate (Internal Original.f_regmap_parse_inplace_noop) [arg]
      (Kcall None caller e le k) m) E0
    (State caller Sskip k e le m).
Proof.
  eapply star_trans.
  - apply callback_returns. exact I.
  - eapply star_step; [apply step_returnstate | apply star_refl | reflexivity].
  - reflexivity.
Qed.

Print Assumptions callback_two_silent_steps.
Print Assumptions original_noop_returns.
Print Assumptions guarded_noop_returns.
Print Assumptions void_callback_resumes.
Print Assumptions callback_only_entry.
Print Assumptions callback_only_exit.
