(* Link the real post-read guard to the six-byte loop and to the live-map
   resource contract. Linux and the compiler remain outside the local model. *)
From Coq Require Import List ZArith Bool Lia.
From compcert Require Import Maps Integers AST Memory Values Events Globalenvs
  Ctypes Cop Clight Clightdefs ClightBigstep.
From Bma400 Require Import BulkRead Original ClightBinding ObjectClass PrivateGuard
  GenericRead Valid ValidGuard.
Import ListNotations.
Local Open Scope Z_scope.

Definition one := Econst_int Int.one tint.
Definition lit z := Econst_int (Int.repr z) tint.
Definition observer := Evar Valid._kconc_keep_callback_entries tbool.
Definition differs e z := Ebinop One e (lit z) tint.
Definition test1 := Sifthenelse observer (Sset Valid._t'3 one)
  (Sset Valid._t'3 (Ecast (differs count 6) tbool)).
Definition test2 := Sifthenelse (Etempvar Valid._t'3 tint) (Sset Valid._t'4 one)
  (Sset Valid._t'4 (Ecast (differs width 1) tbool)).
Definition test3 := Sifthenelse (Etempvar Valid._t'4 tint) (Sset Valid._t'5 one)
  (Sset Valid._t'5 (Ecast different_callback tbool)).
Definition select_loop := Sifthenelse (Etempvar Valid._t'5 tint) callback_loop Sskip.
Definition valid_cut := Ssequence (Ssequence (Ssequence test1 test2) test3) select_loop.

(* The translated short-circuit tests introduce three Clight temporaries. *)
Definition rename i :=
  if Pos.eqb i Original._t'3 then Valid._t'6 else
  if Pos.eqb i Original._t'4 then Valid._t'7 else
  if Pos.eqb i Original._t'5 then Valid._t'8 else i.
Fixpoint rename_expr e :=
  match e with
  | Etempvar i t => Etempvar (rename i) t
  | Ederef a t => Ederef (rename_expr a) t
  | Efield a f t => Efield (rename_expr a) f t
  | Ecast a t => Ecast (rename_expr a) t
  | Eunop op a t => Eunop op (rename_expr a) t
  | Ebinop op a b t => Ebinop op (rename_expr a) (rename_expr b) t
  | other => other
  end.
Fixpoint replace_cut s :=
  match s with
  | Ssequence (Sset _ _) (Sloop _ _) => valid_cut
  | Ssequence a b => Ssequence (replace_cut a) (replace_cut b)
  | Sifthenelse e a b => Sifthenelse (rename_expr e) (replace_cut a) (replace_cut b)
  | Sreturn e => Sreturn (option_map rename_expr e)
  | Sset i e => Sset (rename i) (rename_expr e)
  | Scall i f args => Scall (option_map rename i) (rename_expr f) (map rename_expr args)
  | other => other
  end.
Theorem actual_function :
  loops (fn_body Original.f_regmap_bulk_read) = [callback_loop] /\
  fn_body Valid.f_kconc_valid_sixbyte_read = replace_cut (fn_body Original.f_regmap_bulk_read).
Proof. split; reflexivity. Qed.

(* Execute the guard's actual Clight statements. The three input facts are the
   primitive scalar observations in their respective temporary environments. *)
Definition bit (b : bool) := if b then Vint Int.one else Vint Int.zero.
Definition record_bit i b (le : temp_env) := PTree.set i (bit b) le.

Lemma if_bit ge e le m expr b yes no t le' m' out :
  eval_expr ge e le m expr (bit b) ->
  (typeof expr = tint \/ typeof expr = tbool) ->
  exec_stmt ge e le m (if b then yes else no) t le' m' out ->
  exec_stmt ge e le m (Sifthenelse expr yes no) t le' m' out.
Proof.
  intros E T W. eapply exec_Sifthenelse; [exact E| |exact W].
  destruct T as [T | T]; rewrite T; destruct b; reflexivity.
Qed.
Lemma temp_bit ge e le m id b :
  eval_expr ge e (record_bit id b le) m (Etempvar id tint) (bit b).
Proof. apply eval_Etempvar. apply PTree.gss. Qed.

Theorem execute_selector ge e le m observe wrong_count wrong_width different :
  let a := (observe || wrong_count)%bool in
  let b := (a || wrong_width)%bool in
  let c := (b || different)%bool in
  let le1 := record_bit Valid._t'3 a le in
  let le2 := record_bit Valid._t'4 b le1 in
  eval_expr ge e le m observer (bit observe) ->
  (observe = false -> eval_expr ge e le m (Ecast (differs count 6) tbool) (bit wrong_count)) ->
  (a = false -> eval_expr ge e le1 m (Ecast (differs width 1) tbool) (bit wrong_width)) ->
  (b = false -> eval_expr ge e le2 m (Ecast different_callback tbool) (bit different)) ->
  exec_stmt ge e le m (Ssequence (Ssequence test1 test2) test3)
    E0 (record_bit Valid._t'5 c le2) m Out_normal.
Proof.
  cbv zeta. intros O C W D.
  eapply exec_Sseq_1 with (t1:=E0) (t2:=E0) (m1:=m)
    (le1:=record_bit Valid._t'4 ((observe || wrong_count) || wrong_width)%bool
          (record_bit Valid._t'3 (observe || wrong_count)%bool le)).
  - eapply exec_Sseq_1 with (t1:=E0) (t2:=E0) (m1:=m)
      (le1:=record_bit Valid._t'3 (observe || wrong_count)%bool le).
    + unfold test1. eapply if_bit with (b:=observe); [exact O|right;reflexivity|].
      destruct observe; apply exec_Sset; [apply eval_Econst_int|apply C; reflexivity].
    + unfold test2. eapply if_bit with (b:=(observe || wrong_count)%bool);
        [apply temp_bit|left;reflexivity|].
      destruct (observe || wrong_count)%bool; apply exec_Sset;
        [apply eval_Econst_int|apply W; reflexivity].
  - unfold test3. eapply if_bit with (b:=((observe || wrong_count) || wrong_width)%bool);
      [apply temp_bit|left;reflexivity|].
    destruct ((observe || wrong_count) || wrong_width)%bool; apply exec_Sset;
      [apply eval_Econst_int|apply D; reflexivity].
Qed.

Theorem dispatch_loop ge e le m keep t le' m' out :
  exec_stmt ge e (record_bit Valid._t'5 keep le) m
    (if keep then callback_loop else Sskip) t le' m' out ->
  exec_stmt ge e (record_bit Valid._t'5 keep le) m select_loop t le' m' out.
Proof. intro E. eapply if_bit; [apply temp_bit|left;reflexivity|exact E]. Qed.

(* Evaluate the actual fast branch even at the short-circuit temporary updates.
   The concrete field offset 8 belongs only to this Clight projection. *)
Lemma exact_size ge e le m id z :
  (z = 1 \/ z = 6) ->
  PTree.get id le = Some (Vlong (Int64.repr z)) ->
  eval_expr ge e le m (Ecast (differs (Etempvar id tulong) z) tbool) (bit false).
Proof.
  intros [Z|Z] T; subst z; eapply eval_Ecast;
  [eapply eval_Ebinop; [eapply eval_Etempvar; eexact T|apply eval_Econst_int|reflexivity]
  |reflexivity
  |eapply eval_Ebinop; [eapply eval_Etempvar; eexact T|apply eval_Econst_int|reflexivity]
  |reflexivity].
Qed.

Theorem fast_cut_step e le m obj :
  PTree.get Valid._regmap_parse_inplace_noop e = None ->
  PTree.get Valid._map le = Some (Vptr obj Ptrofs.zero) ->
  PTree.get Valid._val_count le = Some (Vlong (Int64.repr 6)) ->
  PTree.get Valid._val_bytes le = Some (Vlong (Int64.repr 1)) ->
  eval_expr ValidGuard.guard_ge e le m observer (bit false) ->
  installed obj ValidGuard.known_code 8 m ->
  Mem.weak_valid_pointer m ValidGuard.known_code 0 = true ->
  exists le', exec_stmt ValidGuard.guard_ge e le m valid_cut E0 le' m Out_normal.
Proof.
  intros LOCAL MAP COUNT WIDTH OBS INST LIVE.
  set (le1 := record_bit Valid._t'3 false le).
  set (le2 := record_bit Valid._t'4 false le1).
  exists (record_bit Valid._t'5 false le2). unfold valid_cut.
  eapply exec_Sseq_1 with (t1:=E0) (t2:=E0) (m1:=m)
    (le1:=record_bit Valid._t'5 false le2).
  - apply (execute_selector _ _ _ _ false false false false); simpl; [exact OBS| | |].
    + intros _. apply exact_size; [auto|exact COUNT].
    + intros _. apply exact_size; [auto|]. unfold record_bit.
      rewrite PTree.gso by discriminate. exact WIDTH.
    + intros _. eapply eval_Ecast.
      * eapply ValidGuard.actual_guard_false; [exact LOCAL| |exact INST|exact LIVE].
        unfold record_bit. rewrite !PTree.gso by discriminate. exact MAP.
      * reflexivity.
  - apply (dispatch_loop _ _ _ _ false). apply exec_Sskip.
Qed.

Lemma same_projected_empty_symbol : ValidGuard.known_code = PrivateGuard.known_code.
Proof. vm_compute; reflexivity. Qed.

(* ObjectClass.segment models a restricted set of primitive memory actions.
   The Linux interface promises a readable, unchanged slot, not a trace of
   every system allocation. Transport just the observed slot values from the
   real memories to the constant-slot witness used by GenericRead. *)
Theorem api_read addr obj field m0 published g reads advance convert p :
  Mem.store Mint64 m0 obj field (Vptr PrivateGuard.known_code Ptrofs.zero) = Some published ->
  Mem.unchanged_on (slot obj field) published g ->
  (forall i, (i < 6)%nat -> Mem.unchanged_on (slot obj field) published (reads i)) ->
  finish_at addr 6 (run_loop advance convert
       (fun i => classify obj PrivateGuard.known_code field (reads i)) offsets) p =
  finish_at addr 6 (optimized advance convert
       (classify obj PrivateGuard.known_code field g)
       (fun i => classify obj PrivateGuard.known_code field (reads i)) offsets) p.
Proof.
  intros STORE FG FR.
  assert (W : window obj PrivateGuard.known_code field m0 published (fun _ => published) 6).
  { constructor; [exists published; split; [exact STORE|constructor]|intros; constructor|intros; constructor]. }
  pose proof (proj2 (GenericRead.any_start_six addr obj field m0 published
      (fun _ => published) advance convert p W)) as Base.
  assert (INIT : installed obj PrivateGuard.known_code field published) by (eapply initialize; eauto).
  assert (SAME : forall x, Mem.unchanged_on (slot obj field) published x ->
                    classify obj PrivateGuard.known_code field x = Empty).
  { intros x U. apply recognizes. eapply Mem.load_unchanged_on; [exact U| |exact INIT].
    intros i I; split; auto. }
  assert (P := recognizes _ _ _ _ INIT).
  rewrite (SAME _ FG).
  rewrite P in Base. simpl optimized in Base |- *.
  destruct p as [v|v|v]; cbn [finish_at] in *; try reflexivity.
  destruct (Z.eqb (rc v) 0); [|reflexivity].
  rewrite empty_loop; [ |intros i I; apply SAME, FR; apply in_seq in I; lia].
  rewrite empty_loop in Base; [exact Base |auto].
Qed.

Theorem checked_success addr obj m0 published g reads advance convert p e le :
  Mem.store Mint64 m0 obj 8 (Vptr ValidGuard.known_code Ptrofs.zero) = Some published ->
  Mem.unchanged_on (slot obj 8) published g ->
  (forall i, (i < 6)%nat -> Mem.unchanged_on (slot obj 8) published (reads i)) ->
  PTree.get Valid._regmap_parse_inplace_noop e = None ->
  PTree.get Valid._map le = Some (Vptr obj Ptrofs.zero) ->
  PTree.get Valid._val_count le = Some (Vlong (Int64.repr 6)) ->
  PTree.get Valid._val_bytes le = Some (Vlong (Int64.repr 1)) ->
  eval_expr ValidGuard.guard_ge e le g observer (bit false) ->
  Mem.weak_valid_pointer g ValidGuard.known_code 0 = true ->
  (exists le', exec_stmt ValidGuard.guard_ge e le g valid_cut E0 le' g Out_normal) /\
  finish_at addr 6 (run_loop advance convert
       (fun i => classify obj ValidGuard.known_code 8 (reads i)) offsets) p =
  finish_at addr 6 (optimized advance convert (classify obj ValidGuard.known_code 8 g)
       (fun i => classify obj ValidGuard.known_code 8 (reads i)) offsets) p.
Proof.
  intros ST FG FR LOCAL MAP COUNT WIDTH OBS LIVE. split.
  - eapply fast_cut_step; eauto. unfold installed.
    eapply Mem.load_unchanged_on; [exact FG|intros i I; split; auto|].
    exact (initialize obj ValidGuard.known_code 8 m0 published ST).
  - rewrite same_projected_empty_symbol in *. eapply api_read; eauto.
Qed.

Print Assumptions actual_function.
Print Assumptions execute_selector.
Print Assumptions dispatch_loop.
Print Assumptions fast_cut_step.
Print Assumptions same_projected_empty_symbol.
Print Assumptions ValidGuard.actual_guard_false.
Print Assumptions api_read.
Print Assumptions checked_success.
