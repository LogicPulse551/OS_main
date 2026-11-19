From Paco Require Import paco.
From PromisingLib Require Import Basic Language Loc Event.
From PromisingSEQ Require Import ITreeLang NoMix Configuration Behavior SequentialITree SequentialCompatibility.
From O03 Require Import Cases Reproduce.
(* Intentionally omit no-mixed-access requirements for the concurrent threads. *)
Goal forall (loc_na loc_at: Loc.t -> Prop),
 (forall loc, loc_na loc -> loc_at loc -> False) ->
 forall A (ctx_seq: itree MemE.t Const.t -> itree MemE.t A)
 (ctx_ths: Threads.syntax) (tid: Ident.t),
 @itree_context loc_na loc_at Const.t A ctx_seq ->
 nomix loc_na loc_at _ ((lang Const.t).(Language.init) (eval_lang rr_input)) ->
 nomix loc_na loc_at _ ((lang Const.t).(Language.init) (eval_lang rr_expected)) ->
 behaviors Configuration.step
   (Configuration.init (IdentMap.add tid (existT _ (lang A) (ctx_seq (eval_lang rr_expected))) ctx_ths))
 <2= behaviors Configuration.step
   (Configuration.init (IdentMap.add tid (existT _ (lang A) (ctx_seq (eval_lang rr_input))) ctx_ths)).
Proof. intros. eapply rr_instance; eauto. Qed.
