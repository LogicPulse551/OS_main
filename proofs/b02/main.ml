(* Execute the Coq-extracted original optimizers; print structural JSON. *)
module BigInteger = Z
open Original
let array f xs = "[" ^ String.concat "," (List.map f xs) ^ "]"
let number = BigInteger.to_string
let block (label,instructions) = "[" ^ number label ^ "," ^ array (array number) instructions ^ "]"
let program xs = array (fun ((fid,entry),blocks) ->
  "[" ^ number fid ^ "," ^ number entry ^ "," ^ array block blocks ^ "]") xs
let run name opt lo input =
 let before = code_view input in
 let result = opt lo input in
 let after = match result with None -> "null" | Some p -> program (code_view p) in
 Printf.printf "{\"case\":\"%s\",\"before\":%s,\"after\":%s}\n%!" name (program before) after
let () =
 run "cp" run_cp non_atomic cp_input;
 run "cse" run_cse non_atomic cse_input;
 run "dce" run_dce non_atomic dce_input;
 run "licm" run_licm non_atomic licm_input;
 run "cp-boundary" run_cp atomic cp_boundary;
 run "cse-boundary" run_cse non_atomic cse_boundary;
 run "dce-boundary" run_dce non_atomic dce_boundary;
 run "licm-boundary" run_licm atomic licm_boundary;
 run "licm-print-boundary" run_licm non_atomic licm_print_boundary
