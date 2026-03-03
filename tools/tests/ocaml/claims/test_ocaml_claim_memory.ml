let expect_invalid_argument name thunk =
  try
    thunk ();
    Printf.eprintf "test-ocaml-claim-memory failed: %s did not raise Invalid_argument\n" name;
    exit 1
  with
  | Invalid_argument _ ->
      ()

let run_stub_validation_tests xch =
  expect_invalid_argument "negative pages" (fun () ->
      Xenctrl.domain_claim_memory xch 0
        [| { Xenctrl.pages = -1L; node = -1l } |]);

  expect_invalid_argument "node < -1" (fun () ->
      Xenctrl.domain_claim_memory xch 0
        [| { Xenctrl.pages = 0L; node = -2l } |]);

  Printf.printf "test-ocaml-claim-memory passed\n"

let () =
  try
    Xenctrl.with_intf run_stub_validation_tests
  with
  | Xenctrl.Error msg ->
      Printf.printf "test-ocaml-claim-memory skipped: %s\n" msg
  | Failure msg ->
      Printf.printf "test-ocaml-claim-memory skipped: %s\n" msg
  | Unix.Unix_error (err, fn, arg) ->
      Printf.printf "test-ocaml-claim-memory skipped: %s (%s %s)\n"
        (Unix.error_message err) fn arg
