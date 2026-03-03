let claim_test_order = 9
let request_pages = Int64.shift_left 1L claim_test_order

let nr_failures = ref 0

let failf fmt =
  Printf.ksprintf
    (fun msg ->
      incr nr_failures;
      Printf.eprintf "test-ocaml-claim-memory failed: %s\n" msg)
    fmt

let expect_invalid_argument name thunk =
  try
    thunk ();
    failf "%s did not raise Invalid_argument" name
  with
  | Invalid_argument _ ->
      ()
  | Xenctrl.Error msg ->
      failf "%s raised Xenctrl.Error instead of Invalid_argument: %s" name msg

let expect_xc_error name thunk =
  try
    thunk ();
    failf "%s did not raise Xenctrl.Error" name
  with
  | Xenctrl.Error _ ->
      ()
  | Invalid_argument msg ->
      failf "%s raised Invalid_argument instead of Xenctrl.Error: %s" name msg

let has_capability cap physinfo =
  List.exists (( = ) cap) physinfo.Xenctrl.capabilities

let make_domain_config physinfo =
  let flags = ref [ Xenctrl.CDF_HVM; Xenctrl.CDF_HAP ] in
  let emulation_flags = ref [ Xenctrl.X86_EMU_LAPIC ] in
  if not (has_capability Xenctrl.CAP_HAP physinfo) then
    flags := List.filter (( <> ) Xenctrl.CDF_HAP) !flags;
  if
    (not (has_capability Xenctrl.CAP_HVM physinfo))
    ||
    not
      (has_capability Xenctrl.CAP_HAP physinfo
      || has_capability Xenctrl.CAP_Shadow physinfo)
  then begin
    flags := List.filter (( <> ) Xenctrl.CDF_HVM) !flags;
    emulation_flags := []
  end;
  {
    Xenctrl.ssidref = 0l;
    handle = "00000000-0000-0000-0000-000000000000";
    flags = !flags;
    iommu_opts = [];
    max_vcpus = 1;
    max_evtchn_port = 0;
    max_grant_frames = 1;
    max_maptrack_frames = 0;
    max_grant_version = 1;
    altp2m_opts = 0l;
    altp2m_count = 0l;
    vmtrace_buf_kb = 0l;
    cpupool_id = 0l;
    arch = Xenctrl.X86 { emulation_flags = !emulation_flags; misc_flags = [] };
  }

let with_domain xch config f =
  let domid = Xenctrl.domain_create xch config in
  let cleanup () =
    try Xenctrl.domain_destroy xch domid with
    | Xenctrl.Error _ ->
        ()
  in
  try
    Xenctrl.domain_setmaxmem xch domid (-1L);
    let result = f domid in
    cleanup ();
    result
  with
  | exn ->
      cleanup ();
      raise exn

let run_stub_validation_tests xch physinfo config =
  expect_invalid_argument "negative pages" (fun () ->
      Xenctrl.domain_claim_memory xch 0
        [| { Xenctrl.pages = -1L; node = -1l } |]);
  expect_invalid_argument "node < -1" (fun () ->
      Xenctrl.domain_claim_memory xch 0
        [| { Xenctrl.pages = 0L; node = -2l } |]);
  expect_invalid_argument "too many claims" (fun () ->
      Xenctrl.domain_claim_memory xch 0
        (Array.make 256 { Xenctrl.pages = 0L; node = -1l }));

  with_domain xch config (fun domid ->
      expect_xc_error "nr_claims == 0" (fun () ->
          Xenctrl.domain_claim_memory xch domid [||]);
      expect_xc_error "nr_claims == 2" (fun () ->
          Xenctrl.domain_claim_memory xch domid
            [|
              { Xenctrl.pages = 1L; node = -1l };
              { Xenctrl.pages = 1L; node = -1l };
            |]);
      expect_xc_error "pages > Int32.max" (fun () ->
          Xenctrl.domain_claim_memory xch domid
            [|
              {
                Xenctrl.pages = Int64.add (Int64.of_int32 Int32.max_int) 1L;
                node = 0l;
              };
            |]);

      let invalid_node = Int32.of_int (physinfo.Xenctrl.max_node_id + 1) in
      expect_xc_error "invalid node" (fun () ->
          Xenctrl.domain_claim_memory xch domid
            [| { Xenctrl.pages = 1L; node = invalid_node } |]))

let run_host_wide_claim_test xch config =
  let free_pages = Int64.of_nativeint (Xenctrl.physinfo xch).Xenctrl.free_pages in
  if Int64.compare free_pages (Int64.add request_pages 1L) <= 0 then
    Printf.printf
      "test-ocaml-claim-memory skipped: not enough free pages for host-wide claim \
       enforcement\n"
  else
    with_domain xch config (fun domid ->
        let claim_pages = Int64.sub (Int64.add free_pages 1L) request_pages in
        Xenctrl.domain_claim_memory xch domid
          [| { Xenctrl.pages = claim_pages; node = -1l } |];

        with_domain xch config (fun other_domid ->
            expect_xc_error "host-wide claim blocks second-domain allocation"
              (fun () ->
                Xenctrl.domain_memory_increase_reservation xch other_domid
                  (Xenctrl.pages_to_kib request_pages)));

        Xenctrl.domain_memory_increase_reservation xch domid
          (Xenctrl.pages_to_kib request_pages))

let run_node_claim_test xch physinfo config =
  if physinfo.Xenctrl.max_node_id < 0 then
    Printf.printf "test-ocaml-claim-memory skipped: system reports no NUMA nodes\n"
  else
    with_domain xch config (fun domid ->
        let node = 0l in
        Xenctrl.domain_claim_memory xch domid [| { Xenctrl.pages = 1L; node } |];
        Xenctrl.domain_memory_increase_reservation xch domid
          (Xenctrl.pages_to_kib request_pages))

let run_claim_tests xch =
  let physinfo = Xenctrl.physinfo xch in
  let config = make_domain_config physinfo in
  run_stub_validation_tests xch physinfo config;
  run_host_wide_claim_test xch config;
  run_node_claim_test xch physinfo config;
  if !nr_failures = 0 then
    Printf.printf "test-ocaml-claim-memory passed\n"
  else
    exit 1

let () =
  try Xenctrl.with_intf run_claim_tests with
  | Xenctrl.Error msg ->
      Printf.printf "test-ocaml-claim-memory skipped: %s\n" msg
  | Failure msg ->
      Printf.printf "test-ocaml-claim-memory skipped: %s\n" msg
  | Unix.Unix_error (err, fn, arg) ->
      Printf.printf "test-ocaml-claim-memory skipped: %s (%s %s)\n"
        (Unix.error_message err) fn arg
