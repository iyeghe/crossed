;; Crossed - Enhanced Relay Contract for Meta-Transactions
;; Maps user principals to their current nonce values
(define-map nonces principal uint)

;; New: Track batch operations
(define-map batch-results uint (list 50 bool))
(define-data-var batch-counter uint u0)

;; Error codes
(define-constant ERR-ALREADY-INITIALIZED (err u1))
(define-constant ERR-INVALID-NONCE (err u2))
(define-constant ERR-NONCE-NOT-FOUND (err u3))
(define-constant ERR-INVALID-SIGNATURE (err u4))
(define-constant ERR-INVALID-CALL-DATA (err u5))
(define-constant ERR-UNAUTHORIZED (err u6))
(define-constant ERR-PUBKEY-DERIVATION-FAILED (err u7))
(define-constant ERR-BATCH-TOO-LARGE (err u8))
(define-constant ERR-BATCH-EMPTY (err u9))
(define-constant ERR-PARTIAL-BATCH-FAILURE (err u10))

;; Constants for batch processing
(define-constant MAX-BATCH-SIZE u50)
(define-constant EXPECTED-SIGNATURE-LEN u65)

;; Initialize nonce for a new user (optional - can be called explicitly)
(define-public (initialize-nonce (user principal))
  (begin
    (asserts! (is-eq tx-sender user) ERR-UNAUTHORIZED)
    (match (map-get? nonces user)
      current ERR-ALREADY-INITIALIZED
      (begin
        (map-set nonces tx-sender u0)
        (ok true)))))

;; Helper function to create message hash for signature verification
(define-private (create-message-hash (signer principal) (nonce uint) (call-data (buff 128)))
  (let (
    (signer-buff (unwrap-panic (to-consensus-buff? signer)))
    (nonce-buff (unwrap-panic (to-consensus-buff? nonce)))
  )
    (keccak256 (concat (concat signer-buff nonce-buff) call-data))))

;; Helper to derive a principal from a recovered secp256k1 public key
(define-private (pubkey->principal (pubkey (buff 33)))
  (principal-of? (hash160 pubkey)))

;; Helper to ensure the recovered public key matches the expected signer
(define-private (assert-valid-signer (signer principal) (pubkey (buff 33)))
  (match (pubkey->principal pubkey)
    derived-principal
      (if (is-eq derived-principal signer)
        (ok derived-principal)
        ERR-INVALID-SIGNATURE)
    error-code
      ERR-PUBKEY-DERIVATION-FAILED))

(define-private (transaction-shape-valid? (transaction { signer: principal, nonce: uint, call-data: (buff 128), signature: (buff 65) }))
  (let (
    (call-data (get call-data transaction))
    (signature (get signature transaction))
  )
    (and (> (len call-data) u0) (is-eq (len signature) EXPECTED-SIGNATURE-LEN))))

;; ENHANCED: Main relay function with proper signature verification
(define-public (relay-call (signer principal) (nonce uint) (call-data (buff 128)) (sig (buff 65)))
  (let (
    (expected (default-to u0 (map-get? nonces signer)))
    (message-hash (create-message-hash signer nonce call-data))
  )
    (asserts! (is-eq expected nonce) ERR-INVALID-NONCE)
    (asserts! (> (len call-data) u0) ERR-INVALID-CALL-DATA)
    
    ;; FIXED: Correct match syntax for result type
    (match (secp256k1-recover? message-hash sig)
      recovered-pubkey
        (begin
          ;; Verify that signature recovery worked
          (asserts! (> (len recovered-pubkey) u0) ERR-INVALID-SIGNATURE)
          (match (assert-valid-signer signer recovered-pubkey)
            authorized-signer
              (begin
                ;; Update nonce after successful verification
                (map-set nonces authorized-signer (+ nonce u1))
                (ok true))
            error-code
              (err error-code)))
      error-code
        ;; Handle signature recovery failure
        ERR-INVALID-SIGNATURE)))

;; NEW: Shared batch execution helper
(define-private (execute-batch 
  (transactions (list 50 { signer: principal, nonce: uint, call-data: (buff 128), signature: (buff 65) }))
  (require-full-success bool))
  (let (
    (batch-size (len transactions))
    (batch-id (+ (var-get batch-counter) u1))
  )
    ;; Validate batch parameters
    (asserts! (and (> batch-size u0) (<= batch-size MAX-BATCH-SIZE)) ERR-BATCH-TOO-LARGE)
    
    ;; Process all transactions in the batch
    (let (
      (results (map process-single-batch-transaction transactions))
      (success-count (count-successful-transactions results))
    )
      (asserts! (or (not require-full-success) (is-eq success-count batch-size)) ERR-PARTIAL-BATCH-FAILURE)
      ;; Store batch results for tracking
      (map-set batch-results batch-id results)
      (var-set batch-counter batch-id)
      
      ;; Return success information
      (ok { batch-id: batch-id, successful: success-count, total: batch-size }))))

;; NEW: Simplified batch relay function for processing multiple transactions
(define-public (relay-batch-calls 
  (transactions (list 50 { signer: principal, nonce: uint, call-data: (buff 128), signature: (buff 65) })))
  (let (
    (validation-flags (map transaction-shape-valid? transactions))
    (total (len transactions))
    (valid-count (fold + (map bool-to-uint validation-flags) u0))
  )
    (asserts! (is-eq valid-count total) ERR-INVALID-CALL-DATA)
    (execute-batch transactions false)))

;; NEW: Batch relay that reverts unless every transaction succeeds
(define-public (relay-batch-calls-strict 
  (transactions (list 50 { signer: principal, nonce: uint, call-data: (buff 128), signature: (buff 65) })))
  (let (
    (validation-flags (map transaction-shape-valid? transactions))
    (total (len transactions))
    (valid-count (fold + (map bool-to-uint validation-flags) u0))
  )
    (asserts! (is-eq valid-count total) ERR-INVALID-CALL-DATA)
    (execute-batch transactions true)))

;; Helper function to process a single transaction in batch
(define-private (process-single-batch-transaction 
  (transaction { signer: principal, nonce: uint, call-data: (buff 128), signature: (buff 65) }))
  (let (
    (signer (get signer transaction))
    (nonce (get nonce transaction))
    (call-data (get call-data transaction))
    (signature (get signature transaction))
    (expected (default-to u0 (map-get? nonces signer)))
    (message-hash (create-message-hash signer nonce call-data))
  )
    ;; Validate nonce and call data
    (if (and (is-eq expected nonce) (> (len call-data) u0))
      ;; FIXED: Correct match syntax for result type
      (match (secp256k1-recover? message-hash signature)
        recovered-pubkey
          (if (> (len recovered-pubkey) u0)
            (match (assert-valid-signer signer recovered-pubkey)
              authorized-signer
                (begin
                  ;; Update nonce on success
                  (map-set nonces authorized-signer (+ nonce u1))
                  true)
              error-code
                false)
            false)
        error-code
          false)
      false)))

;; Helper function to count successful transactions
(define-private (count-successful-transactions (results (list 50 bool)))
  (fold + (map bool-to-uint results) u0))

;; Helper function to convert bool to uint for counting
(define-private (bool-to-uint (value bool))
  (if value u1 u0))

;; NEW: Alternative batch function with separate parameters (for easier integration)
(define-public (relay-batch-calls-separate
  (signer1 principal) (nonce1 uint) (call-data1 (buff 128)) (sig1 (buff 65))
  (signer2 principal) (nonce2 uint) (call-data2 (buff 128)) (sig2 (buff 65))
  (signer3 principal) (nonce3 uint) (call-data3 (buff 128)) (sig3 (buff 65)))
  (let (
    (transactions (list
      { signer: signer1, nonce: nonce1, call-data: call-data1, signature: sig1 }
      { signer: signer2, nonce: nonce2, call-data: call-data2, signature: sig2 }
      { signer: signer3, nonce: nonce3, call-data: call-data3, signature: sig3 })))
    (let (
      (validation-flags (map transaction-shape-valid? transactions))
      (total (len transactions))
      (valid-count (fold + (map bool-to-uint validation-flags) u0))
    )
      (asserts! (is-eq valid-count total) ERR-INVALID-CALL-DATA)
      (execute-batch transactions false))))

;; NEW: Gas-optimized single relay call
(define-public (relay-call-optimized (signer principal) (nonce uint) (call-data (buff 128)) (sig (buff 65)))
  (let (
    (expected (default-to u0 (map-get? nonces signer)))
    (message-hash (create-message-hash signer nonce call-data))
  )
    ;; Early validation to save gas
    (asserts! (is-eq expected nonce) ERR-INVALID-NONCE)
    (asserts! (> (len call-data) u0) ERR-INVALID-CALL-DATA)
    
    ;; FIXED: Correct match syntax for result type
    (match (secp256k1-recover? message-hash sig)
      recovered-pubkey
        (begin
          (asserts! (> (len recovered-pubkey) u0) ERR-INVALID-SIGNATURE)
          (match (assert-valid-signer signer recovered-pubkey)
            authorized-signer
              (begin
                ;; Atomic nonce update
                (map-set nonces authorized-signer (+ nonce u1))
                (ok true))
            error-code
              (err error-code)))
      error-code
        ERR-INVALID-SIGNATURE)))

;; Simplified relay function with hash-based verification (unchanged for compatibility)
(define-public (relay-call-simple (signer principal) (nonce uint) (call-data (buff 128)) (provided-hash (buff 32)))
  (let (
    (expected (default-to u0 (map-get? nonces signer)))
    (computed-hash (create-message-hash signer nonce call-data))
  )
    (asserts! (is-eq expected nonce) ERR-INVALID-NONCE)
    (asserts! (> (len call-data) u0) ERR-INVALID-CALL-DATA)
    
    ;; Verify that the provided hash matches the computed hash
    (asserts! (is-eq provided-hash computed-hash) ERR-INVALID-SIGNATURE)
    
    ;; Update nonce after successful verification
    (map-set nonces signer (+ nonce u1))
    (ok true)))

;; Relay function that allows the signer to call directly (unchanged for compatibility)
(define-public (relay-call-direct (nonce uint) (call-data (buff 128)))
  (let (
    (signer tx-sender)
    (expected (default-to u0 (map-get? nonces signer)))
  )
    (asserts! (is-eq expected nonce) ERR-INVALID-NONCE)
    (asserts! (> (len call-data) u0) ERR-INVALID-CALL-DATA)
    
    ;; Update nonce after successful verification
    (map-set nonces signer (+ nonce u1))
    (ok true)))

;; Read-only function to get current nonce for a user
(define-read-only (get-nonce (user principal))
  (default-to u0 (map-get? nonces user)))

;; Read-only function to get next expected nonce for a user
(define-read-only (get-next-nonce (user principal))
  (+ (default-to u0 (map-get? nonces user)) u1))

;; Helper function to check if a user has initialized their nonce
(define-read-only (is-nonce-initialized (user principal))
  (is-some (map-get? nonces user)))

;; Helper function to create expected message hash (for off-chain use)
(define-read-only (get-message-hash (signer principal) (nonce uint) (call-data (buff 128)))
  (create-message-hash signer nonce call-data))

;; NEW: Read-only function to get batch results
(define-read-only (get-batch-results (batch-id uint))
  (map-get? batch-results batch-id))

;; NEW: Read-only function to get current batch counter
(define-read-only (get-batch-counter)
  (var-get batch-counter))

;; NEW: Read-only function to check if a batch was fully successful
(define-read-only (is-batch-fully-successful (batch-id uint))
  (match (map-get? batch-results batch-id)
    results
      (is-eq (count-successful-transactions results) (len results))
    false))

;; NEW: Read-only function to get batch success rate
(define-read-only (get-batch-success-rate (batch-id uint))
  (match (map-get? batch-results batch-id)
    results
      (let (
        (total (len results))
        (successful (count-successful-transactions results))
      )
        (if (> total u0)
          (some { successful: successful, total: total, rate: (/ (* successful u100) total) })
          none))
    none))

;; NEW: Helper function to create a transaction tuple for batch processing
(define-read-only (create-transaction (signer principal) (nonce uint) (call-data (buff 128)) (signature (buff 65)))
  { signer: signer, nonce: nonce, call-data: call-data, signature: signature })
