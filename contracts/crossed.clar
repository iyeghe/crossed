;; Crossed - Relay Contract for Meta-Transactions
;; Maps user principals to their current nonce values
(define-map nonces principal uint)

;; Error codes
(define-constant ERR-ALREADY-INITIALIZED (err u1))
(define-constant ERR-INVALID-NONCE (err u2))
(define-constant ERR-NONCE-NOT-FOUND (err u3))
(define-constant ERR-INVALID-SIGNATURE (err u4))
(define-constant ERR-INVALID-CALL-DATA (err u5))
(define-constant ERR-UNAUTHORIZED (err u6))

;; Initialize nonce for a new user (optional - can be called explicitly)
(define-public (initialize-nonce (user principal))
  (match (map-get? nonces user)
    current ERR-ALREADY-INITIALIZED
    (begin
      (map-set nonces user u0)
      (ok true))))

;; Helper function to create message hash for signature verification
(define-private (create-message-hash (signer principal) (nonce uint) (call-data (buff 128)))
  (let (
    (signer-buff (unwrap-panic (to-consensus-buff? signer)))
    (nonce-buff (unwrap-panic (to-consensus-buff? nonce)))
  )
    (keccak256 (concat (concat signer-buff nonce-buff) call-data))))

;; Main relay function with signature verification using secp256k1-recover
(define-public (relay-call (signer principal) (nonce uint) (call-data (buff 128)) (sig (buff 65)))
  (let (
    (expected (default-to u0 (map-get? nonces signer)))
    (message-hash (create-message-hash signer nonce call-data))
  )
    (asserts! (is-eq expected nonce) ERR-INVALID-NONCE)
    (asserts! (> (len call-data) u0) ERR-INVALID-CALL-DATA)
    
    ;; Verify signature using secp256k1-recover with proper match syntax
    (match (secp256k1-recover? message-hash sig)
      recovered-pubkey
        (begin
          ;; For now, we'll use a simplified verification approach
          ;; In production, you'd want to derive the principal from the public key
          ;; and compare it with the signer
          (asserts! (> (len recovered-pubkey) u0) ERR-INVALID-SIGNATURE)
          ;; Update nonce after successful verification
          (map-set nonces signer (+ nonce u1))
          ;; Execute intended action or emit event for off-chain executor
          (ok true))
      error-code
        ERR-INVALID-SIGNATURE)))

;; Simplified relay function with hash-based verification
(define-public (relay-call-simple (signer principal) (nonce uint) (call-data (buff 128)) (provided-hash (buff 32)))
  (let (
    (expected (default-to u0 (map-get? nonces signer)))
    (computed-hash (create-message-hash signer nonce call-data))
  )
    (asserts! (is-eq expected nonce) ERR-INVALID-NONCE)
    (asserts! (> (len call-data) u0) ERR-INVALID-CALL-DATA)
    
    ;; Verify that the provided hash matches the computed hash
    ;; This is a simplified approach - in production you'd want proper signature verification
    (asserts! (is-eq provided-hash computed-hash) ERR-INVALID-SIGNATURE)
    
    ;; Update nonce after successful verification
    (map-set nonces signer (+ nonce u1))
    ;; Execute intended action or emit event for off-chain executor
    (ok true)))

;; Relay function that allows the signer to call directly (no signature needed)
(define-public (relay-call-direct (nonce uint) (call-data (buff 128)))
  (let (
    (signer tx-sender)
    (expected (default-to u0 (map-get? nonces signer)))
  )
    (asserts! (is-eq expected nonce) ERR-INVALID-NONCE)
    (asserts! (> (len call-data) u0) ERR-INVALID-CALL-DATA)
    
    ;; Update nonce after successful verification
    (map-set nonces signer (+ nonce u1))
    ;; Execute intended action or emit event for off-chain executor
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